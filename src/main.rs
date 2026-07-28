use clap::Parser;
use futures::stream::StreamExt;
use hdrhistogram::Histogram;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    CLOUDFLARE, ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use indicatif::{ProgressBar, ProgressStyle};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

/// Valid values for the --type flag
const VALID_QUERY_TYPES: &[&str] = &[
    "A", "AAAA", "MX", "NS", "CAA", "DNSKEY", "DS", "HTTPS", "PTR", "PTRMATCH", "SOA", "SRV",
    "TLSA", "TXT",
];

/// A bulk DNS lookup tool.
/// Reads items from stdin and resolves them concurrently.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(override_usage = "ruresol [OPTIONS] --type TYPE [--type TYPE ...] [-- DOMAIN ...]")]
struct Args {
    /// Custom DNS resolvers (e.g., 8.8.8.8 or 127.0.0.1:5353). Can be used multiple times.
    #[arg(short = 'R', long)]
    resolver: Vec<String>,

    /// Use DNS-over-HTTPS (Routes via Cloudflare's secure endpoint)
    #[arg(long, conflicts_with = "resolver")]
    doh: bool,

    /// Concurrency limit (number of simultaneous requests)
    #[arg(short = 'c', long, default_value_t = 25)]
    concurrency: usize,

    /// Timeout in milliseconds for each query attempt
    #[arg(short = 't', long, default_value_t = 2000)]
    timeout: u64,

    /// Number of attempts (retries) before giving up.
    /// Note: Total timeout ≈ timeout * attempts * (number of nameservers).
    #[arg(long, default_value_t = 2)]
    attempts: usize,

    /// Output results as soon as they are ready (unordered), instead of preserving input order (default)
    #[arg(short = 'u', long)]
    unordered: bool,

    /// Output results in JSON format
    #[arg(short = 'j', long)]
    json: bool,

    /// Rate limit queries per second (QPS)
    #[arg(long)]
    rate_limit: Option<u64>,

    /// Read inputs from a file instead of stdin. Use '-' to explicitly read from stdin.
    #[arg(short = 'i', long)]
    input: Option<String>,

    /// Do not read from stdin (useful when only using -- arguments)
    #[arg(long)]
    no_stdin: bool,

    /// DNS query type. Can be specified multiple times. Allowed: A, AAAA, MX, NS, CAA, DNSKEY, DS, HTTPS, PTR, PTRMATCH, SOA, SRV, TLSA, TXT
    #[arg(long = "type", value_parser = parse_query_type, required = true, value_delimiter = ',')]
    query_type: Vec<String>,

    /// Extra domains to resolve (specified after --)
    #[arg(last = true)]
    extra: Vec<String>,

    /// Shuffle (Knuth/Fisher-Yates) the domains specified after -- before resolving
    #[arg(long)]
    shuf: bool,

    /// Show progress bar and live query statistics on stderr
    #[arg(long)]
    progress: bool,

    /// Only print record values (no query name, no type prefix). Errors are suppressed.
    #[arg(long, conflicts_with_all = ["json", "json_array"])]
    short: bool,

    /// Print query statistics summary after completion
    #[arg(long)]
    stats: bool,

    /// Include TTL in JSON output (effective with --json or --json-array)
    #[arg(long)]
    ttl: bool,

    /// Only show results matching these statuses. Can be specified multiple times.
    /// Allowed: SUCCESS, PTRMATCH, NXDOMAIN, NODATA, TEMP
    #[arg(long = "show-only", value_parser = parse_show_filter, value_delimiter = ',')]
    show_only: Vec<String>,

    /// In plain output, print the punycode (IDNA/ASCII) form of each query name
    /// instead of the name as typed. JSON output always preserves the original
    /// "query" and adds a "punycode" field for names with non-ASCII labels,
    /// regardless of this flag.
    #[arg(long)]
    punycode: bool,

    /// Output a single JSON array document for the whole run, instead of the
    /// line-delimited objects produced by --json. With --stats the array is wrapped
    /// as {"results": [...], "stats": {...}}.
    #[arg(long)]
    json_array: bool,

    /// Only show IP-valued records contained in this CIDR (e.g. 10.0.0.0/8 or
    /// 2001:db8::/32). Can be specified multiple times. Records outside every given
    /// CIDR (and non-IP records) are suppressed.
    #[arg(long = "match-cidr", value_parser = parse_cidr)]
    match_cidr: Vec<IpNet>,

    /// Drop records that are private or reserved IP addresses (IPv4 and IPv6:
    /// RFC1918, loopback, link-local, CGNAT, ULA, documentation, multicast, etc.).
    #[arg(long)]
    exclude_private: bool,

    /// Detect DNS wildcards for the parent domains listed in FILE (one per line,
    /// '#' comments allowed) and filter out A/AAAA answers whose address set is a
    /// subset of a parent's learned wildcard address set.
    #[arg(long = "wildcard-filter", value_name = "FILE")]
    wildcard_filter: Option<String>,
}

/// Parse and validate the --type argument (case-insensitive)
fn parse_query_type(s: &str) -> Result<String, String> {
    let upper = s.to_uppercase();
    if VALID_QUERY_TYPES.contains(&upper.as_str()) {
        Ok(upper)
    } else {
        Err(format!("Invalid query type '{}'. Allowed: {}", s, VALID_QUERY_TYPES.join(", ")))
    }
}

/// Valid values for the --show-only flag
const VALID_SHOW_FILTERS: &[&str] = &["SUCCESS", "PTRMATCH", "NXDOMAIN", "NODATA", "TEMP"];

/// Parse and validate the --show-only argument (case-insensitive)
fn parse_show_filter(s: &str) -> Result<String, String> {
    let upper = s.to_uppercase();
    if VALID_SHOW_FILTERS.contains(&upper.as_str()) {
        Ok(upper)
    } else {
        Err(format!("Invalid filter '{}'. Allowed: {}", s, VALID_SHOW_FILTERS.join(", ")))
    }
}

/// Parse and validate a CIDR for --match-cidr (e.g. "10.0.0.0/8" or "2001:db8::/32")
fn parse_cidr(s: &str) -> Result<IpNet, String> {
    s.parse::<IpNet>().map_err(|e| format!("invalid CIDR '{}': {}", s, e))
}

/// Classify a LookupResult status string into a filter category
fn classify_status(status: &str) -> &'static str {
    match status {
        "SUCCESS" => "SUCCESS",
        "PTRMATCH" => "PTRMATCH",
        "NXDOMAIN" => "NXDOMAIN",
        "NODATA" => "NODATA",
        "No records found" => "NODATA",
        // Everything else is a temporary/transient error
        _ => "TEMP",
    }
}

/// Map a query type string to a hickory RecordType
fn to_record_type(qt: &str) -> RecordType {
    match qt {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "MX" => RecordType::MX,
        "NS" => RecordType::NS,
        "CAA" => RecordType::CAA,
        "DNSKEY" => RecordType::DNSKEY,
        "DS" => RecordType::DS,
        "HTTPS" => RecordType::HTTPS,
        "PTR" => RecordType::PTR,
        "SOA" => RecordType::SOA,
        "SRV" => RecordType::SRV,
        "TLSA" => RecordType::TLSA,
        "TXT" => RecordType::TXT,
        _ => unreachable!("query type already validated"),
    }
}

/// Deduplicate query types while preserving order
fn dedup_types(types: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for qt in types {
        if seen.insert(qt.clone()) {
            result.push(qt.clone());
        }
    }
    result
}

// ─── IDN / punycode, RTT bounds, IP and wildcard helpers ────────────────────

/// Convert a name to its punycode (IDNA / ASCII) form using the resolver's own
/// name encoding, so the displayed value matches what is actually queried.
/// ASCII inputs are returned unchanged; on IDNA failure the original is returned.
fn to_punycode(input: &str) -> String {
    // punycode only affects non-ASCII labels; pure-ASCII names are returned verbatim
    if input.is_ascii() {
        return input.to_string();
    }
    match Name::from_utf8(input) {
        Ok(name) => {
            let mut ascii = name.to_ascii();
            // Preserve the caller's trailing-dot convention
            if !input.ends_with('.') {
                while ascii.ends_with('.') {
                    ascii.pop();
                }
            }
            ascii
        }
        Err(_) => input.to_string(),
    }
}

/// The punycode form, but only when it differs from the input (i.e. the name
/// contains non-ASCII labels). ASCII / already-punycode names return None so the
/// JSON "punycode" field is omitted when it would just duplicate "query".
fn punycode_if_different(input: &str) -> Option<String> {
    if input.is_ascii() {
        return None;
    }
    let p = to_punycode(input);
    if p == input { None } else { Some(p) }
}

/// Microseconds to milliseconds. RTTs are measured and stored in microseconds but
/// every output (text and JSON) is in milliseconds, so this is the single conversion.
fn us_to_ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

/// Highest RTT the histogram needs to track, in microseconds.
///
/// A single query is bounded by `--timeout` per attempt, `--attempts` attempts, and one
/// such budget per nameserver (total timeout ≈ timeout * attempts * nameservers), and
/// every bit of that is a legitimate RTT for a slow-but-successful answer. The bound is
/// that worst case doubled, so real samples never sit at the ceiling; anything beyond it
/// is clamped into the top bucket rather than dropped.
fn max_trackable_rtt_us(timeout_ms: u64, attempts: usize, nameservers: usize) -> u64 {
    timeout_ms
        .max(1)
        .saturating_mul(1_000)
        .saturating_mul(attempts.max(1) as u64)
        .saturating_mul(nameservers.max(1) as u64)
        .saturating_mul(2)
}

/// Well-known private / reserved IPv4 and IPv6 ranges. Built once and reused.
/// These are the data behind --exclude-private; ipnet does the actual matching.
fn reserved_nets() -> &'static [IpNet] {
    static NETS: OnceLock<Vec<IpNet>> = OnceLock::new();
    NETS.get_or_init(|| {
        const RAW: &[&str] = &[
            // IPv4
            "0.0.0.0/8",          // "this host" / unspecified
            "10.0.0.0/8",         // RFC1918 private
            "100.64.0.0/10",      // CGNAT (RFC6598)
            "127.0.0.0/8",        // loopback
            "169.254.0.0/16",     // link-local
            "172.16.0.0/12",      // RFC1918 private
            "192.0.0.0/24",       // IETF protocol assignments
            "192.0.2.0/24",       // TEST-NET-1 (documentation)
            "192.88.99.0/24",     // 6to4 relay anycast
            "192.168.0.0/16",     // RFC1918 private
            "198.18.0.0/15",      // benchmarking
            "198.51.100.0/24",    // TEST-NET-2 (documentation)
            "203.0.113.0/24",     // TEST-NET-3 (documentation)
            "224.0.0.0/4",        // multicast
            "240.0.0.0/4",        // reserved / future use
            "255.255.255.255/32", // limited broadcast
            // IPv6
            "::/128",        // unspecified
            "::1/128",       // loopback
            "::ffff:0:0/96", // IPv4-mapped
            "100::/64",      // discard-only
            "2001:db8::/32", // documentation
            "fc00::/7",      // unique local (ULA)
            "fe80::/10",     // link-local
            "ff00::/8",      // multicast
        ];
        RAW.iter().map(|s| s.parse::<IpNet>().expect("valid reserved CIDR")).collect()
    })
}

/// True if the address falls in any private/reserved range (used by --exclude-private).
fn is_reserved_ip(ip: IpAddr) -> bool {
    reserved_nets().iter().any(|net| net.contains(&ip))
}

/// Generate a random 12-char DNS label, used to probe a zone for wildcard responses.
fn random_label() -> String {
    use rand::RngExt;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..12).map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char).collect()
}

/// Normalize a host/parent for wildcard matching: punycode, lowercase, no trailing dot.
fn normalize_host(h: &str) -> String {
    to_punycode(h.trim()).trim_end_matches('.').to_ascii_lowercase()
}

/// Find the longest parent domain in `wildcards` that `host` belongs to, if any.
/// `host` is expected to already be normalized via `normalize_host`.
fn find_wildcard_parent<'a>(
    host: &str,
    wildcards: &'a HashMap<String, HashSet<IpAddr>>,
) -> Option<&'a HashSet<IpAddr>> {
    let mut best: Option<(&str, &HashSet<IpAddr>)> = None;
    for (parent, set) in wildcards {
        // exact match or a strict subdomain (the leading dot avoids "notexample.com"
        // matching parent "example.com"). Checked without building a ".parent" String,
        // since this runs once per parent for every single result.
        let matches = host == parent
            || (host.len() > parent.len()
                && host.ends_with(parent.as_str())
                && host.as_bytes()[host.len() - parent.len() - 1] == b'.');
        if matches && best.is_none_or(|(bp, _)| parent.len() > bp.len()) {
            best = Some((parent.as_str(), set));
        }
    }
    best.map(|(_, s)| s)
}

/// A result is a wildcard hit when it has at least one IP and *every* resolved IP
/// is contained in the parent's learned wildcard set. A single off-set IP means a
/// genuine record and is kept.
fn is_wildcard_hit(record_ips: &[IpAddr], wildcard_set: &HashSet<IpAddr>) -> bool {
    !record_ips.is_empty() && record_ips.iter().all(|ip| wildcard_set.contains(ip))
}

/// Map a status string to a stable bucket name for per-status statistics.
fn stats_bucket(status: &str) -> &'static str {
    match status {
        "SUCCESS" => "success",
        "PTRMATCH" => "ptrmatch",
        "NXDOMAIN" => "nxdomain",
        "NODATA" | "No records found" => "nodata",
        "TIMEOUT" => "timeout",
        "SERVFAIL" => "servfail",
        "REFUSED" => "refused",
        _ => "other",
    }
}

// ─── RTT / Query Statistics ─────────────────────────────────────────────────

/// Lowest RTT the histogram can tell apart, in microseconds.
const RTT_LOW_US: u64 = 1;
/// Significant digits the histogram keeps (hdrhistogram allows 0..=5). Values below
/// 2048 us are stored at full 1 us resolution; above that the error stays under 0.1%.
const RTT_SIGFIG: u8 = 3;

/// Tracks per-query RTT for min/avg/max/mdev and percentiles.
///
/// Samples are microseconds in an HDR histogram, so the cost is a fixed-size array
/// rather than one f64 per query, and percentiles come straight out of it.
///
/// Only queries that actually got a response are recorded. A timeout never made a round
/// trip -- its elapsed time is just the timeout budget being spent -- so recording it
/// would drag avg/max/mdev and every percentile toward `--timeout`. Timeouts are counted
/// and reported in the timeout status bucket instead; see `QueryStats::record_completion`.
struct RttTracker {
    hist: Histogram<u64>,
}

impl RttTracker {
    /// `max_us` is the largest RTT to track, in microseconds; see `max_trackable_rtt_us`.
    fn new(max_us: u64) -> Self {
        // hdrhistogram requires high >= 2 * low; max_trackable_rtt_us always satisfies
        // that, but clamp so construction can never fail on a pathological value.
        let high = max_us.max(RTT_LOW_US * 2);
        Self {
            hist: Histogram::new_with_bounds(RTT_LOW_US, high, RTT_SIGFIG)
                .expect("valid RTT histogram bounds"),
        }
    }

    fn record(&mut self, duration: Duration) {
        // A cached or loopback answer can round down to 0 us; clamp to the lowest
        // discernible value so the sample still counts. saturating_record clamps the
        // other end, keeping an outlier beyond the bound in the histogram as the max
        // rather than discarding it.
        let us = (duration.as_micros() as u64).max(RTT_LOW_US);
        self.hist.saturating_record(us);
    }

    /// Number of RTT samples, i.e. answered queries. Timeouts are not counted here.
    fn count(&self) -> u64 {
        self.hist.len()
    }

    fn min_ms(&self) -> f64 {
        us_to_ms(self.hist.min())
    }

    fn max_ms(&self) -> f64 {
        us_to_ms(self.hist.max())
    }

    fn avg_ms(&self) -> f64 {
        if self.count() == 0 {
            return 0.0;
        }
        self.hist.mean() / 1000.0
    }

    /// Population standard deviation of RTT
    fn mdev_ms(&self) -> f64 {
        if self.count() == 0 {
            return 0.0;
        }
        self.hist.stdev() / 1000.0
    }

    fn format_rtt(&self) -> String {
        if self.count() == 0 {
            return "-/-/-/- ms".to_string();
        }
        // Three decimals of a millisecond is one microsecond, the resolution the
        // histogram is configured for.
        format!(
            "{:.3}/{:.3}/{:.3}/{:.3} ms",
            self.min_ms(),
            self.avg_ms(),
            self.max_ms(),
            self.mdev_ms()
        )
    }

    /// (p50, p95, p99) latency percentiles in milliseconds, over answered queries only.
    /// These are recorded values rather than interpolated ones, accurate to the
    /// histogram's configured resolution.
    fn percentiles(&self) -> (f64, f64, f64) {
        if self.hist.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        (
            us_to_ms(self.hist.value_at_quantile(0.50)),
            us_to_ms(self.hist.value_at_quantile(0.95)),
            us_to_ms(self.hist.value_at_quantile(0.99)),
        )
    }
}

/// Shared query statistics (thread-safe)
struct QueryStats {
    submitted: AtomicU64,
    completed: AtomicU64,
    errors: AtomicU64,
    eof_reached: AtomicBool,
    // Exact number of queries when knowable upfront (regular -i file pre-scan, or only
    // -- args); None for pipes/stdin where the total emerges only as input is consumed.
    expected_total: Option<u64>,
    start: Instant,
    rtt: Mutex<RttTracker>,
    // Per-status bucket counters (see stats_bucket)
    status_success: AtomicU64,
    status_ptrmatch: AtomicU64,
    status_nxdomain: AtomicU64,
    status_nodata: AtomicU64,
    status_timeout: AtomicU64,
    status_servfail: AtomicU64,
    status_refused: AtomicU64,
    status_other: AtomicU64,
}

impl QueryStats {
    /// `max_rtt_us` sizes the RTT histogram; see `max_trackable_rtt_us`.
    fn new(expected_total: Option<u64>, max_rtt_us: u64) -> Self {
        Self {
            submitted: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            eof_reached: AtomicBool::new(false),
            expected_total,
            start: Instant::now(),
            rtt: Mutex::new(RttTracker::new(max_rtt_us)),
            status_success: AtomicU64::new(0),
            status_ptrmatch: AtomicU64::new(0),
            status_nxdomain: AtomicU64::new(0),
            status_nodata: AtomicU64::new(0),
            status_timeout: AtomicU64::new(0),
            status_servfail: AtomicU64::new(0),
            status_refused: AtomicU64::new(0),
            status_other: AtomicU64::new(0),
        }
    }

    /// Count a finished query. `rtt` is the measured round-trip time, or None when the
    /// query never got a response (a timeout). A timeout still lands in the timeout
    /// status bucket and the error count, but its elapsed time is the timeout budget
    /// rather than a round trip, so it is deliberately kept out of the RTT histogram
    /// and every percentile derived from it.
    fn record_completion(&self, status: &str, rtt: Option<Duration>) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        let bucket = stats_bucket(status);
        // NXDOMAIN and NODATA are definitive negative answers, not transient errors,
        // so they are excluded from the error count (only timeout/servfail/refused/other).
        let is_error = !matches!(bucket, "success" | "ptrmatch" | "nxdomain" | "nodata");
        if is_error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        self.bump_status(bucket);
        if let Some(duration) = rtt
            && let Ok(mut tracker) = self.rtt.lock()
        {
            tracker.record(duration);
        }
    }

    /// Increment the counter for a given status bucket name.
    fn bump_status(&self, bucket: &str) {
        let counter = match bucket {
            "success" => &self.status_success,
            "ptrmatch" => &self.status_ptrmatch,
            "nxdomain" => &self.status_nxdomain,
            "nodata" => &self.status_nodata,
            "timeout" => &self.status_timeout,
            "servfail" => &self.status_servfail,
            "refused" => &self.status_refused,
            _ => &self.status_other,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Ordered (name, count) pairs for non-zero status buckets.
    fn status_counts(&self) -> Vec<(&'static str, u64)> {
        [
            ("success", &self.status_success),
            ("ptrmatch", &self.status_ptrmatch),
            ("nxdomain", &self.status_nxdomain),
            ("nodata", &self.status_nodata),
            ("timeout", &self.status_timeout),
            ("servfail", &self.status_servfail),
            ("refused", &self.status_refused),
            ("other", &self.status_other),
        ]
        .into_iter()
        .filter_map(|(k, a)| {
            let v = a.load(Ordering::Relaxed);
            if v > 0 { Some((k, v)) } else { None }
        })
        .collect()
    }

    /// Number of genuinely successful lookups (SUCCESS + PTRMATCH). NXDOMAIN and NODATA
    /// are definitive answers but are counted as neither successes nor errors here.
    fn succeeded(&self) -> u64 {
        self.status_success.load(Ordering::Relaxed) + self.status_ptrmatch.load(Ordering::Relaxed)
    }

    fn qps(&self) -> f64 {
        let completed = self.completed.load(Ordering::Relaxed) as f64;
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed < 0.001 { 0.0 } else { completed / elapsed }
    }

    /// Format a progress message with live statistics
    fn format_progress(&self) -> String {
        let completed = self.completed.load(Ordering::Relaxed);
        let submitted = self.submitted.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let eof = self.eof_reached.load(Ordering::Relaxed);

        let total_str = match self.expected_total {
            // Exact total known upfront (regular-file pre-scan or -- args only)
            Some(total) => format!("{}", total),
            // Otherwise the best we know: everything submitted so far, exact once EOF is hit
            None if eof => format!("{}", submitted),
            None => "?".to_string(),
        };

        let rtt_str =
            if let Ok(rtt) = self.rtt.lock() { rtt.format_rtt() } else { "-/-/-/- ms".to_string() };

        format!(
            "Q: {}/{} E: {} | {:.1} q/s | RTT {}",
            completed,
            total_str,
            errors,
            self.qps(),
            rtt_str
        )
    }

    /// Format a final statistics summary for --stats
    fn format_summary(&self) -> String {
        let completed = self.completed.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let succeeded = self.succeeded();
        let elapsed = self.start.elapsed();

        // Compute the RTT string, sample count and percentiles under a single lock
        let (rtt_str, rtt_samples, p50, p95, p99) = if let Ok(rtt) = self.rtt.lock() {
            let (p50, p95, p99) = rtt.percentiles();
            (rtt.format_rtt(), rtt.count(), p50, p95, p99)
        } else {
            ("-/-/-/- ms".to_string(), 0, 0.0, 0.0, 0.0)
        };

        let status_str = {
            let parts: Vec<String> =
                self.status_counts().into_iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            if parts.is_empty() { "-".to_string() } else { parts.join(" ") }
        };

        format!(
            "\n--- Query Statistics ---\n\
             Queries:   {}\n\
             Succeeded: {}\n\
             Errors:    {}\n\
             Elapsed:   {:.1}s\n\
             QPS:       {:.1} q/s\n\
             RTT:       {} (min/avg/max/mdev over {} answered, timeouts excluded)\n\
             Pctl:      {:.3}/{:.3}/{:.3} ms (p50/p95/p99)\n\
             Status:    {}",
            completed,
            succeeded,
            errors,
            elapsed.as_secs_f64(),
            self.qps(),
            rtt_str,
            rtt_samples,
            p50,
            p95,
            p99,
            status_str
        )
    }

    /// Build the statistics object (the inner value, without the "stats" wrapper),
    /// shared by --stats --json and the --json-array trailer.
    fn stats_value(&self) -> serde_json::Value {
        let completed = self.completed.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let succeeded = self.succeeded();
        let elapsed = self.start.elapsed().as_secs_f64();

        let (rtt_samples, rtt_min, rtt_avg, rtt_max, rtt_mdev, p50, p95, p99) =
            if let Ok(rtt) = self.rtt.lock() {
                if rtt.count() > 0 {
                    let (p50, p95, p99) = rtt.percentiles();
                    (
                        rtt.count(),
                        rtt.min_ms(),
                        rtt.avg_ms(),
                        rtt.max_ms(),
                        rtt.mdev_ms(),
                        p50,
                        p95,
                        p99,
                    )
                } else {
                    (0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
                }
            } else {
                (0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            };

        // Round helper: keep 3 decimals of a millisecond
        let r3 = |x: f64| (x * 1000.0).round() / 1000.0;

        let mut status_counts = serde_json::Map::new();
        for (k, v) in self.status_counts() {
            status_counts.insert(k.to_string(), serde_json::json!(v));
        }

        serde_json::json!({
            "queries": completed,
            "succeeded": succeeded,
            "errors": errors,
            "elapsed_sec": r3(elapsed),
            "qps": (self.qps() * 10.0).round() / 10.0,
            // RTT figures cover answered queries only; timeouts are in status_counts
            "rtt_samples": rtt_samples,
            "rtt_ms_min": r3(rtt_min),
            "rtt_ms_avg": r3(rtt_avg),
            "rtt_ms_max": r3(rtt_max),
            "rtt_ms_mdev": r3(rtt_mdev),
            "rtt_ms_p50": r3(p50),
            "rtt_ms_p95": r3(p95),
            "rtt_ms_p99": r3(p99),
            "status_counts": serde_json::Value::Object(status_counts)
        })
    }

    /// Format statistics as a JSON object for --stats --json
    fn format_summary_json(&self) -> String {
        serde_json::json!({ "stats": self.stats_value() }).to_string()
    }
}

// ─── Record / Result types ──────────────────────────────────────────────────

/// A single record entry, either a plain value or a value with priority (for MX)
#[derive(serde::Serialize, Clone)]
#[serde(untagged)]
enum RecordEntry {
    Simple(String),
    WithPriority { priority: u16, value: String },
}

impl RecordEntry {
    /// The comparable string value of a record (the host/value for MX entries).
    fn value_str(&self) -> &str {
        match self {
            RecordEntry::Simple(s) => s,
            RecordEntry::WithPriority { value, .. } => value,
        }
    }
}

/// Turn an answer section into output records plus the TTL to report.
///
/// `f` decides which answers are results (returning None for the rest). Filtering
/// matters because the answer section also carries the CNAME chain that led to the
/// answer: those records are not results of the query, and their TTL — usually
/// different from the answer's — must not be reported as the record's TTL. The TTL
/// is the smallest one among the records that `f` kept, or None when `include_ttl`
/// is false or nothing matched.
fn collect_records<'a, I, F>(answers: I, include_ttl: bool, f: F) -> (Vec<RecordEntry>, Option<u32>)
where
    I: IntoIterator<Item = &'a Record>,
    F: Fn(&RData) -> Option<RecordEntry>,
{
    let mut records = Vec::new();
    let mut ttl: Option<u32> = None;
    for r in answers {
        if let Some(entry) = f(&r.data) {
            records.push(entry);
            ttl = Some(ttl.map_or(r.ttl, |t| t.min(r.ttl)));
        }
    }
    (records, if include_ttl { ttl } else { None })
}

/// Unified structure for handling outputs
#[derive(serde::Serialize, Clone)]
struct LookupResult {
    query: String,
    // IDNA/ASCII (punycode) form, populated whenever it differs from `query` (a
    // name with non-ASCII labels). The original `query` is always preserved; the
    // field is skipped in JSON for plain ASCII names.
    #[serde(skip_serializing_if = "Option::is_none")]
    punycode: Option<String>,
    #[serde(rename = "querytype")]
    query_type: String,
    #[serde(skip_serializing)]
    is_success: bool,
    // True when the query never got a response at all -- the case `classify_resolve_error`
    // labels "TIMEOUT". It is still counted and reported as a timeout, but its elapsed
    // time is the timeout budget rather than a round trip, so the RTT statistics skip it.
    #[serde(skip_serializing)]
    timed_out: bool,
    /// RTT measured inside the lookup when the operation performs more than the
    /// one round trip the caller times (PTRMATCH = reverse + forward confirms).
    /// When set, the stats record this instead of the whole operation's elapsed.
    #[serde(skip_serializing)]
    measured_rtt: Option<Duration>,
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<RecordEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

/// Output-side record/result filters (--match-cidr, --exclude-private, --wildcard-filter)
struct OutputFilter {
    match_cidrs: Vec<IpNet>,
    exclude_private: bool,
    // parent domain (normalized) -> learned wildcard IP set
    wildcards: HashMap<String, HashSet<IpAddr>>,
}

impl OutputFilter {
    /// Whether any per-record IP filter is active.
    fn ip_filters_active(&self) -> bool {
        !self.match_cidrs.is_empty() || self.exclude_private
    }

    /// Decide whether a single record value passes the IP-based filters.
    fn record_passes(&self, value: &str) -> bool {
        match value.parse::<IpAddr>() {
            Ok(ip) => {
                if self.exclude_private && is_reserved_ip(ip) {
                    return false;
                }
                if !self.match_cidrs.is_empty() && !self.match_cidrs.iter().any(|n| n.contains(&ip))
                {
                    return false;
                }
                true
            }
            // Non-IP record: nothing to exclude, but it cannot satisfy --match-cidr.
            Err(_) => self.match_cidrs.is_empty(),
        }
    }

    /// Whether this result is a wildcard hit that should be filtered out. Only
    /// applies to successful A/AAAA answers whose name falls under a learned parent.
    fn is_wildcard_result(&self, result: &LookupResult) -> bool {
        if self.wildcards.is_empty() || !result.is_success {
            return false;
        }
        // query_type is stored lowercase; only A/AAAA carry comparable IP sets
        let qt = result.query_type.as_str();
        if qt != "a" && qt != "aaaa" {
            return false;
        }
        let host = normalize_host(&result.query);
        let set = match find_wildcard_parent(&host, &self.wildcards) {
            Some(s) => s,
            None => return false,
        };
        let ips: Vec<IpAddr> =
            result.records.iter().filter_map(|r| r.value_str().parse::<IpAddr>().ok()).collect();
        is_wildcard_hit(&ips, set)
    }
}

/// Output configuration passed to LookupResult::print
struct PrintCfg {
    json: bool,       // any JSON mode (line-delimited --json or --json-array)
    json_array: bool, // single-array JSON mode
    short: bool,
    punycode: bool,
    show_only: Vec<String>,
}

impl LookupResult {
    fn print(&self, cfg: &PrintCfg, filter: &OutputFilter, array_started: &AtomicBool) {
        use std::io::Write;

        // Apply --show-only filter: if filters are set, skip non-matching results
        if !cfg.show_only.is_empty() {
            let category = classify_status(&self.status);
            if !cfg.show_only.iter().any(|f| f == category) {
                return;
            }
        }

        // Wildcard filter: drop A/AAAA answers that match a learned wildcard set
        if filter.is_wildcard_result(self) {
            return;
        }

        // IP-based record filters (--match-cidr / --exclude-private)
        let active = filter.ip_filters_active();
        let filtered: Vec<RecordEntry>;
        let records: &[RecordEntry] = if active {
            filtered = self
                .records
                .iter()
                .filter(|r| filter.record_passes(r.value_str()))
                .cloned()
                .collect();
            if self.records.is_empty() {
                // No records to begin with (error/NXDOMAIN/NODATA): --match-cidr can
                // never match, so suppress; exclude-private alone keeps the status.
                if !filter.match_cidrs.is_empty() {
                    return;
                }
            } else if filtered.is_empty() {
                // Had records, but none survived the filter -> suppress the result.
                return;
            }
            &filtered
        } else {
            &self.records
        };

        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        // Display name honours --punycode for non-JSON output
        let name: &str = if cfg.punycode {
            self.punycode.as_deref().unwrap_or(&self.query)
        } else {
            &self.query
        };

        if cfg.short {
            // --short: only print values for successful lookups, one per line
            if !self.is_success {
                return;
            }
            for record in records {
                let res = match record {
                    RecordEntry::WithPriority { priority, value } => {
                        writeln!(out, "{} {}", priority, value)
                    }
                    RecordEntry::Simple(value) => {
                        writeln!(out, "{}", value)
                    }
                };
                handle_write(res);
            }
            return;
        }

        let res = if cfg.json {
            // Serialize with the filtered records (clone only when filtering changed them)
            let json_str = if active && records.len() != self.records.len() {
                let mut tmp = self.clone();
                tmp.records = records.to_vec();
                serde_json::to_string(&tmp)
            } else {
                serde_json::to_string(self)
            };
            let json_str = match json_str {
                Ok(s) => s,
                Err(_) => return,
            };
            if cfg.json_array {
                // Comma-separate elements; the surrounding brackets are written by main.
                if array_started.swap(true, Ordering::Relaxed) {
                    write!(out, ",{}", json_str)
                } else {
                    write!(out, "{}", json_str)
                }
            } else {
                writeln!(out, "{}", json_str)
            }
        } else if self.is_success {
            // One record per line: "query type [priority]=value"
            // querytype is stored lowercase; keep it lowercase in plain output too so it
            // matches the JSON "querytype" field.
            let qt = &self.query_type;
            let mut res = Ok(());
            for record in records {
                res = match record {
                    RecordEntry::WithPriority { priority, value } => {
                        writeln!(out, "{} {} {}={}", name, qt, priority, value)
                    }
                    RecordEntry::Simple(value) => {
                        writeln!(out, "{} {}={}", name, qt, value)
                    }
                };
                if res.is_err() {
                    break;
                }
            }
            res
        } else {
            writeln!(out, "{}:{}", name, self.status)
        };

        handle_write(res);
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

/// Write a raw string to stdout, suspending the progress bar if one is active so
/// the output is not clobbered by an in-flight bar redraw.
fn emit_raw(pb: &Option<ProgressBar>, s: &str) {
    use std::io::Write;
    let write_it = || {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = write!(out, "{}", s);
        let _ = out.flush();
    };
    match pb {
        Some(pb) => pb.suspend(write_it),
        None => write_it(),
    }
}

/// Handle the result of a stdout write. A broken pipe (the downstream reader closed,
/// e.g. `... | head`) is an expected, clean termination -> exit(0). Any other write
/// error (e.g. disk full when redirected to a file) is a real failure -> exit(1) so
/// callers can detect it. This relies on SIGPIPE being ignored (Rust's default), so a
/// broken pipe surfaces here as an Err rather than a fatal signal.
fn handle_write(res: std::io::Result<()>) {
    if let Err(e) = res {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("error writing to stdout: {}", e);
        std::process::exit(1);
    }
}

/// Normalize one input line: strip whitespace and a UTF-8 BOM, drop empty
/// lines and '#' comments. Returns None when the line carries no query.
fn clean_input_line(line: &str) -> Option<&str> {
    let t = line.trim().trim_start_matches('\u{feff}').trim();
    if t.is_empty() || t.starts_with('#') { None } else { Some(t) }
}

/// Pre-scan a regular input file and count the lines that will actually be queried,
/// applying the same filter as the input stream (valid UTF-8, trimmed non-empty, not a
/// '#' comment). Returns None if the file can't be opened. Only called for regular
/// files; pipes/stdin can't be rewound and are never pre-scanned.
async fn count_input_lines(path: &str) -> Option<u64> {
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    let mut count: u64 = 0;
    loop {
        // A read error must not be reported as an exact count: returning None makes the
        // progress bar fall back to the dynamic total instead of pinning it to a
        // silently truncated one.
        let bytes_read = reader.read_until(b'\n', &mut buf).await.ok()?;
        if bytes_read == 0 {
            break; // EOF
        }
        if let Ok(line_str) = std::str::from_utf8(&buf) {
            if clean_input_line(line_str).is_some() {
                count += 1;
            }
        }
        buf.clear();
    }
    Some(count)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // NOTE: SIGPIPE is left at Rust's default (SIG_IGN), so writes to a closed downstream
    // pipe return Err(BrokenPipe) instead of terminating the process with a signal.
    // handle_write() turns a broken pipe into a clean exit(0) and any other write error
    // into exit(1), giving correct exit codes without depending on signal delivery.
    let args = Args::parse();

    // Deduplicate query types while preserving order
    let effective_types = dedup_types(&args.query_type);

    // --type ptrmatch is exclusive: cannot be combined with other types
    let has_ptrmatch = effective_types.iter().any(|t| t == "PTRMATCH");
    if has_ptrmatch && effective_types.len() > 1 {
        eprintln!("error: --type ptrmatch cannot be combined with other query types");
        std::process::exit(1);
    }

    // --show-only ptrmatch requires --type ptrmatch
    if args.show_only.iter().any(|f| f == "PTRMATCH") && !has_ptrmatch {
        eprintln!("error: --show-only ptrmatch requires --type ptrmatch");
        std::process::exit(1);
    }

    if args.no_stdin && matches!(args.input.as_deref(), Some("-")) {
        eprintln!("error: --input - conflicts with --no-stdin");
        std::process::exit(1);
    }

    // Validate numeric limits that would otherwise panic or silently produce no output.
    if args.concurrency == 0 {
        eprintln!("error: --concurrency must be at least 1");
        std::process::exit(1);
    }
    if args.rate_limit == Some(0) {
        eprintln!("error: --rate-limit must be at least 1 (queries per second)");
        std::process::exit(1);
    }
    if args.timeout == 0 {
        eprintln!("error: --timeout must be at least 1 (milliseconds)");
        std::process::exit(1);
    }
    if args.attempts == 0 {
        eprintln!("error: --attempts must be at least 1");
        std::process::exit(1);
    }

    // NOTE: The custom (`-R`) and DoH branches below use ResolverOpts::default(), while
    // the system branch keeps whatever read_system_conf() returns. As a result, search
    // domains, ndots, and similar resolution behaviour differ between them: a bare name
    // like "foo" may be search-suffixed by the system resolver but queried literally via
    // `-R 8.8.8.8` or `--doh`. This is intentional for a bulk tool, but callers relying
    // on search-list expansion should pass fully-qualified names.
    // Initialize Resolver Config (Custom vs System Default)
    let (config, mut opts) = if args.doh {
        (ResolverConfig::https(&CLOUDFLARE), ResolverOpts::default())
    } else if !args.resolver.is_empty() {
        let mut cfg = ResolverConfig::from_parts(None, vec![], vec![]);
        for r in &args.resolver {
            // Accept either "IP" (port 53) or "IP:PORT"
            let (ip, port): (IpAddr, u16) = if let Ok(ip) = r.parse::<IpAddr>() {
                (ip, 53)
            } else if let Ok(sa) = r.parse::<SocketAddr>() {
                (sa.ip(), sa.port())
            } else {
                eprintln!("error: invalid resolver '{}'. Use IP or IP:PORT (IPv6: [::1]:5353)", r);
                std::process::exit(1);
            };
            // Build UDP + TCP connections with the (possibly non-default) port
            let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
            udp.port = port;
            let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
            tcp.port = port;
            cfg.add_name_server(NameServerConfig::new(ip, true, vec![udp, tcp]));
        }
        (cfg, ResolverOpts::default())
    } else {
        hickory_resolver::system_conf::read_system_conf()?
    };

    // Apply custom timeouts and retries
    opts.timeout = Duration::from_millis(args.timeout);
    opts.attempts = args.attempts;
    // edns_payload_len is 4096 in 0.25.2 and 1232 in next 0.26 release
    opts.edns0 = true;
    opts.try_tcp_on_error = true;

    // Size the RTT histogram from the settings that bound a single query. Read here
    // because building the resolver consumes `config`.
    let max_rtt_us = max_trackable_rtt_us(args.timeout, args.attempts, config.name_servers().len());

    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()?;

    // Learn wildcard address sets up front (if --wildcard-filter FILE is given), so
    // results can be filtered against them during the main resolution pass.
    let wildcards: HashMap<String, HashSet<IpAddr>> = if let Some(path) = &args.wildcard_filter {
        match learn_wildcards(&resolver, path, 3).await {
            Ok(map) => {
                if !map.is_empty() {
                    eprintln!("wildcard: detected wildcards for {} parent domain(s)", map.len());
                }
                map
            }
            Err(e) => {
                eprintln!("error: failed to read wildcard filter file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    } else {
        HashMap::new()
    };

    // Determine whether -i points to a regular file (affects the progress total display).
    let is_regular_file = if let Some(path) = &args.input {
        path != "-" && matches!(tokio::fs::metadata(path).await, Ok(meta) if meta.is_file())
    } else {
        false
    };

    // Setup Input Reading (None when --no-stdin and no -i file)
    let mut reader: Option<Box<dyn AsyncBufRead + Unpin + Send>> = if let Some(path) = &args.input {
        if path == "-" {
            Some(Box::new(BufReader::new(tokio::io::stdin())))
        } else {
            let file = tokio::fs::File::open(path).await?;
            Some(Box::new(BufReader::new(file)))
        }
    } else if args.no_stdin {
        None
    } else {
        Some(Box::new(BufReader::new(tokio::io::stdin())))
    };

    // Rate limiter: qps is validated >= 1 above. Use nanosecond precision and clamp the
    // period to >= 1ns so a very large QPS can't produce a zero-length interval (which
    // would panic). The Delay policy prevents a burst of catch-up ticks after the pipeline
    // stalls while the concurrency buffer is full.
    let mut interval = args.rate_limit.map(|qps| {
        let period = Duration::from_nanos((1_000_000_000u64 / qps).max(1));
        let mut i = tokio::time::interval(period);
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    });

    // Collect extra domains passed after --
    let mut extra_domains: Vec<String> =
        args.extra.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

    // Knuth (Fisher-Yates) shuffle of -- arguments when --shuf is set
    if args.shuf && extra_domains.len() > 1 {
        use rand::seq::SliceRandom;
        extra_domains.shuffle(&mut rand::rng());
    }

    // When the input size is knowable upfront -- a regular -i file (pre-scanned) or only
    // `--` arguments -- compute the exact number of queries so the progress bar shows true
    // completion percentage. This matters with --rate-limit, where submission is throttled
    // to match completion and a dynamic completed/submitted bar would always read 100%.
    // Pipes/stdin can't be pre-counted and fall back to the dynamic total.
    let expected_total: Option<u64> = if args.progress {
        let types_count = effective_types.len() as u64;
        let extras = extra_domains.len() as u64;
        if is_regular_file {
            // Costs one extra sequential read of the file before querying starts, which is
            // negligible next to the DNS traffic itself. If the file changes between this
            // scan and the actual read, the bar may end short of (or be capped at) 100%.
            if let Some(path) = &args.input {
                count_input_lines(path).await.map(|lines| (lines + extras) * types_count)
            } else {
                None
            }
        } else if reader.is_none() {
            // Only -- args: the total is exact without any scan.
            Some(extras * types_count)
        } else {
            None
        }
    } else {
        None
    };

    // Initialize statistics tracking (used by --progress and --stats)
    let stats = Arc::new(QueryStats::new(expected_total, max_rtt_us));

    // Initialize progress bar (if --progress). The bar tracks completed queries. When the
    // total is known upfront (regular -i file or -- args only) the length is exact and
    // fixed; otherwise it grows to the number of queries submitted so far (finalized at
    // input EOF) while the position tracks completions.
    let progress_bar: Option<ProgressBar> = if args.progress {
        let pb = ProgressBar::new(expected_total.unwrap_or(0));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{bar:30.cyan/blue} {percent:>3}% | {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("█▓░"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // Clone handles for the input stream
    let stats_stream = stats.clone();

    // manual UTF-8 check instead of lines()
    let input_stream = async_stream::stream! {
        // First yield extra domains from command line (after --)
        for domain in &extra_domains {
            yield domain.clone();
        }

        // Then read from file/stdin (if available)
        if let Some(ref mut reader) = reader {
            let mut buf = Vec::new();
            loop {
                match reader.read_until(b'\n', &mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {}
                    Err(e) => {
                        // Don't stop silently: a truncated run would otherwise be
                        // indistinguishable from a complete one.
                        eprintln!("error reading input: {}", e);
                        break;
                    }
                }

                // Check if valid UTF-8. If valid, process. If not, we basically ignore (skip) it.
                if let Ok(line_str) = std::str::from_utf8(&buf) {
                    if let Some(line) = clean_input_line(line_str) {
                        yield line.to_string();
                    }
                }
                buf.clear();
            }
        }

        // Input is exhausted: EOF, a read error, or no reader at all (only -- args).
        // Marking it in every case keeps the progress total from being stuck at "?".
        stats_stream.eof_reached.store(true, Ordering::Relaxed);
    };

    let effective_types = Arc::new(effective_types);
    let include_ttl = args.ttl && (args.json || args.json_array); // TTL only meaningful in JSON

    // Output filters and print configuration (shared, read-only during the run)
    let output_filter = Arc::new(OutputFilter {
        match_cidrs: args.match_cidr.clone(),
        exclude_private: args.exclude_private,
        wildcards,
    });
    let print_cfg = Arc::new(PrintCfg {
        json: args.json || args.json_array,
        json_array: args.json_array,
        short: args.short,
        punycode: args.punycode,
        show_only: args.show_only.clone(),
    });
    // Tracks whether the first element of a --json-array has been written (for commas)
    let array_started = Arc::new(AtomicBool::new(false));

    // Expand each input into one work item per query type
    let work_stream = input_stream.flat_map(move |input| {
        let types = effective_types.clone();
        let pairs: Vec<(String, String)> =
            types.iter().map(|qt| (input.clone(), qt.clone())).collect();
        futures::stream::iter(pairs)
    });

    // Rate limit at the per-query granularity so --rate-limit is honored across *all*
    // query types (each input expands into one work item per --type). Ticking here, after
    // flat_map, throttles every actual DNS query rather than every input line.
    let rate_limited = async_stream::stream! {
        futures::pin_mut!(work_stream);
        while let Some(item) = work_stream.next().await {
            if let Some(i) = &mut interval {
                i.tick().await;
            }
            yield item;
        }
    };

    // Clone handles for the task closures
    let stats_task = stats.clone();
    let pb_task = progress_bar.clone();

    let tasks = rate_limited.map(move |(input, query_type)| {
        let resolver = resolver.clone();
        let stats = stats_task.clone();
        let pb = pb_task.clone();

        stats.submitted.fetch_add(1, Ordering::Relaxed);

        async move {
            let start = Instant::now();
            let mut result = typed_lookup(input, resolver, &query_type, include_ttl).await;
            let elapsed = start.elapsed();

            // Always expose the punycode form in JSON when it differs from the query
            // (i.e. the name had non-ASCII labels); omitted for plain ASCII names.
            result.punycode = punycode_if_different(&result.query);

            // A timed-out query never completed a round trip, so `elapsed` is just the
            // timeout budget: pass None and let it be counted purely as a timeout.
            // For multi-round-trip lookups (PTRMATCH), prefer the primary lookup's RTT
            // so forward-confirmation queries don't skew the latency statistics.
            let rtt = if result.timed_out { None } else { result.measured_rtt.or(Some(elapsed)) };
            stats.record_completion(&result.status, rtt);
            if let Some(ref pb) = pb {
                // With an exact pre-counted total the bar length is fixed at creation;
                // otherwise (pipe/stdin) it grows with submissions and the bar shows
                // completed out of submitted-so-far.
                if stats.expected_total.is_none() {
                    pb.set_length(stats.submitted.load(Ordering::Relaxed));
                }
                pb.set_position(stats.completed.load(Ordering::Relaxed));
                pb.set_message(stats.format_progress());
            }

            result
        }
    });

    // Clone handles for the output closure
    let pb_output = progress_bar.clone();

    // Open the JSON array document, if requested, before any results stream out
    if args.json_array {
        let prefix = if args.stats { "{\"results\":[" } else { "[" };
        emit_raw(&pb_output, prefix);
    }

    // Execute with Concurrency Control
    // We switch between buffered (ordered) and buffer_unordered (immediate)
    if args.unordered {
        tasks
            .buffer_unordered(args.concurrency)
            .for_each(|result| {
                let pb = pb_output.clone();
                let cfg = print_cfg.clone();
                let filter = output_filter.clone();
                let astate = array_started.clone();
                async move {
                    if let Some(ref pb) = pb {
                        pb.suspend(|| result.print(&cfg, &filter, &astate));
                    } else {
                        result.print(&cfg, &filter, &astate);
                    }
                }
            })
            .await;
    } else {
        tasks
            .buffered(args.concurrency)
            .for_each(|result| {
                let pb = pb_output.clone();
                let cfg = print_cfg.clone();
                let filter = output_filter.clone();
                let astate = array_started.clone();
                async move {
                    if let Some(ref pb) = pb {
                        pb.suspend(|| result.print(&cfg, &filter, &astate));
                    } else {
                        result.print(&cfg, &filter, &astate);
                    }
                }
            })
            .await;
    }

    // Finish progress bar
    if let Some(ref pb) = progress_bar {
        pb.set_message(stats.format_progress());
        pb.finish_and_clear();
    }

    // Close the JSON array (embedding stats when requested), or otherwise print the
    // statistics summary in the existing line-delimited / text form.
    if args.json_array {
        use std::io::Write;
        let suffix = if args.stats {
            format!("],\"stats\":{}}}\n", stats.stats_value())
        } else {
            "]\n".to_string()
        };
        // A dropped write here silently truncates the JSON document while still exiting
        // 0, so it goes through the same error handling as the result lines.
        handle_write(write!(std::io::stdout().lock(), "{}", suffix));
    } else if args.stats {
        if args.json {
            use std::io::Write;
            handle_write(writeln!(std::io::stdout().lock(), "{}", stats.format_summary_json()));
        } else {
            eprintln!("{}", stats.format_summary());
        }
    }

    Ok(())
}

/// Classify a resolve error into an output message suffix.
/// Returns a descriptive error string for the given NetError.
fn classify_resolve_error(e: &NetError) -> String {
    match e {
        NetError::Timeout => "TIMEOUT".to_string(),
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => match no_records.response_code {
            ResponseCode::NXDomain => "NXDOMAIN".to_string(),
            ResponseCode::NoError => "NODATA".to_string(),
            ResponseCode::ServFail => "SERVFAIL".to_string(),
            ResponseCode::Refused => "REFUSED".to_string(),
            other => format!("NO_RECORDS ({other})"),
        },
        NetError::Dns(DnsError::ResponseCode(rc)) => match *rc {
            ResponseCode::NXDomain => "NXDOMAIN".to_string(),
            ResponseCode::NoError => "NODATA".to_string(),
            ResponseCode::ServFail => "SERVFAIL".to_string(),
            ResponseCode::Refused => "REFUSED".to_string(),
            other => format!("RCODE ({other})"),
        },
        NetError::Proto(proto_err) => format!("PROTO_ERR: {}", proto_err),
        // Fallback: print the actual error message so you know exactly what failed
        _ => format!("ERR: {}", e),
    }
}

/// True when a resolve error means no response ever arrived, so there is no round trip
/// to measure. This is the same condition `classify_resolve_error` reports as "TIMEOUT",
/// exposed as a flag so the RTT statistics can skip these without matching on strings.
fn is_timeout_error(e: &NetError) -> bool {
    matches!(e, NetError::Timeout)
}

/// Helper: build an error LookupResult
fn lookup_error(input: String, qt_lower: String, e: &NetError) -> LookupResult {
    LookupResult {
        query: input,
        punycode: None,
        query_type: qt_lower,
        is_success: false,
        timed_out: is_timeout_error(e),
        measured_rtt: None,
        status: classify_resolve_error(e), // Now consumes the generated String
        records: vec![],
        ttl: None,
    }
}

/// Helper: build a successful LookupResult
fn lookup_success(
    input: String,
    qt_lower: String,
    records: Vec<RecordEntry>,
    ttl: Option<u32>,
) -> LookupResult {
    LookupResult {
        query: input,
        punycode: None,
        query_type: qt_lower,
        is_success: !records.is_empty(),
        // A result only exists here because a response came back, so it was measured.
        timed_out: false,
        measured_rtt: None,
        status: if records.is_empty() {
            "No records found".to_string()
        } else {
            "SUCCESS".to_string()
        },
        records,
        ttl,
    }
}

/// Learn the wildcard address sets for the parent domains listed in `path`.
///
/// For each parent, a few random non-existent labels are resolved (A and AAAA);
/// the union of returned addresses is that parent's wildcard set. Parents with no
/// wildcard (NXDOMAIN for the random probes) are omitted. The resulting map is then
/// used by OutputFilter to drop answers that only ever return wildcard addresses.
async fn learn_wildcards(
    resolver: &TokioResolver,
    path: &str,
    probes: usize,
) -> std::io::Result<HashMap<String, HashSet<IpAddr>>> {
    let content = tokio::fs::read_to_string(path).await?;

    // Normalize + dedup parent domains
    let parents: Vec<String> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(normalize_host)
        .filter(|p| !p.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let mut map = HashMap::new();
    for parent in parents {
        let mut set = HashSet::new();
        for _ in 0..probes {
            let probe = format!("{}.{}", random_label(), parent);
            if let Ok(lookup) = resolver.ipv4_lookup(probe.as_str()).await {
                for r in lookup.answers() {
                    if let RData::A(a) = &r.data {
                        set.insert(IpAddr::V4(a.0));
                    }
                }
            }
            if let Ok(lookup) = resolver.ipv6_lookup(probe.as_str()).await {
                for r in lookup.answers() {
                    if let RData::AAAA(a) = &r.data {
                        set.insert(IpAddr::V6(a.0));
                    }
                }
            }
        }
        // Only keep parents that actually exhibit a wildcard
        if !set.is_empty() {
            map.insert(parent, set);
        }
    }
    Ok(map)
}

/// Perform a DNS lookup for the given query type
async fn typed_lookup(
    input: String,
    resolver: TokioResolver,
    query_type: &str,
    include_ttl: bool,
) -> LookupResult {
    let qt_lower = query_type.to_lowercase();

    match query_type {
        "A" => match resolver.ipv4_lookup(input.as_str()).await {
            Ok(lookup) => {
                let (records, ttl) =
                    collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                        RData::A(a) => Some(RecordEntry::Simple(a.0.to_string())),
                        _ => None,
                    });
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "AAAA" => match resolver.ipv6_lookup(input.as_str()).await {
            Ok(lookup) => {
                let (records, ttl) =
                    collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                        RData::AAAA(a) => Some(RecordEntry::Simple(a.0.to_string())),
                        _ => None,
                    });
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "MX" => match resolver.mx_lookup(input.as_str()).await {
            Ok(lookup) => {
                let (records, ttl) =
                    collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                        RData::MX(mx) => Some(RecordEntry::WithPriority {
                            priority: mx.preference,
                            value: mx.exchange.to_string(),
                        }),
                        _ => None,
                    });
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "NS" => match resolver.ns_lookup(input.as_str()).await {
            Ok(lookup) => {
                let (records, ttl) =
                    collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                        RData::NS(ns) => Some(RecordEntry::Simple(ns.0.to_string())),
                        _ => None,
                    });
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "TXT" => match resolver.txt_lookup(input.as_str()).await {
            Ok(lookup) => {
                let (records, ttl) =
                    collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                        RData::TXT(txt) => Some(RecordEntry::Simple(txt.to_string())),
                        _ => None,
                    });
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "SOA" => match resolver.soa_lookup(input.as_str()).await {
            Ok(lookup) => {
                let (records, ttl) =
                    collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                        RData::SOA(soa) => Some(RecordEntry::Simple(format!(
                            "{} {} {} {} {} {} {}",
                            soa.mname,
                            soa.rname,
                            soa.serial,
                            soa.refresh,
                            soa.retry,
                            soa.expire,
                            soa.minimum
                        ))),
                        _ => None,
                    });
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "SRV" => match resolver.srv_lookup(input.as_str()).await {
            Ok(lookup) => {
                let (records, ttl) =
                    collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                        RData::SRV(srv) => Some(RecordEntry::Simple(format!(
                            "{} {} {} {}",
                            srv.priority, srv.weight, srv.port, srv.target
                        ))),
                        _ => None,
                    });
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        // PTRMATCH: PTR lookup + forward-confirm A/AAAA against the original IP.
        // If the forward lookup matches, output label is "PTRMATCH"; otherwise "PTR".
        // If input is not an IP address, falls through to regular PTR behavior.
        "PTRMATCH" => {
            if let Ok(ip) = input.parse::<IpAddr>() {
                // reverse_lookup takes impl IntoName; convert IP → reverse DNS Name
                let rev_name = hickory_resolver::proto::rr::Name::from(ip);
                let rev_start = Instant::now();
                match resolver.reverse_lookup(rev_name).await {
                    Ok(lookup) => {
                        let rev_elapsed = rev_start.elapsed();
                        // --ttl applies to reverse lookups too; it used to be dropped here.
                        let (records, ttl) =
                            collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                                RData::PTR(ptr) => Some(RecordEntry::Simple(ptr.0.to_string())),
                                _ => None,
                            });

                        // Forward-confirm: resolve A (IPv4) or AAAA (IPv6) for each PTR name
                        let mut any_match = false;
                        'fwd: for record in &records {
                            let ptr_name = match record {
                                RecordEntry::Simple(s) => s.as_str(),
                                _ => continue,
                            };
                            match ip {
                                IpAddr::V4(v4) => {
                                    if let Ok(fwd) = resolver.ipv4_lookup(ptr_name).await {
                                        let has_match = fwd
                                            .answers()
                                            .iter()
                                            .any(|r| matches!(&r.data, RData::A(a) if a.0 == v4));
                                        if has_match {
                                            any_match = true;
                                            break 'fwd;
                                        }
                                    }
                                }
                                IpAddr::V6(v6) => {
                                    if let Ok(fwd) = resolver.ipv6_lookup(ptr_name).await {
                                        let has_match = fwd.answers().iter().any(
                                            |r| matches!(&r.data, RData::AAAA(a) if a.0 == v6),
                                        );
                                        if has_match {
                                            any_match = true;
                                            break 'fwd;
                                        }
                                    }
                                }
                            }
                        }

                        let label = if any_match { "ptrmatch" } else { "ptr" };
                        let mut result = lookup_success(input, label.to_string(), records, ttl);
                        if any_match {
                            result.status = "PTRMATCH".to_string();
                        }
                        result.measured_rtt = Some(rev_elapsed);
                        result
                    }
                    Err(e) => lookup_error(input, "ptr".to_string(), &e),
                }
            } else {
                // Not an IP — do a generic PTR lookup (no forward-confirm possible)
                match resolver.lookup(input.as_str(), RecordType::PTR).await {
                    Ok(lookup) => {
                        let (records, ttl) =
                            collect_records(lookup.answers().iter(), include_ttl, |d| {
                                (d.record_type() == RecordType::PTR)
                                    .then(|| RecordEntry::Simple(d.to_string()))
                            });
                        lookup_success(input, "ptr".to_string(), records, ttl)
                    }
                    Err(e) => lookup_error(input, "ptr".to_string(), &e),
                }
            }
        }
        // PTR: if input is an IP address, use reverse_lookup; otherwise generic lookup
        "PTR" => {
            if let Ok(ip) = input.parse::<IpAddr>() {
                let rev_name = hickory_resolver::proto::rr::Name::from(ip);
                match resolver.reverse_lookup(rev_name).await {
                    Ok(lookup) => {
                        // --ttl applies to reverse lookups too; it used to be dropped here.
                        let (records, ttl) =
                            collect_records(lookup.answers().iter(), include_ttl, |d| match d {
                                RData::PTR(ptr) => Some(RecordEntry::Simple(ptr.0.to_string())),
                                _ => None,
                            });
                        lookup_success(input, qt_lower, records, ttl)
                    }
                    Err(e) => lookup_error(input, qt_lower, &e),
                }
            } else {
                // Not an IP — do a generic PTR lookup on the hostname
                match resolver.lookup(input.as_str(), RecordType::PTR).await {
                    Ok(lookup) => {
                        let (records, ttl) =
                            collect_records(lookup.answers().iter(), include_ttl, |d| {
                                (d.record_type() == RecordType::PTR)
                                    .then(|| RecordEntry::Simple(d.to_string()))
                            });
                        lookup_success(input, qt_lower, records, ttl)
                    }
                    Err(e) => lookup_error(input, qt_lower, &e),
                }
            }
        }
        // Generic lookup for CAA, DNSKEY, DS, HTTPS, TLSA
        // resolver.lookup() returns Lookup directly, so records and TTL are extracted inline
        _ => {
            let record_type = to_record_type(query_type);
            match resolver.lookup(input.as_str(), record_type).await {
                Ok(lookup) => {
                    let (records, ttl) =
                        collect_records(lookup.answers().iter(), include_ttl, |d| {
                            (d.record_type() == record_type)
                                .then(|| RecordEntry::Simple(d.to_string()))
                        });
                    lookup_success(input, qt_lower, records, ttl)
                }
                Err(e) => lookup_error(input, qt_lower, &e),
            }
        }
    }
}

// Helper dependency for the stream macro
mod async_stream {
    pub use async_stream::stream;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn mk_result(query: &str, qt_lower: &str, ips: &[&str]) -> LookupResult {
        let records = ips.iter().map(|s| RecordEntry::Simple(s.to_string())).collect::<Vec<_>>();
        LookupResult {
            query: query.to_string(),
            punycode: None,
            query_type: qt_lower.to_string(),
            is_success: !records.is_empty(),
            timed_out: false,
            measured_rtt: None,
            status: if records.is_empty() {
                "No records found".to_string()
            } else {
                "SUCCESS".to_string()
            },
            records,
            ttl: None,
        }
    }

    // ── argument validation ──────────────────────────────────────────────────
    #[test]
    fn query_type_validation() {
        assert_eq!(parse_query_type("a").unwrap(), "A");
        assert_eq!(parse_query_type("AaAa").unwrap(), "AAAA");
        assert!(parse_query_type("bogus").is_err());
    }

    #[test]
    fn input_line_cleaning() {
        assert_eq!(clean_input_line("  example.com  "), Some("example.com"));
        assert_eq!(clean_input_line("\u{feff}example.com"), Some("example.com"));
        assert_eq!(clean_input_line("# comment"), None);
        assert_eq!(clean_input_line("   "), None);
    }

    #[test]
    fn show_filter_validation() {
        assert_eq!(parse_show_filter("success").unwrap(), "SUCCESS");
        assert!(parse_show_filter("weird").is_err());
    }

    #[test]
    fn cidr_validation() {
        assert!(parse_cidr("10.0.0.0/8").is_ok());
        assert!(parse_cidr("2001:db8::/32").is_ok());
        assert!(parse_cidr("nope").is_err());
        assert!(parse_cidr("10.0.0.0/40").is_err());
    }

    #[test]
    fn dedup_preserves_order() {
        let got = dedup_types(&["A".into(), "MX".into(), "A".into(), "AAAA".into(), "MX".into()]);
        assert_eq!(got, vec!["A", "MX", "AAAA"]);
    }

    #[test]
    fn classify_status_buckets() {
        assert_eq!(classify_status("SUCCESS"), "SUCCESS");
        assert_eq!(classify_status("No records found"), "NODATA");
        assert_eq!(classify_status("TIMEOUT"), "TEMP");
        assert_eq!(classify_status("SERVFAIL"), "TEMP");
    }

    // ── punycode ─────────────────────────────────────────────────────────────
    #[test]
    fn punycode_ascii_passthrough() {
        // ASCII names (any case) are returned exactly as typed
        assert_eq!(to_punycode("example.com"), "example.com");
        assert_eq!(to_punycode("EXAMPLE.Com"), "EXAMPLE.Com");
        assert_eq!(to_punycode("8.8.8.8"), "8.8.8.8");
    }

    #[test]
    fn punycode_idn_conversion() {
        // Well-known punycode encodings
        assert_eq!(to_punycode("münchen.de"), "xn--mnchen-3ya.de");
        assert_eq!(to_punycode("bücher.example"), "xn--bcher-kva.example");
        // trailing-dot convention is preserved
        assert_eq!(to_punycode("münchen.de."), "xn--mnchen-3ya.de.");
    }

    #[test]
    fn punycode_if_different_omits_ascii() {
        // ASCII / already-punycode names add nothing -> None (JSON omits the field)
        assert_eq!(punycode_if_different("example.com"), None);
        assert_eq!(punycode_if_different("8.8.8.8"), None);
        assert_eq!(punycode_if_different("xn--mnchen-3ya.de"), None);
        // IDN names yield the punycode form
        assert_eq!(punycode_if_different("münchen.de").as_deref(), Some("xn--mnchen-3ya.de"));
    }

    #[test]
    fn normalize_host_lowercases_and_trims() {
        assert_eq!(normalize_host("  Example.COM. "), "example.com");
        assert_eq!(normalize_host("München.de"), "xn--mnchen-3ya.de");
    }

    // ── percentiles / RTT ────────────────────────────────────────────────────
    /// A tracker sized like a default run: 2000 ms timeout, 2 attempts, 1 nameserver.
    fn test_rtt_tracker() -> RttTracker {
        RttTracker::new(max_trackable_rtt_us(2000, 2, 1))
    }

    #[test]
    fn rtt_bound_covers_worst_case_query() {
        // timeout * attempts * nameservers, in us, doubled
        assert_eq!(max_trackable_rtt_us(2000, 2, 1), 8_000_000);
        assert_eq!(max_trackable_rtt_us(2000, 2, 3), 24_000_000);
        assert_eq!(max_trackable_rtt_us(1, 1, 1), 2_000);
        // degenerate inputs still produce a usable (high >= 2 * low) bound
        assert!(max_trackable_rtt_us(0, 0, 0) >= 2);
        assert!(max_trackable_rtt_us(u64::MAX, 4, 4) > 0);
    }

    #[test]
    fn rtt_tracker_percentiles() {
        let mut t = test_rtt_tracker();
        for ms in 1..=100u64 {
            t.record(Duration::from_millis(ms));
        }
        assert_eq!(t.count(), 100);
        // The histogram reports recorded values rather than interpolating between them,
        // so these land on the sample itself, within the configured resolution.
        let (p50, p95, p99) = t.percentiles();
        assert!((p50 - 50.0).abs() < 0.1, "p50 was {}", p50);
        assert!((p95 - 95.0).abs() < 0.1, "p95 was {}", p95);
        assert!((p99 - 99.0).abs() < 0.1, "p99 was {}", p99);
        assert!((t.min_ms() - 1.0).abs() < 0.01, "min was {}", t.min_ms());
        assert!((t.max_ms() - 100.0).abs() < 0.1, "max was {}", t.max_ms());
        assert!((t.avg_ms() - 50.5).abs() < 0.1, "avg was {}", t.avg_ms());
        assert_eq!(test_rtt_tracker().percentiles(), (0.0, 0.0, 0.0));
        assert_eq!(test_rtt_tracker().format_rtt(), "-/-/-/- ms");
    }

    #[test]
    fn rtt_tracker_microsecond_resolution() {
        let mut t = test_rtt_tracker();
        // Sub-millisecond RTTs must not collapse to 0: below 2048 us the histogram
        // stores single microseconds.
        t.record(Duration::from_micros(250));
        t.record(Duration::from_micros(251));
        assert_eq!(t.count(), 2);
        assert!((t.min_ms() - 0.250).abs() < 0.0005, "min was {}", t.min_ms());
        assert!((t.max_ms() - 0.251).abs() < 0.0005, "max was {}", t.max_ms());
        // A zero-duration sample is clamped in, not dropped
        let mut z = test_rtt_tracker();
        z.record(Duration::from_micros(0));
        assert_eq!(z.count(), 1);
    }

    #[test]
    fn rtt_tracker_clamps_outliers() {
        let mut t = RttTracker::new(max_trackable_rtt_us(10, 1, 1)); // 20 ms ceiling
        t.record(Duration::from_millis(5));
        t.record(Duration::from_secs(60)); // far beyond the bound
        // The outlier is kept as the max rather than discarded or panicking
        assert_eq!(t.count(), 2);
        assert!(t.max_ms() >= 20.0, "max was {}", t.max_ms());
    }

    #[test]
    fn stats_bucket_mapping() {
        assert_eq!(stats_bucket("SUCCESS"), "success");
        assert_eq!(stats_bucket("No records found"), "nodata");
        assert_eq!(stats_bucket("NODATA"), "nodata");
        assert_eq!(stats_bucket("TIMEOUT"), "timeout");
        assert_eq!(stats_bucket("REFUSED"), "refused");
        assert_eq!(stats_bucket("PROTO_ERR: x"), "other");
    }

    #[test]
    fn query_stats_counts_and_json() {
        let s = QueryStats::new(None, max_trackable_rtt_us(2000, 2, 1));
        s.record_completion("SUCCESS", Some(Duration::from_millis(10)));
        s.record_completion("NXDOMAIN", Some(Duration::from_millis(20)));
        s.record_completion("TIMEOUT", None);
        let counts = s.status_counts();
        assert!(counts.contains(&("success", 1)));
        assert!(counts.contains(&("nxdomain", 1)));
        assert!(counts.contains(&("timeout", 1)));
        let v = s.stats_value();
        assert_eq!(v["queries"], 3);
        assert_eq!(v["succeeded"], 1); // only SUCCESS
        assert_eq!(v["errors"], 1); // only TIMEOUT; NXDOMAIN is a definitive answer, not an error
        assert!(v["status_counts"]["success"] == 1);
    }

    #[test]
    fn timeouts_are_reported_but_not_measured() {
        let s = QueryStats::new(None, max_trackable_rtt_us(2000, 2, 1));
        s.record_completion("SUCCESS", Some(Duration::from_millis(10)));
        s.record_completion("TIMEOUT", None);
        s.record_completion("TIMEOUT", None);
        let v = s.stats_value();
        // Both timeouts are counted and reported as timeouts...
        assert_eq!(v["queries"], 3);
        assert_eq!(v["status_counts"]["timeout"], 2);
        assert_eq!(v["errors"], 2);
        // ...but only the answered query contributes to the RTT figures, so the
        // 2000 ms timeout budget never shows up as latency.
        assert_eq!(v["rtt_samples"], 1);
        let max = v["rtt_ms_max"].as_f64().unwrap();
        let p99 = v["rtt_ms_p99"].as_f64().unwrap();
        assert!((max - 10.0).abs() < 0.1, "max was {}", max);
        assert!((p99 - 10.0).abs() < 0.1, "p99 was {}", p99);
    }

    #[test]
    fn timeout_errors_are_flagged() {
        assert!(is_timeout_error(&NetError::Timeout));
        // A result built from a successful lookup is never treated as a timeout
        assert!(!mk_result("example.com", "a", &["1.2.3.4"]).timed_out);
    }

    // ── reserved IPs ─────────────────────────────────────────────────────────
    #[test]
    fn reserved_ip_detection() {
        for s in ["10.1.2.3", "192.168.1.1", "172.16.5.5", "100.64.1.1", "127.0.0.1", "169.254.0.1"]
        {
            assert!(is_reserved_ip(ip(s)), "{} should be reserved", s);
        }
        for s in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "203.0.114.1"] {
            assert!(!is_reserved_ip(ip(s)), "{} should be public", s);
        }
        for s in ["::1", "fe80::1", "fc00::1", "fd12:3456::1", "2001:db8::1"] {
            assert!(is_reserved_ip(ip(s)), "{} should be reserved", s);
        }
        assert!(!is_reserved_ip(ip("2606:4700:4700::1111")));
    }

    // ── output filter ────────────────────────────────────────────────────────
    #[test]
    fn filter_match_cidr() {
        let f = OutputFilter {
            match_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
            exclude_private: false,
            wildcards: HashMap::new(),
        };
        assert!(f.ip_filters_active());
        assert!(f.record_passes("10.1.2.3"));
        assert!(!f.record_passes("8.8.8.8"));
        assert!(!f.record_passes("mail.example.com")); // non-IP can't satisfy --match-cidr
    }

    #[test]
    fn filter_match_cidr_prefix_semantics() {
        let narrow = OutputFilter {
            match_cidrs: vec!["157.0.0.0/16".parse().unwrap()],
            exclude_private: false,
            wildcards: HashMap::new(),
        };
        assert!(!narrow.record_passes("157.124.1.11"));
        let wide = OutputFilter {
            match_cidrs: vec!["157.0.0.0/8".parse().unwrap()],
            exclude_private: false,
            wildcards: HashMap::new(),
        };
        assert!(wide.record_passes("157.124.1.11"));
        let exact = OutputFilter {
            match_cidrs: vec!["157.124.0.0/16".parse().unwrap()],
            exclude_private: false,
            wildcards: HashMap::new(),
        };
        assert!(exact.record_passes("157.124.1.11"));
    }

    #[test]
    fn filter_match_cidr_ipv6() {
        let f = OutputFilter {
            match_cidrs: vec!["2001:db8::/32".parse().unwrap()],
            exclude_private: false,
            wildcards: HashMap::new(),
        };
        assert!(f.record_passes("2001:db8::1"));
        assert!(f.record_passes("2001:db8:dead:beef::5"));
        assert!(!f.record_passes("2001:4860:4860::8888")); // outside 2001:db8::/32
        assert!(!f.record_passes("8.8.8.8")); // v4 never matches a v6-only filter

        // Mixed-family filter: a v4 and a v6 CIDR together
        let mixed = OutputFilter {
            match_cidrs: vec!["10.0.0.0/8".parse().unwrap(), "2001:db8::/32".parse().unwrap()],
            exclude_private: false,
            wildcards: HashMap::new(),
        };
        assert!(mixed.record_passes("10.1.2.3"));
        assert!(mixed.record_passes("2001:db8::1"));
        assert!(!mixed.record_passes("9.9.9.9"));
        assert!(!mixed.record_passes("2001:4860:4860::8888"));
    }

    #[test]
    fn filter_exclude_private() {
        let f =
            OutputFilter { match_cidrs: vec![], exclude_private: true, wildcards: HashMap::new() };
        assert!(!f.record_passes("10.1.2.3"));
        assert!(!f.record_passes("fc00::1"));
        assert!(f.record_passes("8.8.8.8"));
        assert!(f.record_passes("mail.example.com")); // non-IP kept; nothing to exclude
    }

    #[test]
    fn filter_inactive() {
        let f =
            OutputFilter { match_cidrs: vec![], exclude_private: false, wildcards: HashMap::new() };
        assert!(!f.ip_filters_active());
        assert!(f.record_passes("whatever"));
        assert!(f.record_passes("10.0.0.1"));
    }

    // ── wildcard filtering ───────────────────────────────────────────────────
    #[test]
    fn wildcard_parent_lookup() {
        let mut m: HashMap<String, HashSet<IpAddr>> = HashMap::new();
        m.insert("example.com".into(), HashSet::from([ip("1.2.3.4")]));
        m.insert("sub.example.com".into(), HashSet::from([ip("5.6.7.8")]));
        assert!(find_wildcard_parent("a.sub.example.com", &m).unwrap().contains(&ip("5.6.7.8")));
        assert!(find_wildcard_parent("foo.example.com", &m).unwrap().contains(&ip("1.2.3.4")));
        assert!(find_wildcard_parent("example.com", &m).is_some());
        assert!(find_wildcard_parent("notexample.com", &m).is_none());
        assert!(find_wildcard_parent("other.org", &m).is_none());
        // shorter than the parent, and a suffix that isn't on a label boundary
        assert!(find_wildcard_parent("com", &m).is_none());
        assert!(find_wildcard_parent("xexample.com", &m).is_none());
        // the longest matching parent wins regardless of HashMap iteration order
        assert!(find_wildcard_parent("a.b.sub.example.com", &m).unwrap().contains(&ip("5.6.7.8")));
    }

    #[test]
    fn wildcard_hit_rules() {
        let set = HashSet::from([ip("1.2.3.4"), ip("1.2.3.5")]);
        assert!(is_wildcard_hit(&[ip("1.2.3.4")], &set));
        assert!(is_wildcard_hit(&[ip("1.2.3.4"), ip("1.2.3.5")], &set));
        assert!(!is_wildcard_hit(&[ip("1.2.3.4"), ip("9.9.9.9")], &set)); // a real IP -> keep
        assert!(!is_wildcard_hit(&[], &set));
        assert!(!is_wildcard_hit(&[ip("1.2.3.4")], &HashSet::new()));
    }

    #[test]
    fn wildcard_result_decision() {
        let mut wildcards: HashMap<String, HashSet<IpAddr>> = HashMap::new();
        wildcards.insert("example.com".into(), HashSet::from([ip("1.2.3.4")]));
        let f = OutputFilter { match_cidrs: vec![], exclude_private: false, wildcards };

        // A answer that only returns the wildcard IP -> filtered
        assert!(f.is_wildcard_result(&mk_result("foo.example.com", "a", &["1.2.3.4"])));
        // A answer with a non-wildcard IP -> kept
        assert!(!f.is_wildcard_result(&mk_result("foo.example.com", "a", &["1.2.3.4", "9.9.9.9"])));
        // Not under a known parent -> kept
        assert!(!f.is_wildcard_result(&mk_result("foo.other.org", "a", &["1.2.3.4"])));
        // Non A/AAAA type -> never wildcard-filtered
        assert!(!f.is_wildcard_result(&mk_result("foo.example.com", "mx", &["1.2.3.4"])));
        // No wildcards configured -> never filtered
        let empty =
            OutputFilter { match_cidrs: vec![], exclude_private: false, wildcards: HashMap::new() };
        assert!(!empty.is_wildcard_result(&mk_result("foo.example.com", "a", &["1.2.3.4"])));
    }

    #[test]
    fn record_entry_value_str() {
        assert_eq!(RecordEntry::Simple("x".into()).value_str(), "x");
        assert_eq!(
            RecordEntry::WithPriority { priority: 10, value: "mail.x".into() }.value_str(),
            "mail.x"
        );
    }
}
