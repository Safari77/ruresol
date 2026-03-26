use clap::Parser;
use futures::stream::StreamExt;
use hickory_resolver::ResolveErrorKind;
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::rr::rdata::{A, AAAA};
use hickory_resolver::proto::xfer::Protocol;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

// TokioResolver type alias for convenience
type TokioResolver = Resolver<TokioConnectionProvider>;

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
    #[arg(long)]
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
    #[arg(long = "type", value_parser = parse_query_type, required = true)]
    query_type: Vec<String>,

    /// Extra domains to resolve (specified after --)
    #[arg(last = true)]
    extra: Vec<String>,

    /// Show progress bar and live query statistics on stderr
    #[arg(long)]
    progress: bool,

    /// Only print record values (no query name, no type prefix). Errors are suppressed.
    #[arg(long)]
    short: bool,

    /// Print query statistics summary after completion
    #[arg(long)]
    stats: bool,

    /// Include TTL in JSON output (only effective with --json)
    #[arg(long)]
    ttl: bool,

    /// Only show results matching these statuses. Can be specified multiple times.
    /// Allowed: SUCCESS, PTRMATCH, NXDOMAIN, NODATA, TEMP
    #[arg(long = "show-only", value_parser = parse_show_filter)]
    show_only: Vec<String>,
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

// ─── RTT / Query Statistics ─────────────────────────────────────────────────

/// Tracks per-query RTT for min/avg/max/mdev calculation
struct RttTracker {
    count: u64,
    min_ms: f64,
    max_ms: f64,
    sum_ms: f64,
    sum_sq_ms: f64,
}

impl RttTracker {
    fn new() -> Self {
        Self { count: 0, min_ms: f64::MAX, max_ms: 0.0, sum_ms: 0.0, sum_sq_ms: 0.0 }
    }

    fn record(&mut self, duration: Duration) {
        let ms = duration.as_secs_f64() * 1000.0;
        self.count += 1;
        if ms < self.min_ms {
            self.min_ms = ms;
        }
        if ms > self.max_ms {
            self.max_ms = ms;
        }
        self.sum_ms += ms;
        self.sum_sq_ms += ms * ms;
    }

    fn avg_ms(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        self.sum_ms / self.count as f64
    }

    /// Population standard deviation of RTT
    fn mdev_ms(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let mean = self.avg_ms();
        let variance = (self.sum_sq_ms / self.count as f64) - (mean * mean);
        // Guard against tiny negative values from floating-point imprecision
        if variance < 0.0 { 0.0 } else { variance.sqrt() }
    }

    fn format_rtt(&self) -> String {
        if self.count == 0 {
            return "-/-/-/- ms".to_string();
        }
        format!(
            "{:.1}/{:.1}/{:.1}/{:.1} ms",
            self.min_ms,
            self.avg_ms(),
            self.max_ms,
            self.mdev_ms()
        )
    }
}

/// Shared query statistics (thread-safe)
struct QueryStats {
    submitted: AtomicU64,
    completed: AtomicU64,
    errors: AtomicU64,
    bytes_read: AtomicU64,
    eof_reached: AtomicBool,
    file_input: bool, // true if -i with a regular file (known size)
    start: Instant,
    rtt: Mutex<RttTracker>,
}

impl QueryStats {
    fn new(file_input: bool) -> Self {
        Self {
            submitted: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            eof_reached: AtomicBool::new(false),
            file_input,
            start: Instant::now(),
            rtt: Mutex::new(RttTracker::new()),
        }
    }

    fn record_completion(&self, is_success: bool, duration: Duration) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        if !is_success {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut rtt) = self.rtt.lock() {
            rtt.record(duration);
        }
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

        let total_str =
            if self.file_input || eof { format!("{}", submitted) } else { "?".to_string() };

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
        let succeeded = completed - errors;
        let elapsed = self.start.elapsed();

        let rtt_str =
            if let Ok(rtt) = self.rtt.lock() { rtt.format_rtt() } else { "-/-/-/- ms".to_string() };

        format!(
            "\n--- Query Statistics ---\n\
             Queries:   {}\n\
             Succeeded: {}\n\
             Errors:    {}\n\
             Elapsed:   {:.1}s\n\
             QPS:       {:.1} q/s\n\
             RTT:       {} (min/avg/max/mdev)",
            completed,
            succeeded,
            errors,
            elapsed.as_secs_f64(),
            self.qps(),
            rtt_str
        )
    }

    /// Format statistics as a JSON object for --stats --json
    fn format_summary_json(&self) -> String {
        let completed = self.completed.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let succeeded = completed - errors;
        let elapsed = self.start.elapsed().as_secs_f64();

        let (rtt_min, rtt_avg, rtt_max, rtt_mdev) = if let Ok(rtt) = self.rtt.lock() {
            if rtt.count > 0 {
                (rtt.min_ms, rtt.avg_ms(), rtt.max_ms, rtt.mdev_ms())
            } else {
                (0.0, 0.0, 0.0, 0.0)
            }
        } else {
            (0.0, 0.0, 0.0, 0.0)
        };

        serde_json::json!({
            "stats": {
                "queries": completed,
                "succeeded": succeeded,
                "errors": errors,
                "elapsed_sec": (elapsed * 1000.0).round() / 1000.0,
                "qps": (self.qps() * 10.0).round() / 10.0,
                "rtt_ms_min": (rtt_min * 1000.0).round() / 1000.0,
                "rtt_ms_avg": (rtt_avg * 1000.0).round() / 1000.0,
                "rtt_ms_max": (rtt_max * 1000.0).round() / 1000.0,
                "rtt_ms_mdev": (rtt_mdev * 1000.0).round() / 1000.0
            }
        })
        .to_string()
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

/// Unified structure for handling outputs
#[derive(serde::Serialize)]
struct LookupResult {
    query: String,
    #[serde(rename = "querytype")]
    query_type: String,
    #[serde(skip_serializing)]
    is_success: bool,
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<RecordEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

impl LookupResult {
    fn print(&self, json_output: bool, short: bool, show_only: &[String]) {
        // Apply --show-only filter: if filters are set, skip non-matching results
        if !show_only.is_empty() {
            let category = classify_status(&self.status);
            if !show_only.iter().any(|f| f == category) {
                return;
            }
        }

        if short {
            // --short: only print values for successful lookups, one per line
            if !self.is_success {
                return;
            }
            for record in &self.records {
                match record {
                    RecordEntry::WithPriority { priority, value } => {
                        println!("{} {}", priority, value);
                    }
                    RecordEntry::Simple(value) => {
                        println!("{}", value);
                    }
                }
            }
            return;
        }

        if json_output {
            if let Ok(json_str) = serde_json::to_string(self) {
                println!("{}", json_str);
            }
        } else if self.is_success {
            // One record per line: "query TYPE [priority]=value"
            let qt = &self.query_type.to_uppercase();
            for record in &self.records {
                match record {
                    RecordEntry::WithPriority { priority, value } => {
                        println!("{} {} {}={}", self.query, qt, priority, value);
                    }
                    RecordEntry::Simple(value) => {
                        println!("{} {}={}", self.query, qt, value);
                    }
                }
            }
        } else {
            println!("{}:{}", self.query, self.status);
        }
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Initialize Resolver Config (Custom vs System Default)
    let (config, mut opts) = if args.doh {
        (ResolverConfig::cloudflare_https(), ResolverOpts::default())
    } else if !args.resolver.is_empty() {
        let mut nsg = NameServerConfigGroup::new();
        for r in &args.resolver {
            let addr: SocketAddr = if let Ok(ip) = r.parse::<IpAddr>() {
                SocketAddr::new(ip, 53)
            } else {
                r.parse()
                    .unwrap_or_else(|_| panic!("Invalid resolver format: {}. Use IP or IP:PORT", r))
            };
            nsg.push(NameServerConfig::new(addr, Protocol::Udp));
            nsg.push(NameServerConfig::new(addr, Protocol::Tcp));
        }
        (ResolverConfig::from_parts(None, vec![], nsg), ResolverOpts::default())
    } else {
        hickory_resolver::system_conf::read_system_conf()?
    };

    // Apply custom timeouts and retries
    opts.timeout = Duration::from_millis(args.timeout);
    opts.attempts = args.attempts;
    // edns_payload_len is 4096 in 0.25.2 and 1232 in next 0.26 release
    opts.edns0 = true;
    opts.try_tcp_on_error = true;

    let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();

    // Determine file size for progress bar (if -i points to a regular file)
    let (file_size, is_regular_file) = if let Some(path) = &args.input {
        if path != "-" {
            match tokio::fs::metadata(path).await {
                Ok(meta) if meta.is_file() => (meta.len(), true),
                _ => (0, false),
            }
        } else {
            (0, false)
        }
    } else {
        (0, false)
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

    let mut interval =
        args.rate_limit.map(|qps| tokio::time::interval(Duration::from_micros(1_000_000 / qps)));

    // Collect extra domains passed after --
    let extra_domains: Vec<String> =
        args.extra.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

    // Initialize statistics tracking (used by --progress and --stats)
    let stats = Arc::new(QueryStats::new(is_regular_file));

    // Initialize progress bar (if --progress)
    let progress_bar: Option<ProgressBar> = if args.progress {
        let pb = if is_regular_file && file_size > 0 {
            let pb = ProgressBar::new(file_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{bar:30.cyan/blue} {percent:>3}% | {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar())
                    .progress_chars("█▓░"),
            );
            pb
        } else {
            // Pipe / stdin / unknown size: use spinner
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.cyan} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            );
            pb
        };
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // Clone handles for the input stream
    let stats_stream = stats.clone();
    let pb_stream = progress_bar.clone();

    // manual UTF-8 check instead of lines()
    let input_stream = async_stream::stream! {
        // First yield extra domains from command line (after --)
        for domain in &extra_domains {
            if let Some(i) = &mut interval {
                i.tick().await;
            }
            yield domain.clone();
        }

        // Then read from file/stdin (if available)
        if let Some(ref mut reader) = reader {
            let mut buf = Vec::new();
            while let Ok(bytes_read) = reader.read_until(b'\n', &mut buf).await {
                if bytes_read == 0 {
                    stats_stream.eof_reached.store(true, Ordering::Relaxed);
                    break;
                } // EOF

                stats_stream.bytes_read.fetch_add(bytes_read as u64, Ordering::Relaxed);
                if let Some(ref pb) = pb_stream
                    && is_regular_file {
                        pb.set_position(stats_stream.bytes_read.load(Ordering::Relaxed));
                    }

                if let Some(i) = &mut interval {
                    i.tick().await;
                }

                // Check if valid UTF-8. If valid, process. If not, we basically ignore (skip) it.
                if let Ok(line_str) = std::str::from_utf8(&buf) {
                    let trimmed = line_str.trim().to_string();
                    if !trimmed.starts_with('#') && !trimmed.is_empty() {
                        yield trimmed;
                    }
                }
                buf.clear();
            }
        }

        // If no reader, mark EOF immediately (only -- args)
        if reader.is_none() {
            stats_stream.eof_reached.store(true, Ordering::Relaxed);
        }
    };

    let effective_types = Arc::new(effective_types);
    let json_mode = args.json;
    let short_mode = args.short;
    let show_only: Arc<Vec<String>> = Arc::new(args.show_only.clone());
    let include_ttl = args.ttl && args.json; // TTL only meaningful with --json

    // Expand each input into one work item per query type
    let work_stream = input_stream.flat_map(move |input| {
        let types = effective_types.clone();
        let pairs: Vec<(String, String)> =
            types.iter().map(|qt| (input.clone(), qt.clone())).collect();
        futures::stream::iter(pairs)
    });

    // Clone handles for the task closures
    let stats_task = stats.clone();
    let pb_task = progress_bar.clone();

    let tasks = work_stream.map(move |(input, query_type)| {
        let resolver = resolver.clone();
        let stats = stats_task.clone();
        let pb = pb_task.clone();

        stats.submitted.fetch_add(1, Ordering::Relaxed);

        async move {
            let start = Instant::now();
            let result = typed_lookup(input, resolver, &query_type, include_ttl).await;
            let elapsed = start.elapsed();

            stats.record_completion(result.is_success, elapsed);
            if let Some(ref pb) = pb {
                pb.set_message(stats.format_progress());
            }

            result
        }
    });

    // Clone handles for the output closure
    let pb_output = progress_bar.clone();

    // Execute with Concurrency Control
    // We switch between buffered (ordered) and buffer_unordered (immediate)
    if args.unordered {
        tasks
            .buffer_unordered(args.concurrency)
            .for_each(|result| {
                let pb = pb_output.clone();
                let show_only = show_only.clone();
                async move {
                    if let Some(ref pb) = pb {
                        pb.suspend(|| result.print(json_mode, short_mode, &show_only));
                    } else {
                        result.print(json_mode, short_mode, &show_only);
                    }
                }
            })
            .await;
    } else {
        tasks
            .buffered(args.concurrency)
            .for_each(|result| {
                let pb = pb_output.clone();
                let show_only = show_only.clone();
                async move {
                    if let Some(ref pb) = pb {
                        pb.suspend(|| result.print(json_mode, short_mode, &show_only));
                    } else {
                        result.print(json_mode, short_mode, &show_only);
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

    // Print statistics summary (--stats)
    if args.stats {
        if args.json {
            println!("{}", stats.format_summary_json());
        } else {
            eprintln!("{}", stats.format_summary());
        }
    }

    Ok(())
}

/// Classify a resolve error into an output message suffix.
/// Returns a descriptive error string for the given ResolveError.
fn classify_resolve_error(e: &hickory_resolver::ResolveError) -> String {
    match e.kind() {
        ResolveErrorKind::Proto(proto_err) => match proto_err.kind() {
            ProtoErrorKind::NoRecordsFound { response_code, .. } => match *response_code {
                ResponseCode::NXDomain => "NXDOMAIN".to_string(),
                ResponseCode::NoError => "NODATA".to_string(),
                ResponseCode::ServFail => "SERVFAIL".to_string(),
                ResponseCode::Refused => "REFUSED".to_string(),
                other => format!("NO_RECORDS ({other})"),
            },
            ProtoErrorKind::Timeout => "TIMEOUT".to_string(),
            // This will catch message parsing errors, truncation issues, etc.
            _ => format!("PROTO_ERR: {}", proto_err),
        },
        // Fallback: print the actual error message so you know exactly what failed
        _ => format!("ERR: {}", e),
    }
}

/// Helper: build an error LookupResult
fn lookup_error(
    input: String,
    qt_lower: String,
    e: &hickory_resolver::ResolveError,
) -> LookupResult {
    LookupResult {
        query: input,
        query_type: qt_lower,
        is_success: false,
        status: classify_resolve_error(e), // Now consumes the generated String
        records: vec![],
        ttl: None,
    }
}

/// Fetch minimum TTL for a given name and record type via generic lookup.
/// Uses the resolver cache, so this won't cause an extra network round-trip
/// when called right after a typed lookup for the same name/type.
async fn fetch_ttl(
    resolver: &TokioResolver,
    name: &str,
    record_type: RecordType,
    include_ttl: bool,
) -> Option<u32> {
    if !include_ttl {
        return None;
    }
    resolver
        .lookup(name, record_type)
        .await
        .ok()
        .and_then(|l| l.record_iter().map(|r| r.ttl()).min())
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
        query_type: qt_lower,
        is_success: !records.is_empty(),
        status: if records.is_empty() {
            "No records found".to_string()
        } else {
            "SUCCESS".to_string()
        },
        records,
        ttl,
    }
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
                let ttl = fetch_ttl(&resolver, input.as_str(), RecordType::A, include_ttl).await;
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|ip| RecordEntry::Simple(ip.to_string())).collect();
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "AAAA" => match resolver.ipv6_lookup(input.as_str()).await {
            Ok(lookup) => {
                let ttl = fetch_ttl(&resolver, input.as_str(), RecordType::AAAA, include_ttl).await;
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|ip| RecordEntry::Simple(ip.to_string())).collect();
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "MX" => match resolver.mx_lookup(input.as_str()).await {
            Ok(lookup) => {
                let ttl = fetch_ttl(&resolver, input.as_str(), RecordType::MX, include_ttl).await;
                let records: Vec<RecordEntry> = lookup
                    .iter()
                    .map(|mx| RecordEntry::WithPriority {
                        priority: mx.preference(),
                        value: mx.exchange().to_string(),
                    })
                    .collect();
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "NS" => match resolver.ns_lookup(input.as_str()).await {
            Ok(lookup) => {
                let ttl = fetch_ttl(&resolver, input.as_str(), RecordType::NS, include_ttl).await;
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|ns| RecordEntry::Simple(ns.0.to_string())).collect();
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "TXT" => match resolver.txt_lookup(input.as_str()).await {
            Ok(lookup) => {
                let ttl = fetch_ttl(&resolver, input.as_str(), RecordType::TXT, include_ttl).await;
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|txt| RecordEntry::Simple(txt.to_string())).collect();
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "SOA" => match resolver.soa_lookup(input.as_str()).await {
            Ok(lookup) => {
                let ttl = fetch_ttl(&resolver, input.as_str(), RecordType::SOA, include_ttl).await;
                let records: Vec<RecordEntry> = lookup
                    .iter()
                    .map(|soa| {
                        RecordEntry::Simple(format!(
                            "{} {} {} {} {} {} {}",
                            soa.mname(),
                            soa.rname(),
                            soa.serial(),
                            soa.refresh(),
                            soa.retry(),
                            soa.expire(),
                            soa.minimum()
                        ))
                    })
                    .collect();
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        "SRV" => match resolver.srv_lookup(input.as_str()).await {
            Ok(lookup) => {
                let ttl = fetch_ttl(&resolver, input.as_str(), RecordType::SRV, include_ttl).await;
                let records: Vec<RecordEntry> = lookup
                    .iter()
                    .map(|srv| {
                        RecordEntry::Simple(format!(
                            "{} {} {} {}",
                            srv.priority(),
                            srv.weight(),
                            srv.port(),
                            srv.target()
                        ))
                    })
                    .collect();
                lookup_success(input, qt_lower, records, ttl)
            }
            Err(e) => lookup_error(input, qt_lower, &e),
        },
        // PTRMATCH: PTR lookup + forward-confirm A/AAAA against the original IP.
        // If the forward lookup matches, output label is "PTRMATCH"; otherwise "PTR".
        // If input is not an IP address, falls through to regular PTR behavior.
        "PTRMATCH" => {
            if let Ok(ip) = input.parse::<IpAddr>() {
                match resolver.reverse_lookup(ip).await {
                    Ok(lookup) => {
                        let records: Vec<RecordEntry> = lookup
                            .iter()
                            .map(|name| RecordEntry::Simple(name.to_string()))
                            .collect();

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
                                        if fwd.iter().any(|a| *a == A(v4)) {
                                            any_match = true;
                                            break 'fwd;
                                        }
                                    }
                                }
                                IpAddr::V6(v6) => {
                                    if let Ok(fwd) = resolver.ipv6_lookup(ptr_name).await {
                                        if fwd.iter().any(|a| *a == AAAA(v6)) {
                                            any_match = true;
                                            break 'fwd;
                                        }
                                    }
                                }
                            }
                        }

                        let label = if any_match { "ptrmatch" } else { "ptr" };
                        let mut result = lookup_success(input, label.to_string(), records, None);
                        if any_match {
                            result.status = "PTRMATCH".to_string();
                        }
                        result
                    }
                    Err(e) => lookup_error(input, "ptr".to_string(), &e),
                }
            } else {
                // Not an IP — do a generic PTR lookup (no forward-confirm possible)
                match resolver.lookup(input.as_str(), RecordType::PTR).await {
                    Ok(lookup) => {
                        let ttl = if include_ttl {
                            lookup.record_iter().map(|r| r.ttl()).min()
                        } else {
                            None
                        };
                        let records: Vec<RecordEntry> = lookup
                            .record_iter()
                            .map(|r| RecordEntry::Simple(r.data().to_string()))
                            .collect();
                        lookup_success(input, "ptr".to_string(), records, ttl)
                    }
                    Err(e) => lookup_error(input, "ptr".to_string(), &e),
                }
            }
        }
        // PTR: if input is an IP address, use reverse_lookup; otherwise generic lookup
        "PTR" => {
            if let Ok(ip) = input.parse::<IpAddr>() {
                match resolver.reverse_lookup(ip).await {
                    Ok(lookup) => {
                        let records: Vec<RecordEntry> = lookup
                            .iter()
                            .map(|name| RecordEntry::Simple(name.to_string()))
                            .collect();
                        lookup_success(input, qt_lower, records, None)
                    }
                    Err(e) => lookup_error(input, qt_lower, &e),
                }
            } else {
                // Not an IP — do a generic PTR lookup on the hostname
                match resolver.lookup(input.as_str(), RecordType::PTR).await {
                    Ok(lookup) => {
                        let ttl = if include_ttl {
                            lookup.record_iter().map(|r| r.ttl()).min()
                        } else {
                            None
                        };
                        let records: Vec<RecordEntry> = lookup
                            .record_iter()
                            .map(|r| RecordEntry::Simple(r.data().to_string()))
                            .collect();
                        lookup_success(input, qt_lower, records, ttl)
                    }
                    Err(e) => lookup_error(input, qt_lower, &e),
                }
            }
        }
        // Generic lookup for CAA, DNSKEY, DS, HTTPS, TLSA
        // resolver.lookup() returns Lookup directly, so we extract TTL inline
        _ => {
            let record_type = to_record_type(query_type);
            match resolver.lookup(input.as_str(), record_type).await {
                Ok(lookup) => {
                    let ttl = if include_ttl {
                        lookup.record_iter().map(|r| r.ttl()).min()
                    } else {
                        None
                    };
                    let records: Vec<RecordEntry> = lookup
                        .record_iter()
                        .map(|r| RecordEntry::Simple(r.data().to_string()))
                        .collect();
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
