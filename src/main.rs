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
use hickory_resolver::proto::xfer::Protocol;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

// TokioResolver type alias for convenience
type TokioResolver = Resolver<TokioConnectionProvider>;

/// Valid values for the --type flag
const VALID_QUERY_TYPES: &[&str] =
    &["A", "AAAA", "MX", "NS", "CAA", "DNSKEY", "DS", "HTTPS", "PTR", "SOA", "SRV", "TLSA", "TXT"];

/// A bulk DNS lookup tool.
/// Reads items from stdin and resolves them concurrently.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(
    override_usage = "ruresol [OPTIONS] <-r|--reverse|-a|--address|--type TYPE> [-- DOMAIN ...]"
)]
struct Args {
    /// Reverse lookup mode (resolve IP to Hostname)
    #[arg(short = 'r', long)]
    reverse: bool,

    /// Address lookup mode (resolve Hostname to IP)
    #[arg(short = 'a', long)]
    address: bool,

    /// Custom DNS resolvers (e.g., 8.8.8.8 or 127.0.0.1:5353). Can be used multiple times.
    #[arg(short = 'R', long)]
    resolver: Vec<String>,

    /// Use DNS-over-HTTPS (Routes via Cloudflare's secure endpoint)
    #[arg(long)]
    doh: bool,

    /// Use IPv4 for address lookups (used with -a)
    #[arg(short = '4', long)]
    ipv4: bool,

    /// Use IPv6 for address lookups (used with -a)
    #[arg(short = '6', long)]
    ipv6: bool,

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

    /// DNS query type. Can be specified multiple times. Allowed: A, AAAA, MX, NS, CAA, DNSKEY, DS, HTTPS, PTR, SOA, SRV, TLSA, TXT
    #[arg(long = "type", value_parser = parse_query_type)]
    query_type: Vec<String>,

    /// Extra domains to resolve (specified after --)
    #[arg(last = true)]
    extra: Vec<String>,
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

/// A single record entry, either a plain value or a value with priority (for MX)
#[derive(serde::Serialize, Clone)]
#[serde(untagged)]
enum RecordEntry {
    Simple(String),
    WithPriority { priority: u16, value: String },
}

impl RecordEntry {
    fn value_str(&self) -> &str {
        match self {
            RecordEntry::Simple(s) => s,
            RecordEntry::WithPriority { value, .. } => value,
        }
    }
}

/// Unified structure for handling outputs
#[derive(serde::Serialize)]
struct LookupResult {
    query: String,
    #[serde(rename = "querytype")]
    query_type: String,
    #[serde(skip_serializing)]
    is_success: bool,
    /// True when --type was explicitly given (uses new output format)
    #[serde(skip_serializing)]
    is_typed_query: bool,
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<RecordEntry>,
}

impl LookupResult {
    fn print(&self, json_output: bool) {
        if json_output {
            if let Ok(json_str) = serde_json::to_string(self) {
                println!("{}", json_str);
            }
        } else if self.is_success {
            if self.is_typed_query {
                // Typed query format: one record per line
                // "query TYPE [priority]=value"
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
                // Original format for A/AAAA/reverse: query=value1,value2
                let values: Vec<&str> = self.records.iter().map(|r| r.value_str()).collect();
                println!("{}={}", self.query, values.join(","));
            }
        } else {
            println!("{}:{}", self.query, self.status);
        }
    }
}

/// Build deduplicated, ordered list of effective query types from -a, -4, -6, and --type flags.
/// Returns (effective_types, is_legacy_forward).
/// is_legacy_forward is true when only -a was used without any --type (backward-compat output).
fn build_effective_types(args: &Args) -> (Vec<String>, bool) {
    let mut types: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Add from --type flags first
    for qt in &args.query_type {
        if seen.insert(qt.clone()) {
            types.push(qt.clone());
        }
    }

    let has_explicit_type = !args.query_type.is_empty();

    // Add from -a flag (deduplicated against --type a / --type aaaa)
    if args.address {
        let add_v4 = args.ipv4 || (!args.ipv4 && !args.ipv6); // default to IPv4
        if add_v4 && seen.insert("A".to_string()) {
            types.push("A".to_string());
        }
        if args.ipv6 && seen.insert("AAAA".to_string()) {
            types.push("AAAA".to_string());
        }
    }

    // is_legacy_forward: -a used, but no --type flags → keep old combined A/AAAA output format
    let is_legacy = args.address && !has_explicit_type;

    (types, is_legacy)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Validate: -r and -a are mutually exclusive
    if args.reverse && args.address {
        eprintln!("error: --reverse and --address cannot be used together");
        std::process::exit(2);
    }

    // Build effective query types (deduplicated)
    let (effective_types, is_legacy_forward) = build_effective_types(&args);

    // Validate: at least one mode must be specified
    if !args.reverse && effective_types.is_empty() {
        eprintln!("error: specify at least one of --reverse, --address, or --type");
        std::process::exit(2);
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

    let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();

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
                if bytes_read == 0 { break; } // EOF

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
    };

    let is_reverse = args.reverse;
    let do_ipv4 = args.ipv4 || (!args.ipv4 && !args.ipv6); // default to IPv4 when -a used
    let do_ipv6 = args.ipv6;
    let effective_types = Arc::new(effective_types);
    let json_mode = args.json;

    // Expand each input into one work item per query type (or one reverse item).
    // This gives fine-grained concurrency control: each (input, type) pair is one task.
    let work_stream = input_stream.flat_map(move |input| {
        let types = effective_types.clone();
        let pairs: Vec<(String, String)> = if is_reverse {
            // Reverse mode: single work item per input
            vec![(input, "__REVERSE__".to_string())]
        } else if is_legacy_forward {
            // Legacy -a mode: single work item per input (combined A/AAAA, old output format)
            vec![(input, "__LEGACY__".to_string())]
        } else {
            // Typed mode: one work item per (input, type)
            types.iter().map(|qt| (input.clone(), qt.clone())).collect()
        };
        futures::stream::iter(pairs)
    });

    let tasks = work_stream.map(move |(input, work_type)| {
        let resolver = resolver.clone();
        async move {
            match work_type.as_str() {
                "__REVERSE__" => reverse_lookup(input, resolver).await,
                "__LEGACY__" => legacy_forward_lookup(input, resolver, do_ipv4, do_ipv6).await,
                qt => typed_lookup(input, resolver, qt).await,
            }
        }
    });

    // Execute with Concurrency Control
    // We switch between buffered (ordered) and buffer_unordered (immediate)
    if args.unordered {
        tasks
            .buffer_unordered(args.concurrency)
            .for_each(|result| async move {
                result.print(json_mode);
            })
            .await;
    } else {
        tasks
            .buffered(args.concurrency)
            .for_each(|result| async move {
                result.print(json_mode);
            })
            .await;
    }

    Ok(())
}

/// Classify a resolve error into an output message suffix.
/// Returns the appropriate error string for the given ResolveError.
fn classify_resolve_error(e: &hickory_resolver::ResolveError) -> &'static str {
    match e.kind() {
        ResolveErrorKind::Proto(proto_err) => match proto_err.kind() {
            ProtoErrorKind::NoRecordsFound { response_code, .. } => match *response_code {
                ResponseCode::NXDomain => "NXDOMAIN",
                ResponseCode::ServFail => "Temporary error",
                ResponseCode::NoError => "NODATA",
                _ => "No records found",
            },
            ProtoErrorKind::Timeout => "Temporary error",
            _ => "Temporary error",
        },
        _ => "Temporary error",
    }
}

/// Helper: build a successful typed LookupResult
fn typed_success(input: String, qt_lower: String, records: Vec<RecordEntry>) -> LookupResult {
    LookupResult {
        query: input,
        query_type: qt_lower,
        is_success: !records.is_empty(),
        is_typed_query: true,
        status: if records.is_empty() {
            "No records found".to_string()
        } else {
            "SUCCESS".to_string()
        },
        records,
    }
}

/// Helper: build an error typed LookupResult
fn typed_error(
    input: String,
    qt_lower: String,
    e: &hickory_resolver::ResolveError,
) -> LookupResult {
    LookupResult {
        query: input,
        query_type: qt_lower,
        is_success: false,
        is_typed_query: true,
        status: classify_resolve_error(e).to_string(),
        records: vec![],
    }
}

/// Reverse lookup (IP -> Hostname), legacy output format
async fn reverse_lookup(input: String, resolver: TokioResolver) -> LookupResult {
    if let Ok(ip) = input.parse::<IpAddr>() {
        match resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                if let Some(name) = lookup.iter().next() {
                    return LookupResult {
                        query: input,
                        query_type: "ptr".to_string(),
                        is_success: true,
                        is_typed_query: false,
                        status: "SUCCESS".to_string(),
                        records: vec![RecordEntry::Simple(name.to_string())],
                    };
                }
                LookupResult {
                    query: input,
                    query_type: "ptr".to_string(),
                    is_success: false,
                    is_typed_query: false,
                    status: "No records found".to_string(),
                    records: vec![],
                }
            }
            Err(e) => LookupResult {
                query: input,
                query_type: "ptr".to_string(),
                is_success: false,
                is_typed_query: false,
                status: classify_resolve_error(&e).to_string(),
                records: vec![],
            },
        }
    } else {
        LookupResult {
            query: input,
            query_type: "ptr".to_string(),
            is_success: false,
            is_typed_query: false,
            status: "Invalid IP address format".to_string(),
            records: vec![],
        }
    }
}

/// Legacy forward lookup (Hostname -> IP), combined A/AAAA with old output format
async fn legacy_forward_lookup(
    input: String,
    resolver: TokioResolver,
    do_ipv4: bool,
    do_ipv6: bool,
) -> LookupResult {
    let mut results = Vec::new();
    let mut errors = Vec::new();

    let qt_label = if do_ipv4 && do_ipv6 {
        "a+aaaa"
    } else if do_ipv6 {
        "aaaa"
    } else {
        "a"
    };

    if do_ipv4 {
        match resolver.ipv4_lookup(&input).await {
            Ok(lookup) => {
                for ip in lookup.iter() {
                    results.push(RecordEntry::Simple(ip.to_string()));
                }
            }
            Err(e) => errors.push(e),
        }
    }

    if do_ipv6 {
        match resolver.ipv6_lookup(&input).await {
            Ok(lookup) => {
                for ip in lookup.iter() {
                    results.push(RecordEntry::Simple(ip.to_string()));
                }
            }
            Err(e) => errors.push(e),
        }
    }

    // If we found any records, return them (Success)
    if !results.is_empty() {
        return LookupResult {
            query: input,
            query_type: qt_label.to_string(),
            is_success: true,
            is_typed_query: false,
            status: "SUCCESS".to_string(),
            records: results,
        };
    }

    // If no results, analyze errors to determine the message
    if errors.is_empty() {
        return LookupResult {
            query: input,
            query_type: qt_label.to_string(),
            is_success: false,
            is_typed_query: false,
            status: "No records found".to_string(),
            records: vec![],
        };
    }

    // Check Error Priority: NXDOMAIN > Temporary > NODATA
    let mut has_nxdomain = false;
    let mut has_temp_error = false;

    for e in &errors {
        match e.kind() {
            ResolveErrorKind::Proto(proto_err) => match proto_err.kind() {
                ProtoErrorKind::NoRecordsFound { response_code, .. } => {
                    match *response_code {
                        ResponseCode::NXDomain => has_nxdomain = true,
                        ResponseCode::NoError => { /* This is NODATA */ }
                        ResponseCode::ServFail => has_temp_error = true,
                        _ => has_temp_error = true,
                    }
                }
                _ => has_temp_error = true,
            },
            _ => has_temp_error = true,
        }
    }

    let status = if has_nxdomain {
        "NXDOMAIN"
    } else if has_temp_error {
        "Temporary error"
    } else if do_ipv4 && !do_ipv6 {
        "No A records found"
    } else if do_ipv6 && !do_ipv4 {
        "No AAAA records found"
    } else {
        "No records found"
    };

    LookupResult {
        query: input,
        query_type: qt_label.to_string(),
        is_success: false,
        is_typed_query: false,
        status: status.to_string(),
        records: vec![],
    }
}

/// Perform a typed DNS lookup for --type queries (new output format)
async fn typed_lookup(input: String, resolver: TokioResolver, query_type: &str) -> LookupResult {
    let qt_lower = query_type.to_lowercase();

    match query_type {
        "A" => match resolver.ipv4_lookup(input.as_str()).await {
            Ok(lookup) => {
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|ip| RecordEntry::Simple(ip.to_string())).collect();
                typed_success(input, qt_lower, records)
            }
            Err(e) => typed_error(input, qt_lower, &e),
        },
        "AAAA" => match resolver.ipv6_lookup(input.as_str()).await {
            Ok(lookup) => {
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|ip| RecordEntry::Simple(ip.to_string())).collect();
                typed_success(input, qt_lower, records)
            }
            Err(e) => typed_error(input, qt_lower, &e),
        },
        "MX" => match resolver.mx_lookup(input.as_str()).await {
            Ok(lookup) => {
                let records: Vec<RecordEntry> = lookup
                    .iter()
                    .map(|mx| RecordEntry::WithPriority {
                        priority: mx.preference(),
                        value: mx.exchange().to_string(),
                    })
                    .collect();
                typed_success(input, qt_lower, records)
            }
            Err(e) => typed_error(input, qt_lower, &e),
        },
        "NS" => match resolver.ns_lookup(input.as_str()).await {
            Ok(lookup) => {
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|ns| RecordEntry::Simple(ns.0.to_string())).collect();
                typed_success(input, qt_lower, records)
            }
            Err(e) => typed_error(input, qt_lower, &e),
        },
        "TXT" => match resolver.txt_lookup(input.as_str()).await {
            Ok(lookup) => {
                let records: Vec<RecordEntry> =
                    lookup.iter().map(|txt| RecordEntry::Simple(txt.to_string())).collect();
                typed_success(input, qt_lower, records)
            }
            Err(e) => typed_error(input, qt_lower, &e),
        },
        "SOA" => match resolver.soa_lookup(input.as_str()).await {
            Ok(lookup) => {
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
                typed_success(input, qt_lower, records)
            }
            Err(e) => typed_error(input, qt_lower, &e),
        },
        "SRV" => match resolver.srv_lookup(input.as_str()).await {
            Ok(lookup) => {
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
                typed_success(input, qt_lower, records)
            }
            Err(e) => typed_error(input, qt_lower, &e),
        },
        // Generic lookup for CAA, DNSKEY, DS, HTTPS, PTR, TLSA
        _ => {
            let record_type = to_record_type(query_type);
            match resolver.lookup(input.as_str(), record_type).await {
                Ok(lookup) => {
                    let records: Vec<RecordEntry> = lookup
                        .record_iter()
                        .map(|r| RecordEntry::Simple(r.data().to_string()))
                        .collect();
                    typed_success(input, qt_lower, records)
                }
                Err(e) => typed_error(input, qt_lower, &e),
            }
        }
    }
}

// Helper dependency for the stream macro
mod async_stream {
    pub use async_stream::stream;
}
