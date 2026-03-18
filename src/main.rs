use clap::{ArgGroup, Parser};
use futures::stream::StreamExt;
use hickory_resolver::ResolveErrorKind;
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::xfer::Protocol;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

// TokioResolver type alias for convenience
type TokioResolver = Resolver<TokioConnectionProvider>;

/// A bulk DNS lookup tool.
/// Reads items from stdin and resolves them concurrently.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(
    override_usage = "Required option missing: ruresol [OPTIONS] <-r|--reverse|-a|--address>"
)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["reverse", "address"])
))]
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
    /// Note: Total timeout \u2248 timeout * attempts * (number of nameservers).
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
}

/// Unified structure for handling outputs
#[derive(serde::Serialize)]
struct LookupResult {
    query: String,
    #[serde(skip_serializing)]
    is_success: bool,
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<String>,
}

impl LookupResult {
    fn print(&self, json_output: bool) {
        if json_output {
            if let Ok(json_str) = serde_json::to_string(self) {
                println!("{}", json_str);
            }
        } else if self.is_success {
            println!("{}={}", self.query, self.records.join(","));
        } else {
            println!("{}:{}", self.query, self.status);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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

    // Setup Input Reading
    let mut reader: Box<dyn AsyncBufRead + Unpin + Send> = if let Some(path) = &args.input {
        if path == "-" {
            Box::new(BufReader::new(tokio::io::stdin()))
        } else {
            let file = tokio::fs::File::open(path).await?;
            Box::new(BufReader::new(file))
        }
    } else {
        Box::new(BufReader::new(tokio::io::stdin()))
    };

    let mut interval =
        args.rate_limit.map(|qps| tokio::time::interval(Duration::from_micros(1_000_000 / qps)));

    // manual UTF-8 check instead of lines()
    let input_stream = async_stream::stream! {
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
    };

    // Create the processing stream
    let tasks = input_stream.map(|input| {
        let resolver = resolver.clone();
        let do_reverse = args.reverse;
        let mut do_ipv4 = args.ipv4;
        let do_ipv6 = args.ipv6;

        if args.address && !do_ipv4 && !do_ipv6 {
            do_ipv4 = true;
        }

        async move { process_entry(input, resolver, do_reverse, do_ipv4, do_ipv6).await }
    });

    let json_mode = args.json;

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

async fn process_entry(
    input: String,
    resolver: TokioResolver,
    do_reverse: bool,
    do_ipv4: bool,
    do_ipv6: bool,
) -> LookupResult {
    if do_reverse {
        // Mode: Reverse Lookup (IP -> Hostname)
        if let Ok(ip) = input.parse::<IpAddr>() {
            match resolver.reverse_lookup(ip).await {
                Ok(lookup) => {
                    if let Some(name) = lookup.iter().next() {
                        return LookupResult {
                            query: input,
                            is_success: true,
                            status: "SUCCESS".to_string(),
                            records: vec![name.to_string()],
                        };
                    }
                    LookupResult {
                        query: input,
                        is_success: false,
                        status: "No records found".to_string(),
                        records: vec![],
                    }
                }
                Err(e) => LookupResult {
                    query: input,
                    is_success: false,
                    status: classify_resolve_error(&e).to_string(),
                    records: vec![],
                },
            }
        } else {
            LookupResult {
                query: input,
                is_success: false,
                status: "Invalid IP address format".to_string(),
                records: vec![],
            }
        }
    } else {
        // Mode: Forward Lookup (Hostname -> IP)
        let mut results = Vec::new();
        let mut errors = Vec::new();

        if do_ipv4 {
            match resolver.ipv4_lookup(&input).await {
                Ok(lookup) => {
                    for ip in lookup.iter() {
                        results.push(ip.to_string());
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        if do_ipv6 {
            match resolver.ipv6_lookup(&input).await {
                Ok(lookup) => {
                    for ip in lookup.iter() {
                        results.push(ip.to_string());
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        // If we found any records, return them (Success)
        if !results.is_empty() {
            return LookupResult {
                query: input,
                is_success: true,
                status: "SUCCESS".to_string(),
                records: results,
            };
        }

        // If no results, analyze errors to determine the message
        if errors.is_empty() {
            return LookupResult {
                query: input,
                is_success: false,
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
            is_success: false,
            status: status.to_string(),
            records: vec![],
        }
    }
}

// Helper dependency for the stream macro
mod async_stream {
    pub use async_stream::stream;
}
