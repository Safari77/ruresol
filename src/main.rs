use clap::{ArgGroup, Parser};
use futures::stream::StreamExt;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::proto::op::ResponseCode;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize Resolver with Custom Timeout
    let (config, mut opts) = hickory_resolver::system_conf::read_system_conf()?;
    opts.timeout = Duration::from_millis(args.timeout);
    opts.attempts = args.attempts;
    let resolver = TokioAsyncResolver::tokio(config, opts);

    // Setup Input Reading
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);

    // manual UTF-8 check instead of lines()
    let input_stream = async_stream::stream! {
        let mut buf = Vec::new();
        while let Ok(bytes_read) = reader.read_until(b'\n', &mut buf).await {
            if bytes_read == 0 { break; } // EOF

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

    // Execute with Concurrency Control
    // We switch between buffered (ordered) and buffer_unordered (immediate)
    if args.unordered {
        tasks
            .buffer_unordered(args.concurrency)
            .for_each(|result| async move {
                if let Some(output) = result {
                    println!("{}", output);
                }
            })
            .await;
    } else {
        tasks
            .buffered(args.concurrency)
            .for_each(|result| async move {
                if let Some(output) = result {
                    println!("{}", output);
                }
            })
            .await;
    }

    Ok(())
}

async fn process_entry(
    input: String,
    resolver: TokioAsyncResolver,
    do_reverse: bool,
    do_ipv4: bool,
    do_ipv6: bool,
) -> Option<String> {
    if do_reverse {
        // Mode: Reverse Lookup (IP -> Hostname)
        if let Ok(ip) = input.parse::<IpAddr>() {
            match resolver.reverse_lookup(ip).await {
                Ok(lookup) => {
                    if let Some(name) = lookup.iter().next() {
                        return Some(format!("{}={}", input, name));
                    }
                    Some(format!("{}:No records found", input))
                }
                Err(e) => match e.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code, .. } => match response_code {
                        ResponseCode::NXDomain => Some(format!("{}:NXDOMAIN", input)),
                        ResponseCode::ServFail => Some(format!("{}:Temporary error", input)),
                        _ => Some(format!("{}:No records found", input)),
                    },
                    ResolveErrorKind::Timeout => Some(format!("{}:Temporary error", input)),
                    _ => Some(format!("{}:Temporary error", input)),
                },
            }
        } else {
            Some(format!("{}:Invalid IP address format", input))
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
            return Some(format!("{}={}", input, results.join(",")));
        }

        // If no results, analyze errors to determine the message
        if errors.is_empty() {
            return Some(format!("{}:No records found", input));
        }

        // Check Error Priority: NXDOMAIN > Temporary > NODATA
        let mut has_nxdomain = false;
        let mut has_temp_error = false;

        for e in &errors {
            match e.kind() {
                ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                    match response_code {
                        ResponseCode::NXDomain => has_nxdomain = true,
                        ResponseCode::NoError => { /* This is NODATA */ }
                        ResponseCode::ServFail => has_temp_error = true,
                        _ => has_temp_error = true,
                    }
                }
                ResolveErrorKind::Timeout => has_temp_error = true,
                _ => has_temp_error = true,
            }
        }

        if has_nxdomain {
            return Some(format!("{}:NXDOMAIN", input));
        }

        if has_temp_error {
            return Some(format!("{}:Temporary error", input));
        }

        // If we are here, we only had NoRecordsFound with NoError (NODATA).
        if do_ipv4 && !do_ipv6 {
            Some(format!("{}:No A records found", input))
        } else if do_ipv6 && !do_ipv4 {
            Some(format!("{}:No AAAA records found", input))
        } else {
            Some(format!("{}:No records found", input))
        }
    }
}

// Helper dependency for the stream macro
mod async_stream {
    pub use async_stream::stream;
}
