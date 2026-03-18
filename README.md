# **ruresol**

**ruresol** is a high-performance, asynchronous bulk DNS resolver written in Rust. It is designed to process massive lists of IP addresses or hostnames from standard input, resolving them concurrently with configurable limits.

## **Key Features**

* **High Concurrency:** Uses tokio and futures to handle hundreds or thousands of concurrent DNS queries without spawning OS threads for each.
* **Robust Input Handling:** Safely handles input streams containing invalid UTF-8 sequences (ignoring only the bad lines), comments (\#), and empty lines.
* **Configurable Timeouts:** Fine-grained control over timeouts per attempt and the number of retries (--timeout, \--attempts).
* **Flexible Output Ordering:**
  * **Ordered (Default):** Preserves the order of input lines in the output, even if later queries finish first.
  * **Unordered (-u):** Prints results immediately upon completion for faster visual feedback.
* **System Integration:** Automatically parses /etc/resolv.conf (on Unix) or Registry (on Windows) to use your system's configured upstream nameservers.
* **Precise Error Reporting:** Distinguishes between NXDOMAIN, Temporary error (ServFail/Timeout), and empty responses (No records found).

## **Libraries Used**

* [**hickory-resolver**](https://crates.io/crates/hickory-resolver)**:** The core DNS logic. Formerly known as trust-dns, it provides a safe, secure, and fully async DNS implementation.
* [**tokio**](https://crates.io/crates/tokio)**:** The industry-standard asynchronous runtime for Rust, handling the thread pool and I/O scheduling.
* [**futures**](https://crates.io/crates/futures)**:** Used specifically for buffer\_unordered and buffered combinators, allowing us to govern the flow of thousands of async tasks efficiently.
* [**clap**](https://crates.io/crates/clap)**:** Provides the robust command-line argument parsing and help generation.
* [**async-stream**](https://crates.io/crates/async-stream)**:** Enables the creation of asynchronous streams using generator syntax, allowing efficient, non-blocking reading of stdin.
* [**serde**](https://crates.io/crates/serde) & [**serde_json**](https://crates.io/crates/serde_json)**:** Enables seamless, machine-readable JSON serialization.

## **Installation**

Ensure you have Rust installed, then build the project in release mode for maximum performance:
```bash
cargo build --release
```

The binary will be located at `./target/release/ruresol`.

## **Usage**

### **Reverse Lookup (IP -> Hostname)**

Resolves a list of IPs to their PTR records.
# Read from file
```bash
cat ips.txt | ruresol -r
ruresol -r -i ips.txt
```

# High concurrency (500 requests at once)
```bash
cat huge_list.txt | ruresol -r -c 500
```

### **Forward Lookup (Hostname -> IP)**

Resolves hostnames to A (IPv4) and/or AAAA (IPv6) records.
# Resolve to IPv4 only
```bash
echo "google.com" | ruresol -a -4
```

# Resolve to both IPv4 and IPv6
```bash
echo "example.com" | ruresol -a -4 -6
```

### **Advanced Configuration**

# Custom Resolvers & Rate Limiting

Use specific DNS servers (with custom ports) and strictly limit the tool to 15 queries per second.
```bash
ruresol -a -i domains.txt -R 8.8.8.8 -R 127.0.0.1:5353 --rate-limit 15
```

# Fast Failures
Set a short timeout (e.g., 1s) and only 1 attempt to speed up scanning of unresponsive hosts.
```bash
cat ips.txt | ruresol -r -t 1000 --attempts 1
```

# Immediate Output
Use `-u` to print results as soon as they arrive, rather than waiting to preserve input order.
```bash
ruresol -r -u -i ips.txt
```

## **Options**

| Flag | Long | Description | Default |
| :---- | :---- | :---- | :---- |
| -r | --reverse | Reverse lookup mode (IP -> Hostname). |  |
| -a | --address | Address lookup mode (Hostname -> IP). |  |
| -R | --resolver | Custom DNS resolvers (e.g., 8.8.8.8 or 127.0.0.1:5353 or [2001:34::cafe]:53 ). Can be used multiple times. | System default |
|    | --doh | Use DNS-over-HTTPS (Routes via Cloudflare's secure endpoint). | False |
| -4 | --ipv4 | Query A records. |  |
| -6 | --ipv6 | Query AAAA records. |  |
| -i | --input | Read inputs from a file instead of stdin. Use - to explicitly force stdin. | - |
| -j | --json | Output results in JSON format. | False |
|    | --rate-limit | Rate limit queries per second (QPS). | None |
| -c | --concurrency | Number of simultaneous requests. | 25 |
| -t | --timeout | Timeout per query attempt (ms). | 2000 |
|    | --attempts | Number of retries before giving up. | 2 |
| -u | --unordered | Output results immediately (unordered). | False |

