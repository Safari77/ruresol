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

## **Installation**

Ensure you have Rust installed, then build the project in release mode for maximum performance:
cargo build \--release

The binary will be located at ./target/release/ruresol.

## **Usage**

### **Reverse Lookup (IP \-\> Hostname)**

Resolves a list of IPs to their PTR records.
\# Read from file
cat ips.txt | ./target/release/ruresol \-r

\# High concurrency (500 requests at once)
cat huge\_list\_of\_ips.txt | ./target/release/ruresol \-r \-c 500

### **Forward Lookup (Hostname \-\> IP)**

Resolves hostnames to A (IPv4) and/or AAAA (IPv6) records.
\# Resolve to IPv4 only
echo "google.com" | ./target/release/ruresol \-a \-4

\# Resolve to both IPv4 and IPv6
echo "example.com" | ./target/release/ruresol \-a \-4 \-6

### **Advanced Configuration**

Fast Failures:
Set a short timeout (e.g., 1s) and only 1 attempt to speed up scanning of unresponsive hosts.
cat ips.txt | ./target/release/ruresol \-r \-t 1000 \--attempts 1

Immediate Output:
Use \-u to print results as soon as they arrive, rather than waiting to preserve input order.
cat ips.txt | ./target/release/ruresol \-r \-u

## **Options**

| Flag | Long | Description | Default |
| :---- | :---- | :---- | :---- |
| \-r | \--reverse | Reverse lookup mode (IP \-\> Hostname). |  |
| \-a | \--address | Address lookup mode (Hostname \-\> IP). |  |
| \-4 | \--ipv4 | Query A records. |  |
| \-6 | \--ipv6 | Query AAAA records. |  |
| \-c | \--concurrency | Number of simultaneous requests. | 200 |
| \-t | \--timeout | Timeout per query attempt (ms). | 2000 |
|  | \--attempts | Number of retries before giving up. | 2 |
| \-u | \--unordered | Output results immediately (unordered). | False |

