
import socket
import sys
import argparse
import threading
from queue import Queue
import time
from typing import List, Optional

print_lock = threading.Lock()

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S"
}

def scan_port(target: str, port: int, timeout: float = 0.5, grab_banner: bool = False) -> Optional[dict]:
    """Scan a single port and optionally grab banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = ""
            if grab_banner:
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")  # Try HTTP banner
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    banner = banner.split('\n')[0] if banner else ""
                except:
                    pass
            s.close()
            return {"port": port, "service": service, "banner": banner}
        s.close()
    except Exception as e:
        pass
    return None

def worker(target: str, queue: Queue, results: List[dict], timeout: float, grab_banner: bool, verbose: bool):
    """Worker thread for port scanning."""
    while not queue.empty():
        port = queue.get()
        result = scan_port(target, port, timeout, grab_banner)
        if result:
            with print_lock:
                if verbose:
                    print(f"[+] Port {result['port']} open ({result['service']})")
                    if result['banner']:
                        print(f"    └─ Banner: {result['banner']}")
                results.append(result)
        queue.task_done()

def parse_ports(port_arg: str) -> List[int]:
    """Parse port argument (comma-separated or ranges)."""
    ports = []
    for part in port_arg.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def scan_ports(target: str, ports: List[int], threads: int = 4, timeout: float = 0.5,
               grab_banner: bool = False, verbose: bool = False, output_file: Optional[str] = None) -> List[dict]:
    """Scan multiple ports using threading."""
    queue = Queue()
    results = []

    for port in ports:
        queue.put(port)

    start_time = time.time()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(target, queue, results, timeout, grab_banner, verbose))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    elapsed = time.time() - start_time

    with print_lock:
        print(f"\n[+] Scan completed in {elapsed:.2f}s")
        print(f"[+] Found {len(results)} open ports")

        if output_file:
            save_results(results, output_file, target)

    return results

def save_results(results: List[dict], output_file: str, target: str):
    """Save scan results to a file."""
    try:
        with open(output_file, 'w') as f:
            f.write(f"Port scan results for {target}\n")
            f.write("=" * 40 + "\n")
            for result in results:
                f.write(f"Port {result['port']} ({result['service']}) open\n")
                if result['banner']:
                    f.write(f"  Banner: {result['banner']}\n")
                f.write("\n")
        print(f"[+] Results saved to {output_file}")
    except Exception as e:
        print(f"[-] Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner Tool")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="21,22,23,25,53,80,110,139,143,443,445,993,995",
                        help="Ports to scan (comma-separated or ranges, e.g., 1-100)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout (seconds)")
    parser.add_argument("-b", "--banner", action="store_true", help="Grab service banners")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file for results")

    args = parser.parse_args()

    try:
        # Validate target
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Invalid target: {args.target}")
        sys.exit(1)

    ports = parse_ports(args.ports)

    if args.verbose:
        print(f"[+] Scanning {args.target} for {len(ports)} ports with {args.threads} threads...")

    results = scan_ports(args.target, ports, args.threads, args.timeout, args.banner, args.verbose, args.output)

    if not args.verbose and results:
        print("Open ports:")
        for result in results:
            print(f"  {result['port']} ({result['service']})")
            if result['banner']:
                print(f"    └─ {result['banner']}")

if __name__ == "__main__":
    main()
