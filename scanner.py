#!/usr/bin/env python3
"""Simple multithreaded TCP port scanner with banner grabbing.

Only scan machines you own or have written permission to test.

Examples:
    python3 scanner.py 127.0.0.1
    python3 scanner.py 192.168.1.10 -p 1-1024
    python3 scanner.py scanme.nmap.org -p 22,80,443 -t 100
"""

import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


def parse_ports(text):
    """Turn '1-1024' or '22,80,443' into a list of ports."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_port(host, port, timeout):
    """Return (port, banner) if the port is open, otherwise None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(1)
                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(100).decode(errors="ignore").strip()
                banner = data.splitlines()[0] if data else ""
            except (socket.timeout, OSError):
                pass
            return port, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("host", help="IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="ports, e.g. 1-1024 or 22,80,443 (default 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="number of threads (default 100)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="seconds to wait per port (default 0.5)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Could not resolve {args.host}")
        return

    ports = parse_ports(args.ports)
    print(f"Scanning {args.host} ({ip}), {len(ports)} ports...\n")
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = pool.map(lambda p: scan_port(ip, p, args.timeout), ports)
        open_ports = sorted(r for r in results if r)

    print(f"{'PORT':<8}{'SERVICE':<12}BANNER")
    for port, banner in open_ports:
        print(f"{port:<8}{SERVICES.get(port, 'unknown'):<12}{banner}")

    print(f"\n{len(open_ports)} open port(s) found in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()