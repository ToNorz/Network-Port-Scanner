#!/usr/bin/env python3
"""Simple multithreaded TCP port scanner with banner grabbing.

Only scan machines you own or have written permission to test.

Examples:
    python3 scanner.py 127.0.0.1
    python3 scanner.py 192.168.1.10 -p 1-1024
    python3 scanner.py scanme.nmap.org -p 22,80,443 -t 100

Web interface:
    python3 web.py
"""

import argparse
import socket
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    27017: "MongoDB",
}


def parse_ports(text):
    """Turn '1-1024' or '22,80,443' into a sorted list of ports.

    Ports outside 1-65535 are dropped. Ranges are clamped before they are
    expanded so a value like 1-999999 cannot allocate a huge set.
    """
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = max(int(start_text), 1)
            end = min(int(end_text), 65535)
            if start <= end:
                ports.update(range(start, end + 1))
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


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


def scan_host(ip, ports, timeout, threads, on_result=None, cancel_event=None):
    """Scan TCP ports on an IP address.

    on_result(checked, total, hit) runs as each port finishes. hit is
    (port, banner) when the port is open, otherwise None. Returns the open
    ports sorted by port number. If cancel_event is set, ports that have not
    started are dropped and the call returns what it has so far.
    """
    if threads < 1:
        raise ValueError("threads must be at least 1")

    open_ports = []
    total = len(ports)
    if total == 0:
        return open_ports

    checked = 0
    pool = ThreadPoolExecutor(max_workers=min(threads, total))
    cancelled = False
    try:
        pending = {pool.submit(scan_port, ip, port, timeout) for port in ports}
        while pending:
            done, pending = wait(pending, timeout=0.15, return_when=FIRST_COMPLETED)
            for fut in done:
                checked += 1
                try:
                    result = fut.result()
                except Exception:
                    result = None
                if result:
                    open_ports.append(result)
                if on_result:
                    on_result(checked, total, result)
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
    finally:
        pool.shutdown(wait=not cancelled, cancel_futures=cancelled)

    open_ports.sort()
    return open_ports


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

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print("Ports must look like 1-1024 or 22,80,443")
        return
    if not ports:
        print("No valid ports to scan")
        return

    print(f"Scanning {args.host} ({ip}), {len(ports)} ports...\n")
    start = time.time()
    try:
        open_ports = scan_host(ip, ports, args.timeout, args.threads)
    except ValueError as exc:
        print(exc)
        return

    print(f"{'PORT':<8}{'SERVICE':<12}BANNER")
    for port, banner in open_ports:
        print(f"{port:<8}{SERVICES.get(port, 'unknown'):<12}{banner}")

    print(f"\n{len(open_ports)} open port(s) found in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()