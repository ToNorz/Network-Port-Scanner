#!/usr/bin/env python3
"""Local web interface for the TCP port scanner.

The page is served on the loopback interface only, because anyone who can
open it can start a scan from this machine.

    python3 web.py
    python3 web.py --port 8765
"""

import argparse
import json
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from scanner import SERVICES, parse_ports, scan_host

WEB_DIR = Path(__file__).resolve().parent / "web"
HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_THREADS = 200
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 5.0
MAX_BODY = 8192
POLL_WAIT = 20
KEEP_JOBS = 8

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}

STATE = threading.Lock()
JOBS = {}
JOB_ORDER = []


class Job:
    """One scan, plus the events the page polls for."""

    def __init__(self, host, ip, total):
        self.id = uuid.uuid4().hex
        self.host = host
        self.ip = ip
        self.total = total
        self.events = []
        self.finished = False
        self.cancel_event = threading.Event()
        self.cond = threading.Condition()

    def publish(self, name, data):
        with self.cond:
            self.events.append({"name": name, "data": data})
            self.cond.notify_all()

    def finish(self):
        with self.cond:
            self.finished = True
            self.cond.notify_all()

    def wait_from(self, since):
        """Return (events, next_index, done). Wait until something new arrives."""
        with self.cond:
            if since > len(self.events):
                since = len(self.events)
            deadline = time.monotonic() + POLL_WAIT
            while since == len(self.events) and not self.finished:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.cond.wait(remaining)
            events = self.events[since:]
            return events, since + len(events), self.finished


def get_job(scan_id):
    with STATE:
        return JOBS.get(scan_id)


def run_job(job, ports, timeout, threads):
    started = time.time()
    open_count = 0
    checked = 0
    last_emit = 0.0

    def on_result(done, total, result):
        nonlocal open_count, checked, last_emit
        checked = done
        hit = None
        if result:
            port, banner = result
            open_count += 1
            hit = {
                "port": port,
                "service": SERVICES.get(port, "unknown"),
                "banner": banner,
            }
        now = time.monotonic()
        if hit is None and done != total and now - last_emit < 0.08:
            return
        payload = {
            "checked": done,
            "total": total,
            "open": open_count,
            "elapsed": round(time.time() - started, 2),
        }
        if hit is not None:
            payload["hit"] = hit
        job.publish("progress", payload)
        last_emit = now

    print(f"Scanning {job.host} ({job.ip}), {len(ports)} ports", flush=True)
    job.publish("started", {"host": job.host, "ip": job.ip, "total": len(ports)})
    try:
        scan_host(
            job.ip, ports, timeout, threads,
            on_result=on_result, cancel_event=job.cancel_event,
        )
        elapsed = round(time.time() - started, 2)
        job.publish("finished", {
            "open": open_count,
            "checked": checked,
            "total": len(ports),
            "elapsed": elapsed,
            "cancelled": job.cancel_event.is_set(),
        })
        label = "Stopped" if job.cancel_event.is_set() else "Finished"
        print(f"{label} {job.host}: {open_count} open in {elapsed:.1f}s", flush=True)
    except Exception as exc:
        job.publish("failed", {"message": str(exc) or "Scan failed"})
        print(f"Scan failed for {job.host}: {exc}", flush=True)
    finally:
        job.finish()


def launch_scan(host, ip, ports, timeout, threads):
    """Start a scan unless one is already running. Reserves the slot under the lock."""
    job = Job(host, ip, len(ports))
    with STATE:
        if any(not item.finished for item in JOBS.values()):
            return None
        JOBS[job.id] = job
        JOB_ORDER.append(job.id)
        while len(JOB_ORDER) > KEEP_JOBS:
            dropped = JOB_ORDER.pop(0)
            if dropped != job.id:
                JOBS.pop(dropped, None)
    threading.Thread(
        target=run_job, args=(job, list(ports), timeout, threads), daemon=True,
    ).start()
    return job


def validate(data):
    """Return (host, ports, threads, timeout) or an error string."""
    if not isinstance(data, dict):
        return "Expected a JSON object"

    host = data.get("host", "")
    if not isinstance(host, str):
        return "Enter a hostname or IP address"
    host = host.strip()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        return "Enter a hostname or IP address"
    if "://" in host or "/" in host:
        return "Enter a hostname or IP address, not a URL"

    ports_text = data.get("ports", "1-1024")
    if not isinstance(ports_text, str):
        return "Ports must look like 1-1024 or 22,80,443"
    try:
        ports = parse_ports(ports_text)
    except ValueError:
        return "Ports must look like 1-1024 or 22,80,443"
    if not ports:
        return "No valid ports in that range"

    try:
        threads = int(data.get("threads", 100))
    except (TypeError, ValueError):
        return f"Threads must be between 1 and {MAX_THREADS}"
    if not 1 <= threads <= MAX_THREADS:
        return f"Threads must be between 1 and {MAX_THREADS}"

    try:
        timeout = float(data.get("timeout", 0.5))
    except (TypeError, ValueError):
        return f"Timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds"
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        return f"Timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds"

    return host, ports, threads, timeout


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PortScanner/1.0"

    def log_message(self, fmt, *args):
        path = urlparse(self.path).path
        if path.startswith("/api/scans/") and self.command == "GET":
            return
        super().log_message(fmt, *args)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in STATIC:
            self.serve_static(*STATIC[path])
            return
        if path.startswith("/api/scans/"):
            scan_id = path.removeprefix("/api/scans/").strip("/")
            if scan_id and "/" not in scan_id:
                self.serve_events(scan_id)
                return
        self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/scan":
            self.start_scan()
            return
        prefix = "/api/scans/"
        if path.startswith(prefix) and path.endswith("/cancel"):
            scan_id = path[len(prefix):-len("/cancel")]
            if scan_id and "/" not in scan_id:
                self.cancel_scan(scan_id)
                return
        self.send_error(404)

    def serve_static(self, name, content_type):
        file_path = (WEB_DIR / name).resolve()
        if file_path.parent != WEB_DIR or not file_path.is_file():
            self.send_error(404)
            return
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self.send_json(400, {"error": "Expected JSON"})
            return None
        if length < 0 or length > MAX_BODY:
            self.send_json(413, {"error": "Request too large"})
            return None
        return self.rfile.read(length) if length else b""

    def read_json(self):
        raw = self.read_body()
        if raw is None:
            return None
        try:
            data = json.loads(raw.decode() or "null")
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Expected JSON"})
            return None
        if not isinstance(data, dict):
            self.send_json(400, {"error": "Expected a JSON object"})
            return None
        return data

    def start_scan(self):
        data = self.read_json()
        if data is None:
            return
        result = validate(data)
        if isinstance(result, str):
            self.send_json(400, {"error": result})
            return
        host, ports, threads, timeout = result
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            self.send_json(400, {"error": f"Could not resolve {host}"})
            return
        job = launch_scan(host, ip, ports, timeout, threads)
        if job is None:
            self.send_json(409, {"error": "A scan is already running"})
            return
        self.send_json(200, {
            "id": job.id,
            "host": host,
            "ip": ip,
            "total": len(ports),
        })

    def serve_events(self, scan_id):
        job = get_job(scan_id)
        if job is None:
            self.send_json(404, {"error": "Scan not found"})
            return
        query = parse_qs(urlparse(self.path).query)
        try:
            since = int(query.get("since", ["0"])[0])
        except ValueError:
            self.send_json(400, {"error": "since must be an integer"})
            return
        if since < 0:
            since = 0
        events, nxt, done = job.wait_from(since)
        self.send_json(200, {"events": events, "next": nxt, "done": done})

    def cancel_scan(self, scan_id):
        # sendBeacon posts a body. Read it so the connection stays in sync.
        if self.read_body() is None:
            return
        job = get_job(scan_id)
        if job is None:
            self.send_json(404, {"error": "Scan not found"})
            return
        job.cancel_event.set()
        self.send_json(200, {"ok": True})


def main():
    parser = argparse.ArgumentParser(description="Web interface for the port scanner")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"loopback port to listen on (default {DEFAULT_PORT})")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        print("Port must be between 1 and 65535")
        return

    class Server(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    try:
        server = Server((HOST, args.port), Handler)
    except OSError as exc:
        print(f"Could not listen on {HOST}:{args.port}: {exc}")
        return

    url = f"http://{HOST}:{args.port}/"
    print(url)
    print("Only scan hosts you own or have permission to test.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
