#!/usr/bin/env python3
"""Multithreaded TCP port scanner with banner grabbing, risk scoring, and reporting.

A scan is either a normal three-way handshake or a stealth SYN probe.
Stealth mode needs root. Only scan machines you own or have written
permission to test.

Examples:
    python3 scanner.py 127.0.0.1
    python3 scanner.py 192.168.1.10 -p 1-1024
    python3 scanner.py 192.168.1.0/28 -p 22,80,443 -o results.json
    python3 scanner.py scanme.nmap.org -p 21,22,23,80,443 -o report.csv
    sudo python3 scanner.py 127.0.0.1 --mode stealth -p 22,80,443

Web interface:
    python3 web.py
"""

import argparse
import csv
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from stealth import (
    MODE_STEALTH,
    StealthError,
    mode_label,
    normalize_mode,
    open_engine,
    stealth_available,
)

# Known sensitive ports mapped to security severity, risk score (0-10), and actionable remediation
PORT_SECURITY = {
    21: {
        "service": "FTP",
        "risk": "HIGH",
        "score": 7.5,
        "recommendation": "FTP sends credentials and data in cleartext. Replace with SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS).",
    },
    22: {
        "service": "SSH",
        "risk": "LOW",
        "score": 2.0,
        "recommendation": "Secure shell. Disable password-based authentication in favor of SSH keys, disable root login, and keep OpenSSH patched.",
    },
    23: {
        "service": "Telnet",
        "risk": "CRITICAL",
        "score": 9.5,
        "recommendation": "Telnet transmits passwords and session data completely unencrypted. Disable immediately and migrate to SSH (port 22).",
    },
    25: {
        "service": "SMTP",
        "risk": "MEDIUM",
        "score": 5.0,
        "recommendation": "Ensure SMTP enforces STARTTLS, requires authentication, and is not configured as an open relay.",
    },
    53: {
        "service": "DNS",
        "risk": "LOW",
        "score": 3.0,
        "recommendation": "Ensure open recursion is disabled for external queries to prevent DNS cache poisoning and amplification DDoS.",
    },
    69: {
        "service": "TFTP",
        "risk": "HIGH",
        "score": 7.0,
        "recommendation": "Trivial FTP lacks authentication and encryption. Restrict to isolated PXE boot networks or disable.",
    },
    80: {
        "service": "HTTP",
        "risk": "MEDIUM",
        "score": 4.5,
        "recommendation": "Unencrypted web traffic. Redirect all HTTP requests to HTTPS (port 443) and enable HSTS headers.",
    },
    110: {
        "service": "POP3",
        "risk": "HIGH",
        "score": 7.5,
        "recommendation": "POP3 transmits credentials in plaintext. Migrate to POP3S (port 995 with SSL/TLS) or modern OAuth2 IMAPS.",
    },
    111: {
        "service": "RPCbind",
        "risk": "HIGH",
        "score": 7.0,
        "recommendation": "RPCbind / portmapper can leak internal RPC services and be abused in DDoS reflection attacks. Block external access.",
    },
    135: {
        "service": "MS-RPC",
        "risk": "HIGH",
        "score": 8.0,
        "recommendation": "Microsoft RPC endpoint mapper. Frequently targeted for reconnaissance and lateral movement. Block at network perimeter.",
    },
    139: {
        "service": "NetBIOS",
        "risk": "CRITICAL",
        "score": 9.0,
        "recommendation": "NetBIOS Session Service is legacy and vulnerable to eavesdropping and credential relay. Block from external networks.",
    },
    143: {
        "service": "IMAP",
        "risk": "HIGH",
        "score": 7.0,
        "recommendation": "Unencrypted IMAP transmits user credentials in plaintext. Require IMAPS (port 993) with TLS encryption.",
    },
    443: {
        "service": "HTTPS",
        "risk": "INFO",
        "score": 1.0,
        "recommendation": "Encrypted web service. Enforce TLS 1.2+, modern cipher suites, and verify certificate validity and renewals.",
    },
    445: {
        "service": "SMB",
        "risk": "CRITICAL",
        "score": 9.8,
        "recommendation": "SMB file sharing over TCP. Prime vector for ransomware (EternalBlue/WannaCry). Never expose to the Internet; isolate internally.",
    },
    512: {
        "service": "rexec",
        "risk": "CRITICAL",
        "score": 9.0,
        "recommendation": "Legacy remote execution daemon with weak or cleartext authentication. Disable and replace with SSH.",
    },
    513: {
        "service": "rlogin",
        "risk": "CRITICAL",
        "score": 9.0,
        "recommendation": "Legacy r-command using IP-based trust or cleartext passwords. Disable immediately and replace with SSH.",
    },
    514: {
        "service": "rsh",
        "risk": "CRITICAL",
        "score": 9.0,
        "recommendation": "Legacy remote shell without transport encryption. Disable and migrate to SSH.",
    },
    587: {
        "service": "SMTP-Submission",
        "risk": "LOW",
        "score": 2.5,
        "recommendation": "Mail submission port. Ensure mandatory STARTTLS and strict SMTP authentication.",
    },
    993: {
        "service": "IMAPS",
        "risk": "INFO",
        "score": 1.5,
        "recommendation": "Encrypted IMAP over TLS. Ensure modern TLS ciphers and disable obsolete SSLv3/TLSv1.0.",
    },
    995: {
        "service": "POP3S",
        "risk": "INFO",
        "score": 1.5,
        "recommendation": "Encrypted POP3 over TLS. Ensure modern TLS ciphers and valid SSL certificates.",
    },
    1433: {
        "service": "MSSQL",
        "risk": "HIGH",
        "score": 8.0,
        "recommendation": "Microsoft SQL Server. Publicly accessible database ports invite brute-force and exploit attempts. Restrict via firewall/VPN.",
    },
    1521: {
        "service": "Oracle-DB",
        "risk": "HIGH",
        "score": 8.0,
        "recommendation": "Oracle TNS Listener. Do not expose database listeners to public or untrusted networks; use VPN/firewalls.",
    },
    2049: {
        "service": "NFS",
        "risk": "HIGH",
        "score": 7.5,
        "recommendation": "Network File System. Misconfigured exports can expose entire filesystems. Restrict to authorized internal clients.",
    },
    2375: {
        "service": "Docker",
        "risk": "CRITICAL",
        "score": 10.0,
        "recommendation": "Unencrypted Docker daemon API. Grants unauthenticated root container/host control. Secure with TLS (port 2376) or unix socket only.",
    },
    3306: {
        "service": "MySQL",
        "risk": "HIGH",
        "score": 8.0,
        "recommendation": "MySQL database. Direct network exposure poses high risk of brute-force and remote compromise. Bind to 127.0.0.1 or firewall.",
    },
    3389: {
        "service": "RDP",
        "risk": "HIGH",
        "score": 8.5,
        "recommendation": "Remote Desktop Protocol. Prime vector for brute-force and ransomware (e.g. BlueKeep). Enforce Network Level Authentication (NLA) and VPN/MFA.",
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "HIGH",
        "score": 7.5,
        "recommendation": "PostgreSQL database. Exposing database to untrusted networks is unsafe. Require SSL, strong auth, and IP whitelisting.",
    },
    5900: {
        "service": "VNC",
        "risk": "HIGH",
        "score": 8.0,
        "recommendation": "VNC remote desktop. Often uses DES-truncated passwords and lacks transport encryption. Tunnel via SSH or VPN.",
    },
    6379: {
        "service": "Redis",
        "risk": "CRITICAL",
        "score": 9.5,
        "recommendation": "Redis in-memory store. Frequently targeted for unauthenticated RCE and crypto-mining. Require AUTH, rename dangerous commands, bind to localhost.",
    },
    8080: {
        "service": "HTTP-alt",
        "risk": "MEDIUM",
        "score": 5.0,
        "recommendation": "Alternative HTTP / admin console. Often hosts development servers or management panels. Enforce TLS and authentication.",
    },
    8443: {
        "service": "HTTPS-alt",
        "risk": "LOW",
        "score": 2.0,
        "recommendation": "Alternative HTTPS / admin UI. Verify strong TLS ciphers and ensure administrative endpoints require MFA.",
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "CRITICAL",
        "score": 9.0,
        "recommendation": "Elasticsearch REST API. Easily subjected to automated data theft and ransomware if authentication is disabled. Bind to internal IP only.",
    },
    11211: {
        "service": "Memcached",
        "risk": "HIGH",
        "score": 8.5,
        "recommendation": "Memcached has no native authentication and has been abused for massive DDoS reflection. Bind to localhost or firewall.",
    },
    27017: {
        "service": "MongoDB",
        "risk": "CRITICAL",
        "score": 9.5,
        "recommendation": "MongoDB database. Massively exploited when exposed without authentication. Enable authorization and bind to localhost/private IP.",
    },
}

SERVICES = {port: info["service"] for port, info in PORT_SECURITY.items()}


class Colors:
    """Standard terminal ANSI codes for clean presentation."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"


def colorize(text, color, enabled=True):
    if not enabled:
        return text
    return f"{color}{text}{Colors.RESET}"


# ---------------------------------------------------------------------------
# Dynamic risk analysis engine
# ---------------------------------------------------------------------------

# Known-vulnerable version patterns: list of (compiled_regex, score_penalty, note)
# The regex is matched against the raw banner (case-insensitive).
# Penalties are *added* on top of the port's base score (capped at 10.0).
_VULN_PATTERNS = [
    # OpenSSH – old versions
    (re.compile(r"openssh[_\s-]+(\d+)\.(\d+)", re.I), None,
     "OpenSSH version detected — checking age"),
    # Apache httpd
    (re.compile(r"apache/(\d+)\.(\d+)\.(\d+)", re.I), None,
     "Apache version detected"),
    # nginx
    (re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)", re.I), None,
     "nginx version detected"),
    # ProFTPD
    (re.compile(r"proftpd[^\d]*(\d+)\.(\d+)\.(\d+)", re.I), None,
     "ProFTPD version detected"),
    # vsftpd 2.3.4 (backdoor)
    (re.compile(r"vsftpd\s*2\.3\.4", re.I), 2.5,
     "vsftpd 2.3.4 detected — contains a well-known backdoor (CVE-2011-2523)"),
    # vsftpd any version
    (re.compile(r"vsftpd[^\d]*(\d+)\.(\d+)", re.I), None,
     "vsftpd version detected"),
    # Microsoft IIS
    (re.compile(r"microsoft-iis/(\d+)\.(\d+)", re.I), None,
     "IIS version detected"),
    # Exim
    (re.compile(r"exim\s+(\d+)\.(\d+)", re.I), None,
     "Exim SMTP version detected"),
    # Postfix
    (re.compile(r"postfix", re.I), 0.0,
     "Postfix SMTP detected"),
    # Anonymous FTP hints
    (re.compile(r"anonymous", re.I), 1.5,
     "Anonymous FTP access appears enabled — unauthenticated file access possible"),
    # Telnet cleartext warnings
    (re.compile(r"telnet", re.I), 1.0,
     "Telnet session data is transmitted in cleartext"),
    # Redis without auth
    (re.compile(r"\+PONG", re.I), 2.0,
     "Redis responded to PING without authentication — unauthenticated access confirmed"),
    # MongoDB without auth
    (re.compile(r"mongodb", re.I), 1.0,
     "MongoDB banner detected"),
    # Elasticsearch
    (re.compile(r'"cluster_name"|"tagline"\s*:', re.I), 1.5,
     "Elasticsearch API responded without authentication"),
    # SMB / NetBIOS
    (re.compile(r"smb|cifs", re.I), 1.5,
     "SMB/CIFS service confirmed — keep patched against EternalBlue-class exploits"),
    # Docker API
    (re.compile(r'"ApiVersion"|docker.*api', re.I), 2.5,
     "Docker Remote API detected — unauthenticated container/host control possible"),
    # VNC
    (re.compile(r"RFB \d+\.\d+", re.I), 1.0,
     "VNC RFB protocol confirmed — verify strong password and tunnel via SSH"),
    # RDP/NTLM
    (re.compile(r"NTLMSSP|rdp", re.I), 0.5,
     "RDP/NTLM handshake detected"),
    # SSL/TLS version weak hints (caught separately by TLS probe)
    (re.compile(r"SSLv2|SSLv3", re.I), 2.0,
     "Obsolete SSL version advertised — vulnerable to POODLE/DROWN attacks"),
]

# Version cut-offs: service → (major, minor) below which score is raised
_OLD_VERSION_PENALTIES = {
    "openssh": ((7, 4), 1.5, "OpenSSH < 7.4 has known vulnerabilities; upgrade to latest"),
    "apache":  ((2, 4), 2.0, "Apache < 2.4 is EOL with many unpatched CVEs; upgrade immediately"),
    "nginx":   ((1, 18), 1.0, "nginx < 1.18 may be missing security patches; upgrade"),
    "iis":     ((10, 0), 1.5, "IIS < 10 is outdated and may lack security features"),
    "exim":    ((4, 94), 1.5, "Exim < 4.94 has critical RCE vulnerabilities (21Nails)"),
    "proftpd": ((1, 3), 1.0, "ProFTPD < 1.3 has known remote code execution paths"),
    "vsftpd":  ((3, 0), 0.5, "vsftpd < 3.0 is outdated; consider upgrading"),
}

# Protocol-specific probe payloads: port → bytes to send (or None for banner-only)
_PROBES = {
    21:    b"",                                    # FTP sends banner on connect
    22:    b"",                                    # SSH sends banner on connect
    23:    b"",                                    # Telnet sends banner on connect
    25:    b"EHLO probe\r\n",                      # SMTP
    80:    b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n",
    110:   b"",                                    # POP3 sends banner
    143:   b"",                                    # IMAP sends banner
    443:   None,                                   # TLS-wrapped; special handling
    587:   b"EHLO probe\r\n",
    993:   None,                                   # IMAPS – TLS
    995:   None,                                   # POP3S – TLS
    1433:  b"",
    3306:  b"",                                    # MySQL sends handshake
    3389:  b"",                                    # RDP
    5432:  b"",
    5900:  b"",                                    # VNC sends RFB banner
    6379:  b"PING\r\n",                            # Redis
    8080:  b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n",
    8443:  None,
    9200:  b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",  # Elasticsearch
    27017: b"",                                   # MongoDB
}


def _grab_banner_raw(ip, port, timeout):
    """Open a fresh connection, optionally send a probe, and return raw bytes."""
    probe = _PROBES.get(port, b"")  # default: just read the banner
    recv_timeout = min(2.0, timeout + 0.5)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(recv_timeout)
            if probe:  # None means TLS-wrapped; handled separately
                sock.sendall(probe)
            chunks = []
            try:
                while True:
                    chunk = sock.recv(512)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(c) for c in chunks) >= 2048:
                        break
            except (socket.timeout, OSError):
                pass
            return b"".join(chunks)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return b""


def _grab_tls_banner(ip, port, timeout):
    """Wrap connection in TLS and return (decoded_banner, tls_version, cert_info)."""
    recv_timeout = min(2.0, timeout + 0.5)
    tls_version = None
    cert_info = {}
    banner = ""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Also try to get the negotiated TLS version
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(recv_timeout)
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                tls_version = tls.version()  # e.g. 'TLSv1.2'
                cert = tls.getpeercert()
                if cert:
                    cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    cert_info["not_after"] = cert.get("notAfter", "")
                # Try to get HTTP banner
                try:
                    tls.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                    data = b""
                    while True:
                        chunk = tls.recv(512)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) >= 2048:
                            break
                except (socket.timeout, OSError):
                    pass
                banner = data.decode(errors="ignore").strip()
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        pass
    return banner, tls_version, cert_info


def _score_to_level(score):
    """Convert a numeric score (0-10) into a risk level label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 2.0:
        return "LOW"
    return "INFO"


def dynamic_risk_probe(ip, port, timeout):
    """Probe an open port with protocol-specific packets and return a rich dict.

    Returns:
        {
          'banner': str,          # first line of the raw response
          'full_banner': str,     # multi-line / full decoded response
          'risk': str,            # CRITICAL / HIGH / MEDIUM / LOW / INFO
          'score': float,         # 0.0 – 10.0
          'evidence': [str],      # human-readable findings driving the score
          'recommendation': str,  # actionable remediation text
          'service': str,
          'tls_version': str|None,
        }
    """
    base_info = PORT_SECURITY.get(port)
    base_score = base_info["score"] if base_info else (5.0 if port < 1024 else 2.0)
    base_rec = (
        base_info["recommendation"]
        if base_info
        else (
            "Privileged system port. Verify necessity and restrict access."
            if port < 1024
            else "Non-standard port. Adhere to least privilege and keep software updated."
        )
    )
    service_name = base_info["service"] if base_info else SERVICES.get(port, "unknown")

    evidence = []
    score_delta = 0.0
    tls_version = None
    full_banner = ""

    # --- TLS-wrapped ports ---
    is_tls_port = _PROBES.get(port) is None
    if is_tls_port:
        full_banner, tls_version, cert_info = _grab_tls_banner(ip, port, timeout)
        if tls_version:
            weak_tls = tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")
            if weak_tls:
                score_delta += 2.0
                evidence.append(
                    f"Weak TLS version negotiated: {tls_version} — vulnerable to known downgrade attacks"
                )
            else:
                evidence.append(f"TLS version: {tls_version} (acceptable)")
            # Check certificate expiry
            not_after = cert_info.get("not_after", "")
            if not_after:
                try:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        score_delta += 2.0
                        evidence.append(f"TLS certificate EXPIRED {abs(days_left)} day(s) ago")
                    elif days_left < 30:
                        score_delta += 1.0
                        evidence.append(f"TLS certificate expires in {days_left} day(s) — renew soon")
                    else:
                        evidence.append(f"TLS certificate valid for {days_left} more day(s)")
                except ValueError:
                    pass
        else:
            score_delta += 1.0
            evidence.append("TLS handshake failed — service may be using plain text on an encrypted port")
    else:
        # --- Plain-text probe ---
        raw = _grab_banner_raw(ip, port, timeout)
        full_banner = raw.decode(errors="ignore").strip()

    banner_line = full_banner.splitlines()[0] if full_banner else ""

    # --- Pattern matching against the full banner ---
    for pattern, penalty, note in _VULN_PATTERNS:
        m = pattern.search(full_banner)
        if not m:
            continue
        # Version-aware patterns (penalty is None → look up _OLD_VERSION_PENALTIES)
        if penalty is None:
            # Try to extract major.minor from match groups
            try:
                major = int(m.group(1))
                minor = int(m.group(2)) if len(m.groups()) >= 2 else 0
            except (IndexError, ValueError):
                continue
            # Determine service key from the pattern note
            svc_key = None
            for k in _OLD_VERSION_PENALTIES:
                if k in note.lower():
                    svc_key = k
                    break
            if svc_key:
                cutoff_major, cutoff_minor = _OLD_VERSION_PENALTIES[svc_key][0]
                pen, old_note = _OLD_VERSION_PENALTIES[svc_key][1], _OLD_VERSION_PENALTIES[svc_key][2]
                if (major, minor) < (cutoff_major, cutoff_minor):
                    score_delta += pen
                    evidence.append(
                        f"{note}: {major}.{minor} — {old_note}"
                    )
                else:
                    evidence.append(f"{note}: {major}.{minor} (up-to-date)")
            else:
                evidence.append(f"{note}: {m.group(0)}")
        else:
            score_delta += penalty
            evidence.append(note)

    # Default evidence if nothing matched
    if not evidence:
        if full_banner:
            evidence.append(f"Service responded. Banner: {banner_line[:120]}")
        else:
            evidence.append("Port is open but service did not return a detectable banner.")

    final_score = min(10.0, round(base_score + score_delta, 1))
    risk_level = _score_to_level(final_score)

    return {
        "banner": banner_line,
        "full_banner": full_banner,
        "service": service_name,
        "risk": risk_level,
        "score": final_score,
        "evidence": evidence,
        "recommendation": base_rec,
        "tls_version": tls_version,
    }


def assess_port(port, service_name=None):
    """Return static security metadata for a port (used as a baseline)."""
    info = PORT_SECURITY.get(port)
    if info:
        svc = service_name or info.get("service") or SERVICES.get(port, "unknown")
        return {
            "port": port,
            "service": svc,
            "risk": info["risk"],
            "score": info["score"],
            "recommendation": info["recommendation"],
        }
    svc = service_name or SERVICES.get(port, "unknown")
    if port < 1024:
        return {
            "port": port,
            "service": svc,
            "risk": "MEDIUM",
            "score": 5.0,
            "recommendation": "Privileged system port. Verify necessity of this service and configure restrictive firewall rules.",
        }
    return {
        "port": port,
        "service": svc,
        "risk": "LOW",
        "score": 2.0,
        "recommendation": "Standard service port. Adhere to principle of least privilege and keep software updated.",
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


def parse_targets(target_spec):
    """Turn a target string (hostname, IP, or CIDR range) into [(display_name, ip_str), ...].

    Supports:
        - Single hostname: 'scanme.nmap.org', 'localhost'
        - Single IP: '127.0.0.1', '192.168.1.1'
        - CIDR notation: '192.168.1.0/24', '10.0.0.0/29'
    """
    target_spec = target_spec.strip()
    if not target_spec:
        raise ValueError("Target cannot be empty")

    if "/" in target_spec:
        try:
            network = ipaddress.ip_network(target_spec, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR notation '{target_spec}': {exc}")

        # Limit to prevent runaway socket allocations
        if network.num_addresses > 1024:
            raise ValueError(
                f"Subnet '{target_spec}' contains {network.num_addresses} addresses. "
                "Safety limit is 1024 addresses (e.g., /22 or smaller)."
            )

        hosts = list(network.hosts())
        if not hosts:
            hosts = [network.network_address]
        return [(str(ip), str(ip)) for ip in hosts]

    try:
        ip = socket.gethostbyname(target_spec)
        return [(target_spec, ip)]
    except socket.gaierror:
        raise ValueError(f"Could not resolve host '{target_spec}'")


def scan_port(host, port, timeout, cancel_event=None, mode="connect", engine=None):
    """Return (port, banner) if the port is open, otherwise None.

    Connect mode finishes the TCP handshake and reads a short banner.
    Stealth mode sends SYN and leaves the handshake unfinished, so the
    banner is empty. Pass the engine from scan_host or scan_all_targets.
    """
    if cancel_event is not None and cancel_event.is_set():
        return None
    if normalize_mode(mode) == MODE_STEALTH:
        if engine is None:
            raise StealthError("Use scan_host or scan_all_targets for stealth mode.")
        if engine.probe(host, port, timeout, cancel_event):
            return port, ""
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(min(1.0, timeout))
                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(100).decode(errors="ignore").strip()
                banner = data.splitlines()[0] if data else ""
            except (socket.timeout, OSError):
                pass
            return port, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_target_port(host, ip, port, timeout, cancel_event=None, mode="connect", engine=None):
    """Worker task returning enriched result dictionary if port is open."""
    if cancel_event is not None and cancel_event.is_set():
        return None
    res = scan_port(ip, port, timeout, cancel_event, mode, engine)
    if res:
        port_num, _quick_banner = res
        # Run dynamic risk probe for a real, evidence-backed risk assessment
        probe = dynamic_risk_probe(ip, port_num, timeout)
        return {
            "host": host,
            "ip": ip,
            "port": port_num,
            "service": probe["service"],
            "banner": probe["banner"],
            "full_banner": probe["full_banner"],
            "risk": probe["risk"],
            "score": probe["score"],
            "evidence": probe["evidence"],
            "recommendation": probe["recommendation"],
            "tls_version": probe["tls_version"],
        }
    return None


def scan_host(ip, ports, timeout, threads, on_result=None, cancel_event=None, mode="connect"):
    """Scan TCP ports on a single IP address (backwards compatible).

    Returns list of (port, banner) tuples for open ports.
    mode is 'connect' (three-way handshake) or 'stealth' (SYN only).
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
        with open_engine(mode) as (mode, engine):
            pending = {
                pool.submit(scan_port, ip, port, timeout, cancel_event, mode, engine)
                for port in ports
            }
            while pending:
                try:
                    done, pending = wait(pending, timeout=0.15, return_when=FIRST_COMPLETED)
                except KeyboardInterrupt:
                    cancelled = True
                    if cancel_event is not None:
                        cancel_event.set()
                    for fut in pending:
                        fut.cancel()
                    try:
                        pool.shutdown(wait=False, cancel_futures=True)
                    except TypeError:
                        pool.shutdown(wait=False)
                    raise

                for fut in done:
                    checked += 1
                    try:
                        result = fut.result()
                    except StealthError:
                        cancelled = True
                        if cancel_event is not None:
                            cancel_event.set()
                        raise
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
        try:
            pool.shutdown(wait=not cancelled, cancel_futures=cancelled)
        except TypeError:
            pool.shutdown(wait=not cancelled)

    open_ports.sort()
    return open_ports


def scan_all_targets(targets, ports, timeout, threads, on_result=None, cancel_event=None, mode="connect"):
    """Scan ports across multiple (host, ip) targets with full risk enrichment.

    mode is 'connect' for a full three-way handshake, or 'stealth' for SYN only.
    """
    if threads < 1:
        raise ValueError("threads must be at least 1")

    tasks = [(host, ip, port) for host, ip in targets for port in ports]
    total = len(tasks)
    results = []
    if total == 0:
        return results

    checked = 0
    pool = ThreadPoolExecutor(max_workers=min(threads, total))
    cancelled = False
    try:
        with open_engine(mode) as (mode, engine):
            pending = {
                pool.submit(
                    scan_target_port, host, ip, port, timeout, cancel_event, mode, engine
                )
                for host, ip, port in tasks
            }
            while pending:
                try:
                    done, pending = wait(pending, timeout=0.15, return_when=FIRST_COMPLETED)
                except KeyboardInterrupt:
                    cancelled = True
                    if cancel_event is not None:
                        cancel_event.set()
                    for fut in pending:
                        fut.cancel()
                    try:
                        pool.shutdown(wait=False, cancel_futures=True)
                    except TypeError:
                        pool.shutdown(wait=False)
                    raise

                for fut in done:
                    checked += 1
                    try:
                        res = fut.result()
                    except StealthError:
                        cancelled = True
                        if cancel_event is not None:
                            cancel_event.set()
                        raise
                    except Exception:
                        res = None
                    if res:
                        results.append(res)
                    if on_result:
                        on_result(checked, total, res)
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
    finally:
        try:
            pool.shutdown(wait=not cancelled, cancel_futures=cancelled)
        except TypeError:
            pool.shutdown(wait=not cancelled)

    results.sort(key=lambda x: (x["ip"], x["port"]))
    return results


def compute_risk_summary(results):
    """Compute risk metrics and overall severity for a set of findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    max_score = 0.0
    for r in results:
        risk = r.get("risk", "INFO").upper()
        counts[risk] = counts.get(risk, 0) + 1
        score = float(r.get("score", 0.0))
        if score > max_score:
            max_score = score

    if counts["CRITICAL"] > 0 or max_score >= 9.0:
        overall_level = "CRITICAL"
    elif counts["HIGH"] > 0 or max_score >= 7.0:
        overall_level = "HIGH"
    elif counts["MEDIUM"] > 0 or max_score >= 4.0:
        overall_level = "MEDIUM"
    elif counts["LOW"] > 0 or max_score >= 2.0:
        overall_level = "LOW"
    else:
        overall_level = "INFO" if results else "SAFE"

    return {
        "overall_level": overall_level,
        "max_score": round(max_score, 1),
        "breakdown": counts,
    }


def export_results(filepath, format_type, scan_meta, results):
    """Export scan results to disk as JSON or CSV."""
    fmt = format_type.lower()
    if fmt == "auto":
        ext = os.path.splitext(filepath)[1].lower()
        fmt = "csv" if ext == ".csv" else "json"

    parent = os.path.dirname(filepath)
    if parent:
        os.makedirs(parent, exist_ok=True)

    if fmt == "csv":
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "host", "ip", "port", "service", "risk_level",
                "risk_score", "banner", "recommendation"
            ])
            for r in results:
                writer.writerow([
                    r.get("host", ""),
                    r.get("ip", ""),
                    r.get("port", ""),
                    r.get("service", ""),
                    r.get("risk", ""),
                    r.get("score", ""),
                    r.get("banner", ""),
                    r.get("recommendation", "")
                ])
    else:
        payload = {
            **scan_meta,
            "results": results,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)


def print_recommendations(results, use_color=True):
    """Print prioritized remediation advice for discovered sensitive services."""
    sorted_res = sorted(results, key=lambda x: x.get("score", 0.0), reverse=True)
    if not sorted_res:
        return

    print("\n" + colorize("SECURITY RECOMMENDATIONS & ADVISORIES", Colors.BOLD, use_color))
    print(colorize("-" * 72, Colors.DIM, use_color))

    seen = set()
    for r in sorted_res:
        key = (r["port"], r["service"])
        if key in seen:
            continue
        seen.add(key)

        risk = r.get("risk", "INFO")
        score = r.get("score", 0.0)
        rec = r.get("recommendation", "")

        color = Colors.CYAN
        if risk == "CRITICAL":
            color = Colors.RED + Colors.BOLD
        elif risk == "HIGH":
            color = Colors.RED
        elif risk == "MEDIUM":
            color = Colors.YELLOW

        risk_badge = colorize(f"[{risk} - Score: {score}/10]", color, use_color)
        port_label = colorize(f"Port {r['port']}/TCP ({r['service']})", Colors.BOLD, use_color)
        print(f" • {port_label} {risk_badge}")
        print(f"   {rec}\n")


def main():
    parser = argparse.ArgumentParser(
        description="High-performance multithreaded TCP port scanner with risk scoring and file export."
    )
    parser.add_argument("host", metavar="TARGET",
                        help="Target IP, hostname, or CIDR network range (e.g. 192.168.1.0/28)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="ports to scan, e.g. 1-1024 or 22,80,443 (default 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="number of worker threads (default 100)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="seconds to wait per port (default 0.5)")
    parser.add_argument("--mode", choices=("connect", "stealth"), default="connect",
                        help="connect completes the TCP three-way handshake (default); "
                             "stealth sends SYN and does not finish the handshake (needs root)")
    parser.add_argument("-o", "--output", default=None,
                        help="save scan report to disk (supports .json or .csv)")
    parser.add_argument("-f", "--format", choices=["auto", "json", "csv"], default="auto",
                        help="report format when saving with -o (default: auto)")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI color output in terminal")
    args = parser.parse_args()

    use_color = sys.stdout.isatty() and not args.no_color

    try:
        targets = parse_targets(args.host)
    except ValueError as exc:
        print(colorize(f"Target error: {exc}", Colors.RED, use_color))
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(colorize("Ports must look like 1-1024 or 22,80,443", Colors.RED, use_color))
        sys.exit(1)
    if not ports:
        print(colorize("No valid ports to scan", Colors.RED, use_color))
        sys.exit(1)

    is_multi_host = len(targets) > 1
    total_checks = len(targets) * len(ports)
    try:
        scan_mode = normalize_mode(args.mode)
    except ValueError as exc:
        print(colorize(str(exc), Colors.RED, use_color))
        sys.exit(1)
    if scan_mode == MODE_STEALTH:
        ready, reason = stealth_available()
        if not ready:
            print(colorize(reason, Colors.RED, use_color))
            sys.exit(1)
    how = mode_label(scan_mode)

    if is_multi_host:
        print(colorize(
            f"Scanning subnet {args.host} ({len(targets)} hosts, {len(ports)} ports each, "
            f"{total_checks} total checks, {how})...",
            Colors.BOLD, use_color
        ))
    else:
        label, ip = targets[0]
        print(colorize(
            f"Scanning {label} ({ip}), {len(ports)} ports, {how}...",
            Colors.BOLD, use_color
        ))

    cancel_event = threading.Event()
    interrupted = False
    start_time = time.time()
    open_results = []

    try:
        open_results = scan_all_targets(
            targets, ports, args.timeout, args.threads,
            cancel_event=cancel_event, mode=scan_mode,
        )
    except StealthError as exc:
        print(colorize(str(exc), Colors.RED, use_color))
        sys.exit(1)
    except KeyboardInterrupt:
        interrupted = True
        cancel_event.set()
        print("\n\n" + colorize("[!] Scan interrupted by user (Ctrl+C). Halting cleanly...", Colors.YELLOW, use_color))

    elapsed = round(time.time() - start_time, 2)
    risk_summary = compute_risk_summary(open_results)

    # Print Table
    print("\n" + colorize("PORT SCAN RESULTS", Colors.BOLD, use_color))
    if is_multi_host:
        header = f"{'HOST':<16} {'PORT':<8} {'SERVICE':<14} {'RISK':<10} BANNER"
        print(colorize(header, Colors.DIM, use_color))
        print(colorize("-" * 72, Colors.DIM, use_color))
        for r in open_results:
            risk = r["risk"]
            color = Colors.WHITE
            if risk == "CRITICAL":
                color = Colors.RED + Colors.BOLD
            elif risk == "HIGH":
                color = Colors.RED
            elif risk == "MEDIUM":
                color = Colors.YELLOW
            elif risk == "LOW":
                color = Colors.CYAN
            risk_str = colorize(f"{risk:<10}", color, use_color)
            banner_str = r["banner"] if r["banner"] else "—"
            print(f"{r['ip']:<16} {r['port']:<8} {r['service']:<14} {risk_str} {banner_str}")
    else:
        header = f"{'PORT':<8} {'SERVICE':<14} {'RISK':<10} BANNER"
        print(colorize(header, Colors.DIM, use_color))
        print(colorize("-" * 60, Colors.DIM, use_color))
        for r in open_results:
            risk = r["risk"]
            color = Colors.WHITE
            if risk == "CRITICAL":
                color = Colors.RED + Colors.BOLD
            elif risk == "HIGH":
                color = Colors.RED
            elif risk == "MEDIUM":
                color = Colors.YELLOW
            elif risk == "LOW":
                color = Colors.CYAN
            risk_str = colorize(f"{risk:<10}", color, use_color)
            banner_str = r["banner"] if r["banner"] else "—"
            print(f"{r['port']:<8} {r['service']:<14} {risk_str} {banner_str}")

    # Print Recommendations if open ports were found
    if open_results:
        print_recommendations(open_results, use_color)

    # Assessment summary
    status_label = "Interrupted" if interrupted else "Completed"
    print(colorize(f"Scan Status: {status_label}", Colors.BOLD, use_color))
    print(f"Mode: {how}")
    print(f"Elapsed Time: {elapsed:.2f}s | Open Ports: {len(open_results)} found across {len(targets)} host(s)")

    if open_results:
        bd = risk_summary["breakdown"]
        bd_str = f"Critical: {bd['CRITICAL']}, High: {bd['HIGH']}, Medium: {bd['MEDIUM']}, Low: {bd['LOW']}, Info: {bd['INFO']}"
        sev_color = Colors.GREEN
        if risk_summary["overall_level"] == "CRITICAL":
            sev_color = Colors.RED + Colors.BOLD
        elif risk_summary["overall_level"] == "HIGH":
            sev_color = Colors.RED
        elif risk_summary["overall_level"] == "MEDIUM":
            sev_color = Colors.YELLOW
        print(colorize(f"Risk Rating: {risk_summary['overall_level']} (Max Score: {risk_summary['max_score']}/10)", sev_color, use_color))
        print(f"Risk Breakdown: {bd_str}")

    # File Export
    if args.output:
        scan_meta = {
            "scanner": "Network Port Scanner",
            "version": "2.0",
            "scan_mode": scan_mode,
            "target": args.host,
            "hosts_count": len(targets),
            "ports_scanned_count": len(ports),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "interrupted": interrupted,
            "risk_summary": risk_summary,
            "total_open_ports": len(open_results),
        }
        try:
            export_results(args.output, args.format, scan_meta, open_results)
            print(colorize(f"\n[+] Scan report successfully exported to: {args.output}", Colors.GREEN, use_color))
        except Exception as exc:
            print(colorize(f"\n[-] Failed to export results to '{args.output}': {exc}", Colors.RED, use_color))

    if interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()