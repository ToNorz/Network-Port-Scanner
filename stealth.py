#!/usr/bin/env python3
"""Half-open SYN scans for the port scanner.

Stealth mode sends a SYN and answers SYN-ACK with RST, so the TCP
three-way handshake never completes and no banner is read. The normal
connect scan lives in scanner.py.

Sending these packets needs root (a BPF device on macOS, or a packet
socket on Linux). Only scan hosts you own or have permission to test.
"""

import contextlib
import errno
import fcntl
import ipaddress
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

MODE_CONNECT = "connect"
MODE_STEALTH = "stealth"

STEALTH_ROOT_REASON = (
    "Stealth mode sends raw SYN packets and needs to run as root. "
    "Start the scanner with sudo, or choose the normal three-way handshake."
)

TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12

# Darwin BPF ioctls from <net/bpf.h>. Buffer length must be set before BIOCSETIF.
BIOCSBLEN = 0xC0044266
BIOCGBLEN = 0x40044266
BIOCGDLT = 0x4004426A
BIOCSETIF = 0x8020426C
BIOCIMMEDIATE = 0x80044270
BIOCSHDRCMPLT = 0x80044275
BIOCSSEESENT = 0x80044277

_MODE_ALIASES = {
    "connect": MODE_CONNECT,
    "normal": MODE_CONNECT,
    "handshake": MODE_CONNECT,
    "full": MODE_CONNECT,
    "stealth": MODE_STEALTH,
    "syn": MODE_STEALTH,
    "half-open": MODE_STEALTH,
    "halfopen": MODE_STEALTH,
}

_ARP_RE = re.compile(r"\bat\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b")


class StealthError(RuntimeError):
    """Stealth mode could not send or receive SYN packets."""


def normalize_mode(mode):
    """Return 'connect' or 'stealth'. None and '' mean connect."""
    if mode is None or mode == "":
        return MODE_CONNECT
    if not isinstance(mode, str):
        raise ValueError("Scan mode must be 'connect' or 'stealth'.")
    key = mode.strip().lower()
    try:
        return _MODE_ALIASES[key]
    except KeyError:
        raise ValueError("Scan mode must be 'connect' or 'stealth'.")


def mode_label(mode):
    if normalize_mode(mode) == MODE_STEALTH:
        return "stealth SYN"
    return "three-way handshake"


def stealth_available():
    """Return (ok, reason). Reason is empty when stealth mode can run."""
    if sys.platform == "darwin":
        return _darwin_available()
    if sys.platform.startswith("linux"):
        return _linux_available()
    return False, f"Stealth mode is not available on {sys.platform}."


def internet_checksum(data):
    """One's-complement checksum used by IPv4 and TCP."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) + data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_tcp_segment(src_ip, dst_ip, sport, dport, seq, ack, flags, window=65535):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(header),
    )
    checksum = internet_checksum(pseudo + header)
    return struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, checksum, 0
    )


def build_ipv4(src_ip, dst_ip, payload, ident, ttl=64):
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        ident & 0xFFFF,
        0x4000,
        ttl,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    checksum = internet_checksum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        ident & 0xFFFF,
        0x4000,
        ttl,
        socket.IPPROTO_TCP,
        checksum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    ) + payload


def link_frame(dlt, src_mac, dst_mac, ip_packet):
    """Wrap an IPv4 packet for the capture device's link type."""
    if dlt == DLT_NULL:
        return struct.pack("<I", socket.AF_INET) + ip_packet
    if dlt == DLT_RAW:
        return ip_packet
    if dlt == DLT_EN10MB:
        if not src_mac or not dst_mac:
            raise StealthError("Stealth mode is missing a hardware address for this network.")
        frame = struct.pack("!6s6sH", dst_mac, src_mac, 0x0800) + ip_packet
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        return frame
    raise StealthError(f"Stealth mode does not support link type {dlt}.")


def arp_request_frame(src_mac, src_ip, target_ip):
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        1,
        src_mac,
        socket.inet_aton(src_ip),
        b"\x00" * 6,
        socket.inet_aton(target_ip),
    )
    frame = struct.pack("!6s6sH", b"\xff" * 6, src_mac, 0x0806) + arp
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def parse_captured_frame(frame, dlt):
    """Return ('tcp', segment) or ('arp', ip, mac), or None."""
    if dlt == DLT_NULL:
        if len(frame) < 4:
            return None
        family = struct.unpack_from("<I", frame, 0)[0]
        if family != socket.AF_INET and struct.unpack_from(">I", frame, 0)[0] != socket.AF_INET:
            return None
        return _parse_ipv4(frame[4:])
    if dlt == DLT_RAW:
        return _parse_ipv4(frame)
    if dlt != DLT_EN10MB or len(frame) < 14:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    payload = frame[14:]
    if ether_type == 0x8100 and len(frame) >= 18:
        ether_type = struct.unpack_from("!H", frame, 16)[0]
        payload = frame[18:]
    if ether_type == 0x0806:
        return _parse_arp(payload)
    if ether_type == 0x0800:
        return _parse_ipv4(payload)
    return None


class _Segment:
    def __init__(self, src_ip, dst_ip, sport, dport, seq, ack, flags):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags


class _Route:
    def __init__(self, iface, src_ip, src_mac, dst_mac, dlt, capture):
        self.iface = iface
        self.src_ip = src_ip
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.dlt = dlt
        self.capture = capture


class _Capture:
    def __init__(self, fd, dlt, buf_len):
        self.fd = fd
        self.dlt = dlt
        self.buf_len = buf_len
        self._lock = threading.Lock()

    def fileno(self):
        return self.fd

    def send(self, frame):
        with self._lock:
            if self.fd is None:
                return False
            try:
                written = os.write(self.fd, frame)
            except OSError as exc:
                if exc.errno in (errno.EBADF, errno.EPIPE):
                    return False
                raise StealthError(f"Could not send a packet: {exc}") from exc
        if written != len(frame):
            raise StealthError("The packet device accepted only part of a SYN packet.")
        return True

    def recv_frames(self):
        try:
            data = os.read(self.fd, self.buf_len or 65536)
        except BlockingIOError:
            return []
        except OSError as exc:
            if exc.errno in (errno.EBADF, errno.EINTR):
                return []
            raise
        if sys.platform == "darwin":
            return _unpack_bpf(data)
        if data:
            return [data]
        return []

    def close(self):
        with self._lock:
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None


class StealthEngine:
    """One shared capture for every probe in a scan."""

    def __init__(self):
        self._lock = threading.Lock()
        self._resolve_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._closed = False
        self._fatal = None
        self._captures = {}
        self._pending = {}
        self._routes = {}
        self._mac_cache = {}
        self._arp_wait = {}
        self._free_ports = list(range(32768, 61000))
        self._ip_id = int.from_bytes(os.urandom(2), "big") or 1
        self._interfaces = None
        self._wake_r = None
        self._wake_w = None

    def start(self):
        if self._thread is not None:
            return
        self._stop.clear()
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        os.set_blocking(self._wake_w, False)
        self._thread = threading.Thread(target=self._loop, name="stealth-recv", daemon=True)
        self._thread.start()

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        self._wake_all()
        self._notify()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.5)
        with self._lock:
            captures = list(self._captures.values())
            self._captures.clear()
        for capture in captures:
            capture.close()
        for fd in (self._wake_r, self._wake_w):
            if fd is None:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
        self._wake_r = None
        self._wake_w = None

    def _notify(self):
        if self._wake_w is None:
            return
        try:
            os.write(self._wake_w, b"\x00")
        except OSError:
            pass

    def _drain_wake(self):
        if self._wake_r is None:
            return
        try:
            while os.read(self._wake_r, 256):
                pass
        except OSError:
            pass

    def probe(self, ip, port, timeout, cancel_event=None):
        """Return True when the port answers SYN-ACK. Closed and silent ports return False."""
        if self._stop.is_set() or (cancel_event is not None and cancel_event.is_set()):
            return False
        self._raise_if_fatal()
        route = self._route_for(ip, cancel_event)
        if self._stop.is_set() or (cancel_event is not None and cancel_event.is_set()):
            return False

        src_port = self._alloc_port()
        seq = int.from_bytes(os.urandom(4), "big")
        key = (ip, port, src_port)
        slot = {
            "event": threading.Event(),
            "state": None,
            "seq": seq,
            "route": route,
            "dst_ip": ip,
            "dst_port": port,
            "src_port": src_port,
        }
        try:
            with self._lock:
                self._pending[key] = slot
            self._send_tcp(route, ip, port, src_port, seq, 0, TCP_SYN, 65535)
            deadline = time.monotonic() + max(0.05, float(timeout))
            sent_retry = False
            while True:
                if self._stop.is_set() or (cancel_event is not None and cancel_event.is_set()):
                    return False
                self._raise_if_fatal()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return slot["state"] == "open"
                if slot["event"].wait(min(0.15, remaining)):
                    return slot["state"] == "open"
                # A second SYN is still half-open. It covers a single lost probe.
                if not sent_retry and (deadline - time.monotonic()) > 0.2:
                    sent_retry = True
                    self._send_tcp(route, ip, port, src_port, seq, 0, TCP_SYN, 65535)
        finally:
            with self._lock:
                self._pending.pop(key, None)
            self._release_port(src_port)

    def _raise_if_fatal(self):
        if self._fatal is not None:
            raise StealthError(str(self._fatal))

    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                captures = [cap for cap in self._captures.values() if cap.fd is not None]
            watch = list(captures)
            if self._wake_r is not None:
                watch.append(self._wake_r)
            if not watch:
                self._stop.wait(0.05)
                continue
            try:
                readable, _, _ = select.select(watch, [], [], 0.5)
            except (OSError, ValueError):
                continue
            if self._wake_r in readable:
                self._drain_wake()
            for capture in readable:
                if capture is self._wake_r or getattr(capture, "fd", None) is None:
                    continue
                try:
                    frames = capture.recv_frames()
                except OSError as exc:
                    self._fatal = exc
                    self._wake_all()
                    return
                for frame in frames:
                    try:
                        parsed = parse_captured_frame(frame, capture.dlt)
                    except Exception:
                        continue
                    if parsed is None:
                        continue
                    kind = parsed[0]
                    if kind == "tcp":
                        self._handle_tcp(parsed[1])
                    elif kind == "arp":
                        self._handle_arp(parsed[1], parsed[2])

    def _handle_tcp(self, segment):
        key = (segment.src_ip, segment.sport, segment.dport)
        rst_slot = None
        their_seq = segment.seq
        their_ack = segment.ack
        with self._lock:
            slot = self._pending.get(key)
            if slot is None or slot["state"] is not None:
                return
            expected = (slot["seq"] + 1) & 0xFFFFFFFF
            if segment.flags & TCP_RST:
                if segment.ack not in (0, expected):
                    return
                slot["state"] = "closed"
                slot["event"].set()
                return
            if (segment.flags & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK):
                return
            if segment.ack != expected:
                return
            slot["state"] = "open"
            slot["event"].set()
            rst_slot = slot
        if rst_slot is not None:
            # RST finishes our side without the final ACK of the handshake.
            try:
                self._send_tcp(
                    rst_slot["route"],
                    rst_slot["dst_ip"],
                    rst_slot["dst_port"],
                    rst_slot["src_port"],
                    their_ack,
                    (their_seq + 1) & 0xFFFFFFFF,
                    TCP_RST | TCP_ACK,
                    0,
                )
            except StealthError as exc:
                self._fatal = exc
                self._wake_all()

    def _handle_arp(self, sender_ip, sender_mac):
        with self._lock:
            waiter = self._arp_wait.get(sender_ip)
            if waiter is None:
                return
            waiter["mac"] = sender_mac
            waiter["event"].set()

    def _wake_all(self):
        with self._lock:
            for slot in self._pending.values():
                slot["event"].set()
            for waiter in self._arp_wait.values():
                waiter["event"].set()

    def _alloc_port(self):
        with self._lock:
            if not self._free_ports:
                raise StealthError("Too many stealth probes are in flight.")
            return self._free_ports.pop()

    def _release_port(self, port):
        with self._lock:
            self._free_ports.append(port)

    def _next_ip_id(self):
        with self._lock:
            self._ip_id = (self._ip_id + 1) & 0xFFFF or 1
            return self._ip_id

    def _send_tcp(self, route, dst_ip, dst_port, src_port, seq, ack, flags, window):
        segment = build_tcp_segment(
            route.src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window
        )
        packet = build_ipv4(route.src_ip, dst_ip, segment, self._next_ip_id())
        frame = link_frame(route.dlt, route.src_mac, route.dst_mac, packet)
        if not route.capture.send(frame):
            if self._stop.is_set():
                return
            raise StealthError("Could not send a SYN packet. The capture device is closed.")

    def _route_for(self, dst_ip, cancel_event):
        with self._lock:
            cached = self._routes.get(dst_ip)
        if cached is not None:
            return cached
        with self._resolve_lock:
            with self._lock:
                cached = self._routes.get(dst_ip)
            if cached is not None:
                return cached
            if self._stop.is_set() or (cancel_event is not None and cancel_event.is_set()):
                raise StealthError("Stealth scan stopped before the route was ready.")
            route = self._build_route(dst_ip, cancel_event)
            with self._lock:
                self._routes[dst_ip] = route
            return route

    def _build_route(self, dst_ip, cancel_event):
        interfaces = self._load_interfaces()
        if _is_loopback(dst_ip):
            iface = _loopback_name(interfaces)
            src_ip = "127.0.0.1"
            gateway = None
        else:
            iface, gateway, src_ip = _lookup_route(dst_ip)
            if not src_ip:
                src_ip = _source_ip(dst_ip)
            if not iface:
                iface = _iface_for_ip(src_ip, interfaces)
        if not iface:
            raise StealthError(f"Could not find a network interface for {dst_ip}.")
        info = interfaces.get(iface, {})
        capture = self._capture_for(iface)
        src_mac = info.get("mac")
        dst_mac = None
        if capture.dlt == DLT_EN10MB:
            if not src_mac:
                raise StealthError(f"Interface {iface} has no hardware address.")
            if _is_loopback(dst_ip) or dst_ip == src_ip or dst_ip in _local_ips(interfaces):
                dst_mac = src_mac
            else:
                next_hop = gateway or dst_ip
                dst_mac = self._mac_for(capture, src_mac, src_ip, next_hop, cancel_event)
        elif capture.dlt not in (DLT_NULL, DLT_RAW):
            raise StealthError(
                f"Stealth mode cannot send on {iface} (link type {capture.dlt}). "
                "Use the normal three-way handshake."
            )
        return _Route(iface, src_ip, src_mac, dst_mac, capture.dlt, capture)

    def _mac_for(self, capture, src_mac, src_ip, target_ip, cancel_event):
        with self._lock:
            cached = self._mac_cache.get(target_ip)
        if cached is not None:
            return cached
        cached = _arp_cache(target_ip)
        if cached is not None:
            with self._lock:
                self._mac_cache[target_ip] = cached
            return cached
        waiter = {"event": threading.Event(), "mac": None}
        with self._lock:
            self._arp_wait[target_ip] = waiter
        try:
            if not capture.send(arp_request_frame(src_mac, src_ip, target_ip)):
                raise StealthError("Could not send an ARP request for the stealth scan.")
            deadline = time.monotonic() + 1.5
            while waiter["mac"] is None:
                if self._stop.is_set() or (cancel_event is not None and cancel_event.is_set()):
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                waiter["event"].wait(min(0.15, remaining))
        finally:
            with self._lock:
                self._arp_wait.pop(target_ip, None)
        mac = waiter["mac"] or _arp_cache(target_ip)
        if mac is None:
            raise StealthError(
                f"Could not resolve the hardware address for {target_ip} on {capture_iface(capture)}. "
                "Use the normal three-way handshake if this host is not on the local network."
            )
        with self._lock:
            self._mac_cache[target_ip] = mac
        return mac

    def _capture_for(self, iface):
        with self._lock:
            existing = self._captures.get(iface)
        if existing is not None and existing.fd is not None:
            return existing
        opened = _open_capture(iface)
        with self._lock:
            current = self._captures.get(iface)
            if current is not None and current.fd is not None:
                opened.close()
                return current
            self._captures[iface] = opened
        self._notify()
        return opened

    def _load_interfaces(self):
        if self._interfaces is None:
            self._interfaces = list_interfaces()
        return self._interfaces


def capture_iface(capture):
    return getattr(capture, "iface", "the network")


@contextlib.contextmanager
def open_engine(mode):
    """Yield (mode, engine). Engine is None for a normal handshake scan."""
    mode = normalize_mode(mode)
    engine = None
    if mode == MODE_STEALTH:
        ok, reason = stealth_available()
        if not ok:
            raise StealthError(reason)
        engine = StealthEngine()
        engine.start()
    try:
        yield mode, engine
    finally:
        if engine is not None:
            engine.close()


def list_interfaces():
    """Return {iface: {'ips': set(str), 'mac': bytes|None}}."""
    if sys.platform == "darwin":
        return _darwin_interfaces()
    if sys.platform.startswith("linux"):
        return _linux_interfaces()
    return {}


def _parse_ipv4(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_len = (packet[0] & 0x0F) * 4
    if header_len < 20 or len(packet) < header_len:
        return None
    frag = struct.unpack_from("!H", packet, 6)[0]
    if frag & 0x3FFF:
        return None
    if packet[9] != socket.IPPROTO_TCP:
        return None
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    total = struct.unpack_from("!H", packet, 2)[0]
    if total < header_len:
        return None
    end = min(len(packet), total)
    return _parse_tcp(src_ip, dst_ip, packet[header_len:end])


def _parse_tcp(src_ip, dst_ip, segment):
    if len(segment) < 20:
        return None
    sport, dport, seq, ack, offset, flags = struct.unpack_from("!HHIIBB", segment)
    if (offset >> 4) * 4 < 20:
        return None
    return ("tcp", _Segment(src_ip, dst_ip, sport, dport, seq, ack, flags))


def _parse_arp(payload):
    if len(payload) < 28:
        return None
    htype, ptype, hlen, plen, oper = struct.unpack_from("!HHBBH", payload)
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4 or oper != 2:
        return None
    mac = payload[8:14]
    ip = socket.inet_ntoa(payload[14:18])
    return ("arp", ip, mac)


def _word_align(size):
    return (size + 3) & ~3


def _unpack_bpf(data):
    """Split one BPF read into link-layer frames.

    struct bpf_hdr on 64-bit macOS is timeval32 (8) + caplen + datalen + hdrlen.
    """
    frames = []
    offset = 0
    total = len(data)
    while offset + 20 <= total:
        caplen, _, hdrlen = struct.unpack_from("IIH", data, offset + 8)
        if hdrlen < 18 or hdrlen > 128 or offset + hdrlen > total:
            break
        take = min(caplen, total - (offset + hdrlen))
        frames.append(data[offset + hdrlen:offset + hdrlen + take])
        step = _word_align(hdrlen + caplen)
        if step <= 0:
            break
        offset += step
    return frames


def _darwin_available():
    last_error = None
    for index in range(256):
        path = f"/dev/bpf{index}"
        try:
            fd = os.open(path, os.O_RDWR)
        except PermissionError:
            return False, STEALTH_ROOT_REASON
        except FileNotFoundError:
            break
        except OSError as exc:
            last_error = exc
            if exc.errno == errno.EBUSY:
                continue
            if exc.errno == errno.EPERM:
                return False, STEALTH_ROOT_REASON
            continue
        else:
            os.close(fd)
            return True, ""
    if last_error is not None:
        return False, f"Stealth mode could not open a packet device: {last_error}"
    return False, "Stealth mode could not find a BPF packet device."


def _linux_available():
    if not hasattr(socket, "AF_PACKET"):
        return False, "Stealth mode needs a Linux packet socket."
    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        return False, STEALTH_ROOT_REASON
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            return False, STEALTH_ROOT_REASON
        return False, f"Stealth mode could not open a packet socket: {exc}"
    else:
        raw.close()
        return True, ""


def _open_capture(iface):
    if sys.platform == "darwin":
        fd, dlt, buf_len = _open_bpf(iface)
        capture = _Capture(fd, dlt, buf_len)
        capture.iface = iface
        return capture
    if sys.platform.startswith("linux"):
        return _open_linux(iface)
    raise StealthError(f"Stealth mode is not available on {sys.platform}.")


def _set_bpf_uint(fd, request, value):
    buf = bytearray(struct.pack("I", value))
    fcntl.ioctl(fd, request, buf, True)


def _open_bpf(iface):
    last_error = None
    fd = None
    for index in range(256):
        try:
            fd = os.open(f"/dev/bpf{index}", os.O_RDWR | os.O_NONBLOCK)
            break
        except PermissionError:
            raise StealthError(STEALTH_ROOT_REASON)
        except FileNotFoundError:
            fd = None
            break
        except OSError as exc:
            last_error = exc
            if exc.errno == errno.EPERM:
                raise StealthError(STEALTH_ROOT_REASON)
            continue
    if fd is None:
        detail = f": {last_error}" if last_error else ""
        raise StealthError(f"Could not open a BPF device{detail}.")

    attached = False
    try:
        chosen = None
        for size in (262144, 65536, 32768, 4096):
            buf = bytearray(struct.pack("I", size))
            try:
                fcntl.ioctl(fd, BIOCSBLEN, buf, True)
            except OSError:
                continue
            chosen = struct.unpack("I", buf)[0] or size
            break
        if chosen is None:
            raise StealthError("Could not set the BPF buffer size.")

        name = iface.encode("ascii", "ignore")[:15]
        req = bytearray(name + b"\x00" * (32 - len(name)))
        fcntl.ioctl(fd, BIOCSETIF, req, True)
        attached = True
        _set_bpf_uint(fd, BIOCIMMEDIATE, 1)
        # Header complete: the kernel must not rewrite the frame or the checksum.
        _set_bpf_uint(fd, BIOCSHDRCMPLT, 1)
        _set_bpf_uint(fd, BIOCSSEESENT, 1)
        dlt_buf = bytearray(4)
        fcntl.ioctl(fd, BIOCGDLT, dlt_buf, True)
        dlt = struct.unpack("I", dlt_buf)[0]
        length_buf = bytearray(4)
        fcntl.ioctl(fd, BIOCGBLEN, length_buf, True)
        buf_len = struct.unpack("I", length_buf)[0] or chosen
        return fd, dlt, buf_len
    except StealthError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        if not attached:
            raise StealthError(f"Could not capture on {iface}: {exc}")
        raise StealthError(f"Could not configure the capture on {iface}: {exc}")


def _open_linux(iface):
    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        raw.bind((iface, 0))
        raw.setblocking(False)
    except PermissionError:
        raise StealthError(STEALTH_ROOT_REASON)
    except OSError as exc:
        raise StealthError(f"Could not capture on {iface}: {exc}")
    capture = _Capture(raw.fileno(), DLT_EN10MB, 65535)
    capture.iface = iface
    capture._socket = raw

    def close_with_socket():
        # The socket owns the fd. Closing both would close it twice.
        with capture._lock:
            capture.fd = None
        try:
            raw.close()
        except OSError:
            pass

    capture.close = close_with_socket
    return capture


def _darwin_interfaces():
    import ctypes
    from ctypes import POINTER, Structure, byref, c_char_p, c_int, c_uint, c_void_p

    class Ifaddrs(Structure):
        pass

    Ifaddrs._fields_ = [
        ("ifa_next", POINTER(Ifaddrs)),
        ("ifa_name", c_char_p),
        ("ifa_flags", c_uint),
        ("ifa_addr", c_void_p),
        ("ifa_netmask", c_void_p),
        ("ifa_dstaddr", c_void_p),
        ("ifa_data", c_void_p),
    ]

    libc = ctypes.CDLL("/usr/lib/libc.dylib")
    libc.getifaddrs.argtypes = [POINTER(POINTER(Ifaddrs))]
    libc.getifaddrs.restype = c_int
    libc.freeifaddrs.argtypes = [POINTER(Ifaddrs)]
    head = POINTER(Ifaddrs)()
    if libc.getifaddrs(byref(head)) != 0:
        raise StealthError("Could not list network interfaces.")
    found = {}
    try:
        ptr = head
        while ptr:
            item = ptr.contents
            name = item.ifa_name.decode() if item.ifa_name else ""
            entry = found.setdefault(name, {"ips": set(), "mac": None})
            if item.ifa_addr and name:
                family = ctypes.cast(item.ifa_addr, POINTER(ctypes.c_ubyte))[1]
                if family == socket.AF_INET:
                    raw = ctypes.string_at(item.ifa_addr, 8)
                    entry["ips"].add(socket.inet_ntoa(raw[4:8]))
                elif family == 18:
                    sdl_len = ctypes.cast(item.ifa_addr, POINTER(ctypes.c_ubyte))[0]
                    blob = ctypes.string_at(item.ifa_addr, max(sdl_len, 8))
                    if len(blob) >= 8:
                        name_len = blob[5]
                        addr_len = blob[6]
                        start = 8 + name_len
                        mac = blob[start:start + addr_len]
                        if len(mac) == 6:
                            entry["mac"] = mac
            ptr = item.ifa_next
    finally:
        libc.freeifaddrs(head)
    return found


def _linux_interfaces():
    found = {}
    root = "/sys/class/net"
    if not os.path.isdir(root):
        return found
    for name in os.listdir(root):
        entry = {"ips": set(), "mac": None}
        mac_path = os.path.join(root, name, "address")
        try:
            text = open(mac_path, encoding="utf-8").read().strip()
        except OSError:
            text = ""
        parts = text.split(":")
        if len(parts) == 6:
            try:
                mac = bytes(int(part, 16) for part in parts)
            except ValueError:
                mac = None
            if mac and mac != b"\x00" * 6:
                entry["mac"] = mac
        found[name] = entry
    try:
        output = _command(["ip", "-4", "-o", "addr", "show"])
    except (OSError, subprocess.SubprocessError):
        return found
    for line in output.splitlines():
        pieces = line.split()
        if len(pieces) < 4 or pieces[2] != "inet":
            continue
        iface = pieces[1]
        ip = pieces[3].split("/", 1)[0]
        found.setdefault(iface, {"ips": set(), "mac": None})["ips"].add(ip)
    return found


def _lookup_route(dst_ip):
    if sys.platform == "darwin":
        return _macos_route(dst_ip)
    if sys.platform.startswith("linux"):
        return _linux_route(dst_ip)
    raise StealthError(f"Stealth mode is not available on {sys.platform}.")


def _macos_route(dst_ip):
    try:
        output = _command(["/sbin/route", "-n", "get", dst_ip])
    except (OSError, subprocess.SubprocessError) as exc:
        raise StealthError(f"Could not find a route to {dst_ip}: {exc}")
    info = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        info[key.strip()] = value.strip()
    flags = info.get("flags", "")
    gateway = info.get("gateway")
    if gateway in ("", "none"):
        gateway = None
    if "LOCAL" in flags:
        gateway = None
    return info.get("interface"), gateway, None


def _linux_route(dst_ip):
    try:
        output = _command(["ip", "route", "get", dst_ip])
    except (OSError, subprocess.SubprocessError) as exc:
        raise StealthError(f"Could not find a route to {dst_ip}: {exc}")
    parts = output.split()
    info = {}
    index = 0
    while index < len(parts) - 1:
        if parts[index] in {"via", "dev", "src"}:
            info[parts[index]] = parts[index + 1]
        index += 1
    return info.get("dev"), info.get("via"), info.get("src")


def _arp_cache(ip):
    if sys.platform == "darwin":
        try:
            output = _command(["/usr/sbin/arp", "-n", ip])
        except (OSError, subprocess.SubprocessError):
            return None
        if "incomplete" in output.lower():
            return None
        match = _ARP_RE.search(output)
        if not match:
            return None
        try:
            return bytes(int(part, 16) for part in match.group(1).split(":"))
        except ValueError:
            return None
    path = "/proc/net/arp"
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[0] == ip and parts[2] != "0x0":
            try:
                mac = bytes(int(part, 16) for part in parts[3].split(":"))
            except ValueError:
                return None
            if len(mac) == 6 and mac != b"\x00" * 6:
                return mac
    return None


def _command(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=3)


def _source_ip(dst_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((dst_ip, 1))
        return sock.getsockname()[0]
    except OSError as exc:
        raise StealthError(f"Could not choose a source address for {dst_ip}: {exc}")
    finally:
        sock.close()


def _iface_for_ip(ip, interfaces):
    for name, info in interfaces.items():
        if ip in info.get("ips", ()):
            return name
    return None


def _local_ips(interfaces):
    ips = set()
    for info in interfaces.values():
        ips.update(info.get("ips", ()))
    return ips


def _loopback_name(interfaces):
    if "lo0" in interfaces:
        return "lo0"
    if "lo" in interfaces:
        return "lo"
    for name, info in interfaces.items():
        if "127.0.0.1" in info.get("ips", ()):
            return name
    return "lo0"


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False
