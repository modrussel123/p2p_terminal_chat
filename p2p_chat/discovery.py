"""
discovery.py
------------
Zero-infrastructure peer discovery on a local network using UDP broadcast.
No DHT, no bootstrap/rendezvous server, no accounts -- just a shout on the
LAN that only the peer holding the same one-time code will answer.

Flow
====
1. Host generates a one-time code, derives its fingerprint, opens a TCP
   port for the chat itself, and starts a DiscoveryResponder that listens
   on UDP for HELLO packets carrying that fingerprint.
2. Host reads the plain code out loud / sends it via any side channel to
   their peer (SMS, in person, whatever -- this app never transports it).
3. Joiner enters the code. Their machine broadcasts HELLO packets
   (fingerprint only, never the raw code) to the LAN broadcast address.
4. Only the host whose fingerprint matches replies (unicast) with its
   real IP, TCP port, and public key.
5. Joiner opens a normal TCP connection to that IP:port and the two sides
   perform the NaCl key exchange (see network.py).

This intentionally only works on the same broadcast domain (same Wi-Fi /
LAN segment) -- which matches "same network" in the brief. As a fallback
for networks that block broadcast, the UI also accepts a manual
`CODE@ip:port` form that skips discovery entirely.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

DISCOVERY_PORT = 51234
BROADCAST_ADDR = "255.255.255.255"
MAGIC = "P2PCHAT-v1"


def get_local_ip() -> str:
    """Best-effort local LAN IP (doesn't actually send any packets)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


@dataclass
class PeerInfo:
    host_ip: str
    tcp_port: int
    pubkey: str


class DiscoveryResponder:
    """Runs on the hosting peer's side. Answers only HELLO packets whose
    fingerprint matches ours. Uses a plain background thread (not asyncio)
    since it's a tiny, self-contained blocking loop."""

    def __init__(self, fingerprint: str, tcp_port: int, pubkey_str: str):
        self.fingerprint = fingerprint
        self.tcp_port = tcp_port
        self.pubkey_str = pubkey_str
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass  # not available on every platform
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(0.5)
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def _listen(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if msg.get("magic") != MAGIC or msg.get("type") != "HELLO":
                continue
            if msg.get("fingerprint") != self.fingerprint:
                continue  # not for us -- someone else's pairing code
            reply = {
                "magic": MAGIC,
                "type": "REPLY",
                "fingerprint": self.fingerprint,
                "tcp_port": self.tcp_port,
                "pubkey": self.pubkey_str,
                "host_ip": get_local_ip(),
            }
            try:
                self._sock.sendto(json.dumps(reply).encode("utf-8"), addr)
            except OSError:
                pass

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


def discover_peer(fingerprint: str, timeout: float = 25.0,
                   retry_interval: float = 1.0) -> Optional[PeerInfo]:
    """Runs on the joining peer's side. BLOCKING call intended to be run
    in a thread/executor. Broadcasts HELLO repeatedly until a matching
    REPLY arrives or `timeout` seconds elapse."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(retry_interval)

    payload = json.dumps({
        "magic": MAGIC,
        "type": "HELLO",
        "fingerprint": fingerprint,
    }).encode("utf-8")

    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                sock.sendto(payload, (BROADCAST_ADDR, DISCOVERY_PORT))
            except OSError:
                pass
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if msg.get("magic") == MAGIC and msg.get("type") == "REPLY" \
                    and msg.get("fingerprint") == fingerprint:
                return PeerInfo(
                    host_ip=msg["host_ip"],
                    tcp_port=int(msg["tcp_port"]),
                    pubkey=msg["pubkey"],
                )
    finally:
        sock.close()
    return None


async def discover_peer_async(fingerprint: str, timeout: float = 25.0,
                               retry_interval: float = 1.0) -> Optional[PeerInfo]:
    """Async-friendly wrapper around discover_peer().

    Deliberately does NOT use loop.run_in_executor()/the default
    ThreadPoolExecutor: that pool is made of non-daemon threads, and a
    still-running search would otherwise keep the whole process alive
    (up to `timeout` seconds) even after the user quits the app. Running
    the blocking search on our own daemon thread means the process can
    exit immediately -- the search thread is simply abandoned if nobody
    is waiting on it anymore.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()

    def worker():
        try:
            result = discover_peer(fingerprint, timeout, retry_interval)
        except Exception as exc:  # pragma: no cover - defensive
            if not loop.is_closed():
                loop.call_soon_threadsafe(_safe_set_exception, future, exc)
            return
        if not loop.is_closed():
            loop.call_soon_threadsafe(_safe_set_result, future, result)

    threading.Thread(target=worker, daemon=True).start()
    return await future


def _safe_set_result(future: asyncio.Future, result) -> None:
    if not future.done():
        future.set_result(result)


def _safe_set_exception(future: asyncio.Future, exc: Exception) -> None:
    if not future.done():
        future.set_exception(exc)
