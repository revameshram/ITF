"""In-process network egress guard (OFFLINE / AIR-GAPPED MODE).

REAL IMPLEMENTATION (scope: this Python process only).

Wraps socket.connect / socket.create_connection so that any attempt to
reach a non-loopback address raises `NetworkBlocked` and is recorded.
The web UI is additionally served with a strict Content-Security-Policy
(`default-src 'self'`) so the browser refuses to load anything remote.

Limitation: this does not stop *other* processes on the machine from
using the network. On a real air-gapped deployment the host itself has
no network route; this guard is defence-in-depth and a design check.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
from datetime import datetime, timezone

_blocked: list[dict] = []
_lock = threading.Lock()
_installed = False
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex
_orig_create_connection = socket.create_connection


class NetworkBlocked(ConnectionRefusedError):
    pass


def _is_local(host) -> bool:
    if host is None:
        return True
    if isinstance(host, (bytes, bytearray)):
        host = host.decode()
    host = str(host)
    if host in ("localhost", ""):
        return True
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
        return ip.is_loopback or ip.is_unspecified
    except ValueError:
        # hostname that is not localhost -> would need DNS -> treat as remote
        return False


def _record(host, port) -> None:
    with _lock:
        _blocked.append({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         "host": str(host), "port": port})


def _check(address) -> None:
    if isinstance(address, tuple) and address:
        host, port = address[0], address[1] if len(address) > 1 else None
        if not _is_local(host):
            _record(host, port)
            raise NetworkBlocked(f"AegisVision offline mode: outbound connection to {host}:{port} blocked")


def _guarded_connect(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _check(address)
    return _orig_connect(self, address)


def _guarded_connect_ex(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _check(address)
    return _orig_connect_ex(self, address)


def _guarded_create_connection(address, *args, **kwargs):
    _check(address)
    return _orig_create_connection(address, *args, **kwargs)


def install() -> None:
    global _installed
    if _installed:
        return
    socket.socket.connect = _guarded_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[assignment]
    socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
    _installed = True


def uninstall() -> None:
    global _installed
    socket.socket.connect = _orig_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _orig_connect_ex  # type: ignore[assignment]
    socket.create_connection = _orig_create_connection  # type: ignore[assignment]
    _installed = False


def status() -> dict:
    with _lock:
        return {"mode": "OFFLINE / AIR-GAPPED", "guard_installed": _installed,
                "blocked_attempts": list(_blocked[-20:]), "blocked_count": len(_blocked),
                "scope": "in-process socket guard + browser CSP default-src 'self'"}
