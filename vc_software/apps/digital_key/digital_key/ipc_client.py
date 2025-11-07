"""Lightweight Unix-domain socket client for realtime vehicle control."""
from __future__ import annotations

import os
import socket
import time
import uuid
from typing import Tuple

# Socket exposed by realtime ipc_server.cpp. Permissions are managed so that
# members of the vc group (digital_key, ota, etc.) can access it.
SOCK_PATH = "/run/vc/ipc/realtime.sock"


def send_cmd(cmd: str, src: str, *, timeout: float = 0.3) -> Tuple[bool, str]:
    """Send a command to the realtime process.

    Args:
        cmd: One of LOCK, UNLOCK, START, GET_ALL.
        src: Caller identifier (e.g., "DK" for digital key).
        timeout: Socket timeout in seconds.

    Returns:
        Tuple of (success flag, raw response string).
    """
    req = int(time.time() * 1000)
    message = f"CMD={cmd};REQ={req};SRC={src}\n".encode()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    client_path = f"/run/vc/ipc/dk_{os.getpid()}_{uuid.uuid4().hex[:8]}.sock"
    try:
        # Bind to a unique client path so the server can reply.
        sock.bind(client_path)
        sock.sendto(message, SOCK_PATH)
        response, _ = sock.recvfrom(256)
        decoded = response.decode()
        ok = decoded.startswith("OK;") and f"REQ={req}" in decoded
        return ok, decoded.strip()
    except Exception as exc:  # pragma: no cover - thin IPC wrapper
        return False, f"ERR;{exc}"
    finally:
        try:
            os.unlink(client_path)
        except OSError:
            pass
        sock.close()
