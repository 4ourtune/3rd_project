"""Unix-domain socket client for interacting with the realtime service."""
from __future__ import annotations

import socket
import time
from typing import Tuple

SOCK_PATH = "/run/vc/ipc/realtime.sock"


def send_cmd(cmd: str, src: str, *, timeout: float = 0.3) -> Tuple[bool, str]:
    """Send LOCK/UNLOCK/START/GET_ALL commands to realtime."""
    req = int(time.time() * 1000)
    payload = f"CMD={cmd};REQ={req};SRC={src}\n".encode()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect(SOCK_PATH)
        sock.send(payload)
        resp = sock.recv(256).decode()
        ok = resp.startswith("OK;") and f"REQ={req}" in resp
        return ok, resp.strip()
    except Exception as exc:  # pragma: no cover - thin IPC wrapper
        return False, f"ERR;{exc}"
    finally:
        sock.close()
