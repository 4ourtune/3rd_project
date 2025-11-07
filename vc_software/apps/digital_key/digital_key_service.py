#!/usr/bin/env python3
"""Systemd entry point for the digital_key BLE service."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent
    init_script = project_root / "scripts" / "init_vehicle.sh"

    if not init_script.exists():
        print(f"[digital_key-service] init script not found: {init_script}", file=sys.stderr)
        return 1

    cmd = ["/bin/bash", str(init_script)]
    print(f"[digital_key-service] launching {' '.join(cmd)}", flush=True)
    process = subprocess.Popen(cmd, cwd=str(project_root))  # pylint: disable=consider-using-with
    return process.wait()


if __name__ == "__main__":
    sys.exit(main())
