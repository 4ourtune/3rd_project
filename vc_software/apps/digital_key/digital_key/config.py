"""Central configuration helpers for the digital_key package."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Union

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
LOG_DIR = PROJECT_ROOT / "logs"
CACHE_DIR = Path.home() / ".cache" / "dks"


def ensure_runtime_dirs() -> None:
    """Create directories used for logs and cached state."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def resolve_path(path: Union[str, os.PathLike[str]], *, fallback_root: Path | None = None) -> Path:
    """Resolve a potentially relative path against the project root."""
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    base = fallback_root or PROJECT_ROOT
    return (base / candidate).resolve()


__all__ = [
    "PACKAGE_DIR",
    "PROJECT_ROOT",
    "LOG_DIR",
    "CACHE_DIR",
    "ensure_runtime_dirs",
    "resolve_path",
]
