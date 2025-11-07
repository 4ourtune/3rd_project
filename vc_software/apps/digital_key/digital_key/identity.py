"""Utilities for loading immutable vehicle identity metadata and related env defaults."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

from .config import PROJECT_ROOT

DEFAULT_IDENTITY_FILENAME = "vehicle_identity.txt"
DEFAULT_ENV_FILENAME = ".env"
ENV_IDENTITY_PATH = "VEHICLE_IDENTITY_PATH"
ENV_ENV_PATH = "VEHICLE_ENV_PATH"


def _resolve_identity_path(provided: str | os.PathLike[str] | None = None) -> Path:
    if provided:
        return Path(provided).expanduser().resolve()
    env_path = os.environ.get(ENV_IDENTITY_PATH)
    if env_path:
        return Path(env_path).expanduser().resolve()
    return PROJECT_ROOT / DEFAULT_IDENTITY_FILENAME


def _resolve_env_path(provided: str | os.PathLike[str] | None = None) -> Path:
    if provided:
        return Path(provided).expanduser().resolve()
    env_path = os.environ.get(ENV_ENV_PATH)
    if env_path:
        return Path(env_path).expanduser().resolve()
    return PROJECT_ROOT / DEFAULT_ENV_FILENAME


def _parse_kv_file(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    values: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip()
    return values


@lru_cache(maxsize=1)
def load_identity(path: str | os.PathLike[str] | None = None) -> Dict[str, str]:
    """Load identity metadata once and cache the result."""
    resolved = _resolve_identity_path(path)
    return _parse_kv_file(resolved)


def get_identity_value(
    key: str,
    default: Optional[str] = None,
    *,
    path: str | os.PathLike[str] | None = None,
) -> Optional[str]:
    """Return a single identity value (lowercased key) or a default."""
    identity = load_identity(path)
    return identity.get(key.lower(), default)


def refresh_identity(path: str | os.PathLike[str] | None = None) -> Dict[str, str]:
    """Force reload of identity metadata (clears cache)."""
    load_identity.cache_clear()
    return load_identity(path)


def load_env_defaults(path: str | os.PathLike[str] | None = None) -> None:
    """Read a .env-style file and populate os.environ without overwriting existing keys."""
    target = _resolve_env_path(path)
    if not target.exists():
        return
    for raw_line in target.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


__all__ = [
    "DEFAULT_IDENTITY_FILENAME",
    "DEFAULT_ENV_FILENAME",
    "ENV_IDENTITY_PATH",
    "ENV_ENV_PATH",
    "load_identity",
    "get_identity_value",
    "refresh_identity",
    "load_env_defaults",
]
