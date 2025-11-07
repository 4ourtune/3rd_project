"""Key storage utilities for Digital Key BLE prototype."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .config import CACHE_DIR, ensure_runtime_dirs

LOGGER = logging.getLogger(__name__)


def _default_store_path() -> Path:
    """Return the development-time path for persisted keys."""
    ensure_runtime_dirs()
    return CACHE_DIR / "keys.json"


class KeyStore:
    """Thread-safe JSON-based key storage."""

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = Path(path) if path else _default_store_path()
        self._lock = threading.Lock()
        self._keys: Dict[str, Dict[str, Any]] = {}
        self._load_from_disk()

    # Public API ---------------------------------------------------------
    def upsert_key(self, key_id: str, payload: Dict[str, Any]) -> None:
        """Persist key metadata by identifier."""
        with self._lock:
            self._keys[key_id] = payload
            self._flush()
            LOGGER.info("Persisted key %s", key_id)

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve key metadata if present."""
        with self._lock:
            return self._keys.get(key_id)

    def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """Return a copy of stored keys for inspection/testing."""
        with self._lock:
            return dict(self._keys)

    def replace_all(self, data: Dict[str, Dict[str, Any]]) -> None:
        """Replace the entire key store with provided mapping."""
        with self._lock:
            self._keys = dict(data)
            self._flush()
            LOGGER.info("Replaced key store contents with %d entries", len(self._keys))

    # Internal helpers ---------------------------------------------------
    def _load_from_disk(self) -> None:
        if not self.path.exists():
            LOGGER.debug("No key store found at %s; starting empty", self.path)
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                self._keys = data
                LOGGER.info("Loaded %d keys from %s", len(self._keys), self.path)
        except json.JSONDecodeError as exc:
            LOGGER.warning("Failed to parse key store JSON: %s", exc)

    def _flush(self) -> None:
        self.path.write_text(
            json.dumps(self._keys, indent=2, sort_keys=True),
            encoding='utf-8',
        )
