"""Utilities for assembling chunked BLE command payloads."""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Dict, Tuple

from .config import LOG_DIR

LOGGER = logging.getLogger(__name__)
_DEBUG_CHUNK_PATH = LOG_DIR / "last_chunk.json"


class CommandChunkAssembler:
    """Reassemble chunked BLE command payloads written by the smartphone app."""

    class _ChunkState:
        def __init__(self, chunk_id: str, total: int, created: float):
            self.chunk_id = chunk_id
            self.total = total
            self.created = created
            self.parts: Dict[int, bytes] = {}

        def add(self, index: int, data: bytes) -> None:
            self.parts[index] = data

        def complete(self) -> bool:
            return len(self.parts) == self.total and all(idx in self.parts for idx in range(self.total))

        def build(self) -> bytes:
            return b"".join(self.parts[idx] for idx in range(self.total))

    def __init__(self, ttl_seconds: float = 15.0) -> None:
        self._ttl = ttl_seconds
        self._state: CommandChunkAssembler._ChunkState | None = None

    def reset(self) -> None:
        self._state = None

    def ingest(self, payload: Dict[str, Any]) -> Dict[str, Any] | None:
        chunk_meta = self._extract_chunk_meta(payload)
        if chunk_meta is None:
            if self._state is not None:
                self._state = None
            LOGGER.info(
                "Received non-chunk command payload with keys: %s",
                list(payload.keys()) if isinstance(payload, dict) else type(payload),
            )
            return payload

        chunk_id, index, total, chunk_bytes = chunk_meta
        if total <= 0:
            raise ValueError(f"Invalid chunk total={total}")
        if not 0 <= index < total:
            raise ValueError(f"Chunk index {index} out of bounds for total {total}")

        now = time.monotonic()
        if self._state and (
            self._state.chunk_id != chunk_id
            or self._state.total != total
            or now - self._state.created > self._ttl
            or index == 0
        ):
            self._state = None

        if self._state is None:
            if index != 0:
                LOGGER.warning(
                    "Received command chunk index=%d without existing buffer; starting new sequence id=%s total=%d",
                    index,
                    chunk_id,
                    total,
                )
            self._state = CommandChunkAssembler._ChunkState(chunk_id=chunk_id, total=total, created=now)

        self._state.add(index, chunk_bytes)
        LOGGER.info("Buffered command chunk id=%s index=%d/%d", chunk_id, index + 1, total)

        if not self._state.complete():
            return None

        assembled_bytes = self._state.build()
        self._state = None
        try:
            assembled_text = assembled_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Failed to decode assembled chunk payload: {exc}") from exc

        try:
            assembled_json = json.loads(assembled_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Assembled chunk payload is not valid JSON: {exc}") from exc

        try:
            _DEBUG_CHUNK_PATH.write_text(assembled_text, encoding="utf-8")
        except Exception:  # pylint: disable=broad-except
            pass

        LOGGER.info("Assembled command chunk sequence id=%s bytes=%d", chunk_id, len(assembled_bytes))
        return assembled_json

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _first_non_none(payload: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in payload and payload[key] is not None:
                return payload[key]
        return None

    @staticmethod
    def _to_bytes(data: Any, encoding_hint: str | None) -> bytes:
        if isinstance(data, bytes):
            raw = data
        elif isinstance(data, list) and all(isinstance(item, int) for item in data):
            raw = bytes(data)
        else:
            raw = str(data).encode("utf-8")

        if encoding_hint and encoding_hint.lower() == "base64":
            try:
                return base64.b64decode(raw, validate=True)
            except (base64.binascii.Error, ValueError) as exc:
                raise ValueError(f"Failed to base64-decode chunk data: {exc}") from exc
        return raw

    def _extract_chunk_meta(self, payload: Dict[str, Any]) -> Tuple[str, int, int, bytes] | None:
        if not isinstance(payload, dict):
            return None

        index = self._coerce_int(
            self._first_non_none(
                payload,
                "index",
                "chunkIndex",
                "chunk_index",
                "part",
                "partIndex",
                "sequence",
            )
        )
        total = self._coerce_int(
            self._first_non_none(
                payload,
                "total",
                "chunkTotal",
                "parts",
                "chunkCount",
                "totalChunks",
                "chunk_count",
            )
        )

        if index is None or total is None:
            return None

        data_field = None
        for key in ("data", "chunkData", "payload", "value", "content", "chunk"):
            if key in payload and payload[key] is not None and key != "chunkIndex":
                data_field = payload[key]
                break

        if data_field is None:
            return None

        encoding_hint = payload.get("encoding") or payload.get("dataEncoding")
        chunk_bytes = self._to_bytes(data_field, encoding_hint)

        chunk_id = (
            payload.get("id")
            or payload.get("chunkId")
            or payload.get("messageId")
            or payload.get("requestId")
            or payload.get("sessionId")
            or payload.get("nonce")
        )
        chunk_id = str(chunk_id) if chunk_id is not None else "default"
        return chunk_id, index, total, chunk_bytes


__all__ = ["CommandChunkAssembler"]
