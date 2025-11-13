"""Reporting utilities for the LKAS vision pipeline."""

from __future__ import annotations

import logging
import time
from collections import Counter, deque
from typing import Any, Deque, Dict, Optional


class StatusReporter:
    """Maintains smoothed statistics and emits structured debug logs."""

    def __init__(
        self,
        alpha: float = 0.2,
        log_interval: float = 0.5,
        window_size: int = 60,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Configure EMA smoothing and logging cadence."""
        self.alpha = alpha
        self.log_interval = max(0.1, log_interval)
        self.history: Deque[Dict[str, Any]] = deque(maxlen=max(1, window_size))
        self.logger = logger or logging.getLogger(__name__)
        self._ema_offset: Optional[float] = None
        self._last_log_ts = 0.0

    def update(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Apply smoothing to the latest result and emit logs as needed."""
        offset = result.get("offset")
        if offset is not None:
            if self._ema_offset is None:
                self._ema_offset = float(offset)
            else:
                self._ema_offset = self.alpha * float(offset) + (1.0 - self.alpha) * self._ema_offset

        result["offset_smoothed"] = self._ema_offset if self._ema_offset is not None else offset
        self.history.append(result)
        self._maybe_log(result)
        return result

    def _maybe_log(self, latest: Dict[str, Any]) -> None:
        """Log a concise status summary at the configured cadence."""
        now = time.monotonic()
        if self._last_log_ts != 0.0 and (now - self._last_log_ts) < self.log_interval:
            return
        self._last_log_ts = now

        sample_count = len(self.history)
        if sample_count == 0:
            return

        offsets = [entry.get("offset_smoothed") for entry in self.history if entry.get("offset_smoothed") is not None]
        avg_offset = sum(offsets) / len(offsets) if offsets else None

        lane_counter = Counter(entry.get("lane_state") for entry in self.history if entry.get("lane_state"))
        dominant_state, dominant_count = (lane_counter.most_common(1)[0] if lane_counter else ("N/A", 0))

        stop_hits = sum(1 for entry in self.history if entry.get("stop_detected"))
        stop_rate = (100.0 * stop_hits / sample_count) if sample_count else 0.0

        self.logger.info(
            "state=%s offset=%.3f ema=%.3f avg=%.3f conf=%.2f fps=%.1f stop_rate=%.1f%% window=%d",
            latest.get("lane_state"),
            float(latest.get("offset") or 0.0),
            float(latest.get("offset_smoothed") or 0.0),
            float(avg_offset or 0.0),
            float(latest.get("confidence") or 0.0),
            float(latest.get("fps") or 0.0),
            stop_rate,
            sample_count,
        )
