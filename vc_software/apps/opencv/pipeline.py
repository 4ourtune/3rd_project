"""Vision preprocessing pipeline using HSV masking and morphological filtering."""

from __future__ import annotations

import time
from typing import Any, Dict

import cv2
import numpy as np

from lane_analyzer import LaneAnalyzer


class VisionPipeline:
    """Prepare frames for lane analysis using HSV-based masking and morphology."""

    def __init__(
        self,
        analyzer: LaneAnalyzer,
        frame_width: int,
        frame_height: int,
        target_fps: int,
        process_width: int | None = None,
        process_height: int | None = None,
        use_edges: bool = True,
    ) -> None:
        self.analyzer = analyzer
        self.frame_width = frame_width
        self.frame_height = frame_height
        self.target_fps = target_fps
        self.process_width = process_width or frame_width
        self.process_height = process_height or frame_height
        self.use_edges = use_edges
        self.calibration = analyzer.calibration
        self._last_frame_time: float | None = None

    def process(self, frame: np.ndarray) -> Dict[str, Any]:
        """Run HSV masking, morphology, and lane analysis on a BGR frame."""
        start = time.perf_counter()
        resized = self._resize_frame(frame)
        binary = self._create_binary_mask(resized)

        analysis = self.analyzer.analyze(binary)
        fps = self._update_fps()
        latency_ms = (time.perf_counter() - start) * 1000.0

        result: Dict[str, Any] = {
            "timestamp": time.time(),
            "offset": analysis.get("offset"),
            "offset_px": analysis.get("offset_px"),
            "offset_cm": analysis.get("offset_cm"),
            "lane_state": analysis.get("lane_state"),
            "stop_detected": analysis.get("stop_detected"),
            "confidence": analysis.get("confidence"),
            "curve_hint": analysis.get("curve_hint"),
            "lane_visibility": analysis.get("lane_visibility"),
            "curve_scope": analysis.get("curve_scope"),
            "curve_phase": analysis.get("curve_phase"),
            "release_debug": analysis.get("release_debug"),
            "fps": fps,
            "latency_ms": latency_ms,
        }
        # Preserve auxiliary information for downstream debugging if needed.
        result["details"] = {
            "binary_shape": binary.shape,
            "process_dimensions": (self.process_width, self.process_height),
            "lane_width_px": analysis.get("lane_width_px"),
        }
        if self.calibration is not None:
            result["details"]["calibration"] = {
                "lane_width_px": self.calibration.lane_width_px,
                "lane_width_cm": self.calibration.lane_width_cm,
                "cm_per_pixel": self.calibration.cm_per_pixel,
                "pixels_per_cm": self.calibration.pixels_per_cm,
                "camera_height_cm": self.calibration.camera_height_cm,
                "source_image": self.calibration.source_image,
            }
        return result

    def _resize_frame(self, frame: np.ndarray) -> np.ndarray:
        """Optionally resize the frame to the processing resolution."""
        if frame.shape[0] == self.process_height and frame.shape[1] == self.process_width:
            return frame
        return cv2.resize(frame, (self.process_width, self.process_height), interpolation=cv2.INTER_LINEAR)

    def _create_binary_mask(self, frame: np.ndarray) -> np.ndarray:
        """Generate a binary lane mask using HSV thresholds and morphology."""
        hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)

        mask_yellow = cv2.inRange(
            hsv,
            np.array([15, 80, 160], dtype=np.uint8),
            np.array([40, 255, 255], dtype=np.uint8),
        )
        mask_white = cv2.inRange(
            hsv,
            np.array([0, 0, 200], dtype=np.uint8),
            np.array([255, 20, 255], dtype=np.uint8),
        )

        mask = cv2.bitwise_or(mask_yellow, mask_white)

        kernel = np.ones((5, 5), dtype=np.uint8)
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel)
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)

        if self.use_edges:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray, 50, 150)
            mask = cv2.bitwise_or(mask, edges)

        return mask

    def _update_fps(self) -> float:
        """Estimate instantaneous FPS to aid performance monitoring."""
        now = time.perf_counter()
        if self._last_frame_time is None:
            self._last_frame_time = now
            return float(self.target_fps)

        delta = now - self._last_frame_time
        self._last_frame_time = now
        if delta <= 0.0:
            return float(self.target_fps)
        return 1.0 / delta
