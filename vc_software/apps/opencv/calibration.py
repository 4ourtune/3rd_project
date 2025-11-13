"""Utilities for loading and storing lane calibration metadata."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict


@dataclass(frozen=True)
class LaneCalibration:
    """Persisted calibration parameters derived from offline measurements."""

    frame_width: int
    frame_height: int
    lane_width_cm: float
    lane_width_px: float
    pixels_per_cm: float
    cm_per_pixel: float
    camera_height_cm: float
    source_image: str | None = None
    timestamp: float | None = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise calibration data for JSON output."""
        return {
            "frame_width": self.frame_width,
            "frame_height": self.frame_height,
            "lane_width_cm": self.lane_width_cm,
            "lane_width_px": self.lane_width_px,
            "pixels_per_cm": self.pixels_per_cm,
            "cm_per_pixel": self.cm_per_pixel,
            "camera_height_cm": self.camera_height_cm,
            "source_image": self.source_image,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_file(cls, path: str | Path) -> LaneCalibration:
        """Load calibration parameters from a JSON file."""
        json_path = Path(path)
        with json_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        return cls(
            frame_width=int(data["frame_width"]),
            frame_height=int(data["frame_height"]),
            lane_width_cm=float(data["lane_width_cm"]),
            lane_width_px=float(data["lane_width_px"]),
            pixels_per_cm=float(data["pixels_per_cm"]),
            cm_per_pixel=float(data["cm_per_pixel"]),
            camera_height_cm=float(data["camera_height_cm"]),
            source_image=data.get("source_image"),
            timestamp=float(data["timestamp"]) if "timestamp" in data else None,
        )

    def save(self, path: str | Path) -> None:
        """Write calibration parameters to disk."""
        json_path = Path(path)
        with json_path.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
            handle.write("\n")
