#!/usr/bin/env python3
"""Offline calibration helper that estimates pixel lane width from a captured frame."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Tuple

import cv2
import numpy as np

from calibration import LaneCalibration

DEFAULT_FRAME_WIDTH = 1920
DEFAULT_FRAME_HEIGHT = 1080


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Calibrate lane parameters from a captured image.")
    parser.add_argument("--image", required=True, help="Path to the captured calibration image.")
    parser.add_argument("--output", default="calibration.json", help="Filename for the generated calibration JSON.")
    parser.add_argument("--lane-width-cm", type=float, required=True, help="Real-world lane width in centimeters.")
    parser.add_argument("--camera-height-cm", type=float, required=True, help="Camera height above the ground.")
    parser.add_argument(
        "--frame-width", type=int, default=DEFAULT_FRAME_WIDTH, help="Processing width used by the vision pipeline."
    )
    parser.add_argument(
        "--frame-height", type=int, default=DEFAULT_FRAME_HEIGHT, help="Processing height used by the vision pipeline."
    )
    parser.add_argument(
        "--visualize",
        action="store_true",
        help="Display binary mask and detected peaks for quick verification.",
    )
    return parser.parse_args()


def create_binary_mask(frame: np.ndarray) -> np.ndarray:
    """Replicate the HSV + morphology mask from the runtime pipeline."""
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

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 50, 150)
    mask = cv2.bitwise_or(mask, edges)
    return mask


def measure_lane_width(mask: np.ndarray) -> Tuple[int, int, int]:
    """Measure lane width in pixels using a histogram peak search near the horizon."""
    if mask.ndim != 2:
        raise ValueError("Binary mask must be single-channel.")

    start_row = int(mask.shape[0] * 0.6)
    roi = mask[start_row:, :]
    histogram = np.sum(roi, axis=0).astype(np.float32)

    if not np.any(histogram):
        raise RuntimeError("Unable to find any lane-like pixels in the provided image.")

    midpoint = histogram.shape[0] // 2
    left_peak = int(np.argmax(histogram[:midpoint]))
    right_peak = int(np.argmax(histogram[midpoint:]) + midpoint)
    width_px = right_peak - left_peak

    if width_px <= 0:
        raise RuntimeError("Detected lane width is non-positive; check the calibration image.")

    return left_peak, right_peak, width_px


def main() -> int:
    args = parse_args()
    image_path = Path(args.image)
    if not image_path.exists():
        print(f"❌ Image not found: {image_path}", file=sys.stderr)
        return 1

    frame = cv2.imread(str(image_path))
    if frame is None:
        print(f"❌ Failed to load image: {image_path}", file=sys.stderr)
        return 1

    resized = cv2.resize(frame, (args.frame_width, args.frame_height), interpolation=cv2.INTER_LINEAR)
    mask = create_binary_mask(resized)
    left_peak, right_peak, width_px = measure_lane_width(mask)

    calibration = LaneCalibration(
        frame_width=args.frame_width,
        frame_height=args.frame_height,
        lane_width_cm=args.lane_width_cm,
        lane_width_px=float(width_px),
        pixels_per_cm=float(width_px / args.lane_width_cm),
        cm_per_pixel=float(args.lane_width_cm / width_px),
        camera_height_cm=args.camera_height_cm,
        source_image=str(image_path),
        timestamp=time.time(),
    )
    calibration.save(args.output)

    print(
        "✅ Calibration complete:"
        f" lane_width_px={width_px:.2f}, cm_per_pixel={calibration.cm_per_pixel:.4f},"
        f" pixels_per_cm={calibration.pixels_per_cm:.2f}"
    )
    print(f"💾 Saved to {args.output}")

    if args.visualize:
        vis = cv2.cvtColor(mask, cv2.COLOR_GRAY2BGR)
        cv2.line(vis, (left_peak, 0), (left_peak, vis.shape[0]), (0, 255, 0), 2)
        cv2.line(vis, (right_peak, 0), (right_peak, vis.shape[0]), (0, 0, 255), 2)
        cv2.putText(
            vis,
            f"{width_px}px",
            (int((left_peak + right_peak) / 2) - 40, 40),
            cv2.FONT_HERSHEY_SIMPLEX,
            1.0,
            (255, 255, 255),
            2,
            cv2.LINE_AA,
        )
        cv2.imshow("Calibration Mask", vis)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
