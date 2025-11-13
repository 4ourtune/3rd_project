"""Sliding window lane analyser with bird's-eye perspective transform."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

import math

import cv2
import numpy as np

from calibration import LaneCalibration

SRC_POINT_RATIOS = np.float32(
    [
        [0.18, 0.78],  # keep a moderate portion of the mid-field; ignore far horizon
        [0.82, 0.78],
        [0.02, 1.0],
        [0.98, 1.0],
    ]
)

DST_POINT_RATIOS = np.float32(
    [
        [0.2, 0.0],
        [0.8, 0.0],
        [0.25, 1.0],
        [0.75, 1.0],
    ]
)


@dataclass
class SlidingWindowConfig:
    """Configuration parameters for the sliding window tracker."""

    n_windows: int = 9
    margin: int = 60
    minpix: int = 50
    expected_lane_width: float = 320.0  # pixels in warped view


class LaneAnalyzer:
    """Detect lane boundaries using a histogram-guided sliding window search."""

    def __init__(
        self,
        frame_width: int,
        frame_height: int,
        calibration: LaneCalibration | None = None,
    ) -> None:
        self.frame_width = frame_width
        self.frame_height = frame_height
        self.warp_size = (frame_width, frame_height)
        self.calibration = calibration
        self.frame_counter = 0
        self.curve_warmup_frames = 12
        self.curve_offset_guard = 0.013
        self.curve_near_top_ratio = 0.94
        self.curve_far_top_ratio = 0.8
        self.lane_startup_guard_frames = 8
        self.top_crop_ratio = 0.3
        self._last_full_offsets = {"norm": None, "px": None, "cm": None}
        self._single_lane_decay_frames = 0
        self._single_lane_offsets = {"norm": None, "px": None, "cm": None}
        self._single_lane_active = False
        self._single_lane_frame_count = 0
        self.single_lane_release_window = 26
        self.single_lane_min_bias = 0.014
        self.single_lane_hold_frames = 8
        self.straight_centering_alpha = 0.07
        self.lane_center_safe_band = 0.03
        self.lane_center_push_gain = 0.032
        self.single_lane_offset_limit = 0.18
        self.single_lane_force_threshold = 6
        self.curve_phase_state = "STRAIGHT"
        self.single_lane_curve_active_scale = 0.4
        self.single_lane_release_hold_frames = 8
        self._single_lane_release_tail = 0
        self.curve_hint_switch_frames = 3
        self._curve_hint_sticky = "STRAIGHT"
        self._curve_hint_pending: str | None = None
        self._curve_hint_pending_count = 0
        self._straight_settle_frames = 0
        self.vehicle_width_cm = 15.0
        self.vehicle_margin_cm = 1.0
        self.curve_release_confirm_frames = 6
        self._curve_release_counter = 0
        self._release_candidate_counter = 0
        self.curve_release_recent_frames = 8
        self._recent_both_lane_frames = 0
        self.curve_entry_hold_frames = 3
        self.curve_entry_hold_min_frames = 1
        self.curve_entry_hold_guard_scale = 3.8
        self.curve_entry_hold_max_frames = 24
        self._curve_entry_hold_active = False
        self._curve_entry_hold_elapsed = 0
        self._curve_entry_hold_limited_frames = 0
        self.curve_entry_hold_limited_frames_max = 9
        self._prev_detected_turning = False
        self._curve_turn_frame_count = 0
        self.curve_late_boost_start_frames = 14
        self.curve_late_boost_ramp_frames = 8
        self.curve_late_boost_gain = 1.12
        self.curve_late_boost_offset_cap_scale = 2.1
        self.single_lane_curve_infer_frames = 3
        self.single_lane_curve_infer_offset_scale = 1.6
        self._single_lane_left_frames = 0
        self._single_lane_right_frames = 0
        self._last_curve_offset = 0.0
        self.config = SlidingWindowConfig()
        if calibration is not None:
            self.config.expected_lane_width = calibration.lane_width_px
        else:
            self.config.expected_lane_width = frame_width * 0.5

        self.perspective_matrix = self._compute_perspective_matrix()

    def analyze(self, binary_img: np.ndarray) -> Dict[str, float | bool | None]:
        """Perform bird's-eye lane detection and compute lateral offset."""
        self.frame_counter += 1
        warped = cv2.warpPerspective(binary_img, self.perspective_matrix, self.warp_size)
        if self.top_crop_ratio > 0.0:
            top_cut = int(self.frame_height * (1.0 - self.top_crop_ratio))
            top_cut = max(0, min(self.frame_height, top_cut))
            warped[: self.frame_height - top_cut, :] = 0
        histogram = np.sum(warped[warped.shape[0] // 2 :, :], axis=0)

        leftx_base, rightx_base = self._find_lane_bases(histogram)
        if leftx_base is None or rightx_base is None:
            return self._result(
                None,
                "NO_LANE",
                False,
                0.0,
                curve_hint="UNKNOWN",
                curve_scope="UNKNOWN",
                curve_phase="STRAIGHT",
                lane_visibility="NONE",
            )

        left_fit, right_fit, leftx, lefty, rightx, righty = self._sliding_window_fit(
            warped, leftx_base, rightx_base
        )
        left_detected = len(leftx) >= 3
        right_detected = len(rightx) >= 3
        if not left_detected and not right_detected:
            return self._result(
                None,
                "NO_LANE",
                False,
                0.0,
                curve_hint="UNKNOWN",
                curve_scope="UNKNOWN",
                curve_phase="STRAIGHT",
                lane_visibility="NONE",
            )

        lane_visibility = "BOTH"
        if left_detected and not right_detected:
            lane_visibility = "LEFT_ONLY"
        elif right_detected and not left_detected:
            lane_visibility = "RIGHT_ONLY"
        if lane_visibility == "LEFT_ONLY":
            self._single_lane_left_frames = min(self._single_lane_left_frames + 1, 30)
            self._single_lane_right_frames = max(self._single_lane_right_frames - 1, 0)
        elif lane_visibility == "RIGHT_ONLY":
            self._single_lane_right_frames = min(self._single_lane_right_frames + 1, 30)
            self._single_lane_left_frames = max(self._single_lane_left_frames - 1, 0)
        else:
            self._single_lane_left_frames = max(self._single_lane_left_frames - 1, 0)
            self._single_lane_right_frames = max(self._single_lane_right_frames - 1, 0)
        single_lane_view = lane_visibility != "BOTH"
        if single_lane_view:
            self._single_lane_frame_count = getattr(self, "_single_lane_frame_count", 0) + 1
            self._single_lane_release_tail = self.single_lane_release_hold_frames
        else:
            self._single_lane_frame_count = 0
            if self._single_lane_release_tail > 0:
                self._single_lane_release_tail -= 1
            self._straight_settle_frames = 0
        if lane_visibility == "BOTH":
            self._recent_both_lane_frames = self.curve_release_recent_frames
        elif self._recent_both_lane_frames > 0:
            self._recent_both_lane_frames -= 1

        if left_detected and left_fit is None:
            left_fit = np.polyfit(lefty, leftx, 2)
        if right_detected and right_fit is None:
            right_fit = np.polyfit(righty, rightx, 2)
        if left_fit is None and right_fit is not None:
            expected = self.config.expected_lane_width
            left_fit = (right_fit[0], right_fit[1], right_fit[2] - expected)
        if right_fit is None and left_fit is not None:
            expected = self.config.expected_lane_width
            right_fit = (left_fit[0], left_fit[1], left_fit[2] + expected)
        if left_fit is None or right_fit is None:
            return self._result(
                None,
                "NO_LANE",
                False,
                0.0,
                curve_hint="UNKNOWN",
                curve_scope="UNKNOWN",
                curve_phase="STRAIGHT",
                lane_visibility=lane_visibility,
            )

        (
            offset_norm,
            offset_px,
            offset_cm,
            lane_width_px,
        ) = self._compute_offset_metrics(left_fit, right_fit, warped.shape[1])
        if lane_visibility == "BOTH" and offset_norm is not None:
            self._last_curve_offset = offset_norm

        startup_guard_active = self.frame_counter <= self.lane_startup_guard_frames
        if startup_guard_active and lane_visibility != "BOTH":
            offset_norm = 0.0
            offset_px = 0.0
            if offset_cm is not None:
                offset_cm = 0.0
        elif lane_visibility != "BOTH":
            stored = self._last_full_offsets
            if stored["norm"] is None:
                self._last_full_offsets["norm"] = offset_norm
                self._last_full_offsets["px"] = offset_px
                self._last_full_offsets["cm"] = offset_cm
            else:
                stored_norm = stored["norm"]
                decay = 0.988
                guard = self.curve_offset_guard
                extra_decay = decay
                if stored_norm is not None and guard > 0.0:
                    mag = abs(stored_norm)
                    if mag > guard * 2.0:
                        extra_decay *= 0.985
                    if mag > guard * 4.0:
                        extra_decay *= 0.96
                    if mag > guard * 6.0:
                        extra_decay *= 0.92
                if stored_norm is None:
                    offset_norm = 0.0
                    scale = 0.0
                else:
                    offset_norm = stored_norm * extra_decay
                    clamp_limit = guard * 10.0 if guard > 0.0 else None
                    if clamp_limit is not None and clamp_limit > 0.0:
                        offset_norm = max(min(offset_norm, clamp_limit), -clamp_limit)
                    scale = (
                        offset_norm / stored_norm
                        if abs(stored_norm) > 1e-6
                        else extra_decay
                    )
                offset_px = stored["px"] * scale if stored["px"] is not None else None
                offset_cm = stored["cm"] * scale if stored["cm"] is not None else None
            if (offset_norm is None or abs(offset_norm) < guard * 1.1) and self._last_curve_offset not in (None, 0.0):
                offset_norm = self._last_curve_offset
                if offset_px is not None:
                    offset_px = math.copysign(abs(offset_px), offset_norm)
                if offset_cm is not None:
                    offset_cm = math.copysign(abs(offset_cm), offset_norm)
            self._single_lane_active = True
            self._single_lane_offsets = {"norm": offset_norm, "px": offset_px, "cm": offset_cm}
            self._single_lane_decay_frames = 0
        else:
            if self._single_lane_active and offset_norm is not None:
                previous = self._single_lane_offsets
                blend = 0.35
                if previous["norm"] is not None:
                    offset_norm = (1.0 - blend) * offset_norm + blend * previous["norm"]
                if previous["px"] is not None and offset_px is not None:
                    offset_px = (1.0 - blend) * offset_px + blend * previous["px"]
                if previous["cm"] is not None and offset_cm is not None:
                    offset_cm = (1.0 - blend) * offset_cm + blend * previous["cm"]
            self._single_lane_active = False
            self._last_full_offsets["norm"] = offset_norm
            self._last_full_offsets["px"] = offset_px
            self._last_full_offsets["cm"] = offset_cm
            self._single_lane_decay_frames = 0
            self._single_lane_offsets = {"norm": offset_norm, "px": offset_px, "cm": offset_cm}

        release_context_active = (self._single_lane_release_tail > 0) and not single_lane_view

        if release_context_active and offset_norm is not None:
            scale = 0.85 if single_lane_view else 0.92
            offset_norm *= scale
            offset_px *= scale
            if offset_cm is not None:
                offset_cm *= scale
            limit = self.single_lane_offset_limit
            if not single_lane_view:
                limit *= 1.2
            if abs(offset_norm) > limit:
                clamp_scale = limit / max(abs(offset_norm), 1e-4)
                offset_norm *= clamp_scale
                if offset_px is not None:
                    offset_px *= clamp_scale
                if offset_cm is not None:
                    offset_cm *= clamp_scale

        lane_state = self._classify_lane_state(offset_norm)
        confidence = self._compute_confidence(leftx, rightx, lefty, righty, left_fit, right_fit)
        # Stop-line detection is temporarily disabled; misfires were halting LKAS in curves.
        stop_detected = False

        curve_hint, curve_scope = self._classify_curve(left_fit, right_fit, lane_visibility, offset_norm)
        sticky_curve = self._curve_hint_sticky
        if lane_visibility != "BOTH":
            guard = self.curve_offset_guard
            sticky_single_override = False
            if sticky_curve in ("LEFT_CURVE", "RIGHT_CURVE") and offset_norm is not None:
                sticky_guard = guard * max(self.single_lane_curve_infer_offset_scale * 0.8, 1.0)
                sticky_same_side = (
                    sticky_curve == "LEFT_CURVE" and offset_norm < -sticky_guard
                ) or (
                    sticky_curve == "RIGHT_CURVE" and offset_norm > sticky_guard
                )
                if sticky_same_side:
                    curve_hint = sticky_curve
                    curve_scope = "STICKY_SINGLE"
                    sticky_single_override = True
            if not sticky_single_override:
                infer_frames = 0
                infer_dir: str | None = None
                if lane_visibility == "LEFT_ONLY":
                    infer_frames = self._single_lane_left_frames
                    infer_dir = "LEFT_CURVE"
                elif lane_visibility == "RIGHT_ONLY":
                    infer_frames = self._single_lane_right_frames
                    infer_dir = "RIGHT_CURVE"
                if infer_dir and infer_frames >= self.single_lane_curve_infer_frames and offset_norm is not None:
                    offset_limit = guard * self.single_lane_curve_infer_offset_scale
                    same_side = (
                        (infer_dir == "LEFT_CURVE" and offset_norm < -offset_limit)
                        or (infer_dir == "RIGHT_CURVE" and offset_norm > offset_limit)
                    )
                    sticky_conflict = (
                        sticky_curve in ("LEFT_CURVE", "RIGHT_CURVE") and sticky_curve != infer_dir
                    )
                    if same_side and not sticky_conflict:
                        curve_hint = infer_dir
                        curve_scope = "VISIBILITY"
        elif sticky_curve in ("LEFT_CURVE", "RIGHT_CURVE") and offset_norm is not None:
            guard = self.curve_offset_guard * max(self.single_lane_curve_infer_offset_scale * 0.8, 1.1)
            sticky_same_side = (
                sticky_curve == "LEFT_CURVE" and offset_norm < -guard
            ) or (
                sticky_curve == "RIGHT_CURVE" and offset_norm > guard
            )
            if sticky_same_side and curve_hint != sticky_curve:
                curve_hint = sticky_curve
                curve_scope = "STICKY"
        guard = self.curve_offset_guard
        if (
            curve_hint == "STRAIGHT"
            and guard > 0.0
            and offset_norm is not None
            and abs(offset_norm) >= guard * 2.0
        ):
            curve_hint = "RIGHT_CURVE" if offset_norm > 0.0 else "LEFT_CURVE"
            curve_scope = "OFFSET"
        curve_hint = self._stabilize_curve_hint(curve_hint)
        abs_offset = abs(offset_norm) if offset_norm is not None else None
        detected_turning = curve_hint in ("LEFT_CURVE", "RIGHT_CURVE")
        if detected_turning and not self._prev_detected_turning:
            self._curve_entry_hold_active = True
            self._curve_entry_hold_elapsed = 0
        elif not detected_turning:
            self._curve_entry_hold_active = False
            self._curve_entry_hold_elapsed = 0
            self._curve_entry_hold_limited_frames = 0
        self._prev_detected_turning = detected_turning

        if single_lane_view and self._curve_hint_sticky in ("LEFT_CURVE", "RIGHT_CURVE"):
            curve_hint = self._curve_hint_sticky
            curve_scope = "NEAR"

        hold_active = self._curve_entry_hold_active and detected_turning
        if hold_active:
            self._curve_entry_hold_elapsed += 1
            limit = self.curve_offset_guard * self.curve_entry_hold_guard_scale
            limited_view = lane_visibility != "BOTH"
            if limited_view:
                self._curve_entry_hold_limited_frames += 1
            else:
                self._curve_entry_hold_limited_frames = 0
            large_offset = abs_offset is None or abs_offset > limit
            must_hold = self._curve_entry_hold_elapsed <= self.curve_entry_hold_min_frames and not (limited_view or large_offset)
            exceeded_max = self._curve_entry_hold_elapsed >= self.curve_entry_hold_max_frames
            if must_hold and not exceeded_max:
                curve_hint = "STRAIGHT"
                curve_scope = "ENTRY_HOLD"
            else:
                self._curve_entry_hold_active = False
        else:
            self._curve_entry_hold_elapsed = 0
            self._curve_entry_hold_limited_frames = 0
        turning_now = curve_hint in ("LEFT_CURVE", "RIGHT_CURVE")
        if turning_now:
            self._curve_turn_frame_count = min(
                self._curve_turn_frame_count + 1,
                self.curve_late_boost_start_frames + self.curve_late_boost_ramp_frames + 12,
            )
        else:
            self._curve_turn_frame_count = 0
        if (
            turning_now
            and offset_norm is not None
            and self._curve_turn_frame_count >= self.curve_late_boost_start_frames
        ):
            frames_into_boost = self._curve_turn_frame_count - self.curve_late_boost_start_frames
            ramp = min(
                frames_into_boost / max(self.curve_late_boost_ramp_frames, 1),
                1.0,
            )
            limit = self.curve_offset_guard * self.curve_late_boost_offset_cap_scale
            abs_before = abs(offset_norm)
            if abs_before < limit:
                headroom = max(limit - abs_before, 0.0) / max(limit, 1e-4)
                boost = 1.0 + (self.curve_late_boost_gain - 1.0) * min(ramp, headroom)
                offset_norm *= boost
                if offset_px is not None:
                    offset_px *= boost
                if offset_cm is not None:
                    offset_cm *= boost
        abs_offset = abs(offset_norm) if offset_norm is not None else None
        curve_phase = self._update_curve_phase(curve_hint, lane_visibility, offset_norm)
        guard = self.curve_offset_guard
        both_lanes_visible = lane_visibility == "BOTH"
        lanes_recently_visible = both_lanes_visible or self._recent_both_lane_frames > 0
        candidate_condition_met = (
            lanes_recently_visible
            and abs_offset is not None
            and abs_offset <= guard * 1.05
        )
        if candidate_condition_met:
            self._release_candidate_counter = min(
                self._release_candidate_counter + 1, self.curve_release_confirm_frames
            )
        elif self._release_candidate_counter > 0:
            self._release_candidate_counter -= 1

        release_offset_limit = guard * 0.95
        release_allowed = (
            lanes_recently_visible
            and offset_norm is not None
            and abs_offset is not None
            and abs_offset <= release_offset_limit
            and self._release_candidate_counter >= self.curve_release_confirm_frames
        )

        if (
            curve_hint in ("LEFT_CURVE", "RIGHT_CURVE")
            and release_allowed
        ):
            self._curve_release_counter += 1
            if self._curve_release_counter >= self.curve_release_confirm_frames:
                curve_hint = "STRAIGHT"
                curve_phase = "CURVE_RELEASE"
                self._curve_hint_sticky = "STRAIGHT"
                self._curve_hint_pending = None
                self._curve_hint_pending_count = 0
        else:
            self._curve_release_counter = 0
            if not lanes_recently_visible and self._release_candidate_counter > 0:
                self._release_candidate_counter -= 1
        override_curve: str | None = None
        override_phase: str | None = None
        sticky_curve = self._curve_hint_sticky
        straight_settled = self._straight_settle_frames >= 3
        if curve_hint == "STRAIGHT":
            self._straight_settle_frames += 1
        else:
            self._straight_settle_frames = 0

        if curve_hint == "STRAIGHT" and offset_norm is not None and straight_settled:
            override_curve = None

        allow_centering = (
            lane_visibility == "BOTH"
            and offset_norm is not None
            and offset_px is not None
            and (
                (curve_phase == "STRAIGHT" and not release_context_active)
                or (curve_phase == "CURVE_RELEASE")
            )
        )

        if allow_centering:
            decay = 1.0 - self.straight_centering_alpha
            if curve_phase == "CURVE_RELEASE":
                decay = 1.0 - (self.straight_centering_alpha * 1.5)
                decay = max(0.0, decay)
            offset_norm *= decay
            offset_px *= decay
            if offset_cm is not None:
                offset_cm *= decay

            safe_band_norm = self._compute_safe_band(offset_cm)
            if abs(offset_norm) > safe_band_norm:
                overshoot = abs(offset_norm) - safe_band_norm
                push_mag = min(self.lane_center_push_gain, overshoot * 0.5)
                push = push_mag * np.sign(offset_norm)
                offset_norm -= push
                offset_px -= push * (self.frame_width * 0.5)
                if offset_cm is not None:
                    if self.calibration is not None and self.calibration.cm_per_pixel is not None:
                        offset_cm -= push * (self.frame_width * 0.5) * self.calibration.cm_per_pixel
                    else:
                        offset_cm -= push * (safe_band_norm * 100.0)

            self._last_full_offsets["norm"] = offset_norm
            self._last_full_offsets["px"] = offset_px
            self._last_full_offsets["cm"] = offset_cm

        return {
            "offset": offset_norm,
            "offset_px": offset_px,
            "offset_cm": offset_cm,
            "lane_width_px": lane_width_px,
            "lane_state": lane_state,
            "stop_detected": stop_detected,
            "confidence": confidence,
            "curve_hint": curve_hint,
            "curve_scope": curve_scope,
            "curve_phase": curve_phase,
            "lane_visibility": lane_visibility,
            "release_debug": {
                "both_lanes": both_lanes_visible,
                "recent_both_lanes": self._recent_both_lane_frames,
                "abs_offset": abs_offset,
                "guard": guard,
                "candidate_counter": self._release_candidate_counter,
                "release_counter": self._curve_release_counter,
                "release_allowed": release_allowed,
                "single_lane_view": single_lane_view,
            },
        }

    def _find_lane_bases(self, histogram: np.ndarray) -> Tuple[int | None, int | None]:
        """Identify initial left/right lane base positions from histogram peaks."""
        midpoint = histogram.shape[0] // 2
        left_hist = histogram[:midpoint]
        right_hist = histogram[midpoint:]

        leftx_base = np.argmax(left_hist) if np.max(left_hist) > 0 else None
        rightx_offset = np.argmax(right_hist) if np.max(right_hist) > 0 else None
        rightx_base = (rightx_offset + midpoint) if rightx_offset is not None else None

        expected = int(round(self.config.expected_lane_width))
        if leftx_base is None and rightx_base is not None:
            leftx_base = max(0, rightx_base - expected)
        elif rightx_base is None and leftx_base is not None:
            rightx_base = min(histogram.shape[0] - 1, leftx_base + expected)

        return leftx_base, rightx_base

    def _sliding_window_fit(
        self, warped: np.ndarray, leftx_base: int, rightx_base: int
    ) -> Tuple[
        Tuple[float, float, float] | None,
        Tuple[float, float, float] | None,
        np.ndarray,
        np.ndarray,
        np.ndarray,
        np.ndarray,
    ]:
        """Run a vertical sliding window search to collect lane pixels and fit polynomials."""
        config = self.config
        nonzero = warped.nonzero()
        nonzeroy = np.array(nonzero[0])
        nonzerox = np.array(nonzero[1])

        left_current = leftx_base
        right_current = rightx_base
        window_height = warped.shape[0] // config.n_windows

        left_lane_inds: List[np.ndarray] = []
        right_lane_inds: List[np.ndarray] = []

        for window in range(config.n_windows):
            win_y_low = warped.shape[0] - (window + 1) * window_height
            win_y_high = warped.shape[0] - window * window_height

            win_xleft_low = left_current - config.margin
            win_xleft_high = left_current + config.margin
            win_xright_low = right_current - config.margin
            win_xright_high = right_current + config.margin

            good_left_inds = np.where(
                (nonzeroy >= win_y_low)
                & (nonzeroy < win_y_high)
                & (nonzerox >= win_xleft_low)
                & (nonzerox < win_xleft_high)
            )[0]
            good_right_inds = np.where(
                (nonzeroy >= win_y_low)
                & (nonzeroy < win_y_high)
                & (nonzerox >= win_xright_low)
                & (nonzerox < win_xright_high)
            )[0]

            left_lane_inds.append(good_left_inds)
            right_lane_inds.append(good_right_inds)

            if len(good_left_inds) > config.minpix:
                left_current = int(np.mean(nonzerox[good_left_inds]))
            if len(good_right_inds) > config.minpix:
                right_current = int(np.mean(nonzerox[good_right_inds]))

        left_lane_inds_concat = np.concatenate(left_lane_inds) if left_lane_inds else np.array([], dtype=int)
        right_lane_inds_concat = np.concatenate(right_lane_inds) if right_lane_inds else np.array([], dtype=int)

        leftx = nonzerox[left_lane_inds_concat]
        lefty = nonzeroy[left_lane_inds_concat]
        rightx = nonzerox[right_lane_inds_concat]
        righty = nonzeroy[right_lane_inds_concat]

        left_fit = np.polyfit(lefty, leftx, 2) if len(leftx) >= 3 else None
        right_fit = np.polyfit(righty, rightx, 2) if len(rightx) >= 3 else None

        return left_fit, right_fit, leftx, lefty, rightx, righty

    def _compute_offset_metrics(
        self, left_fit: Tuple[float, float, float], right_fit: Tuple[float, float, float], width: int
    ) -> Tuple[float | None, float | None, float | None, float | None]:
        """Compute lateral offset in normalised units, pixels, and centimeters."""
        y_eval = self.frame_height - 1
        x_left = left_fit[0] * y_eval**2 + left_fit[1] * y_eval + left_fit[2]
        x_right = right_fit[0] * y_eval**2 + right_fit[1] * y_eval + right_fit[2]
        lane_center = (x_left + x_right) / 2.0
        frame_center = width / 2.0
        lane_width = x_right - x_left
        if frame_center == 0:
            return None, None, None, None
        offset_px = lane_center - frame_center
        offset_norm = offset_px / frame_center
        offset_cm = None
        if self.calibration is not None:
            offset_cm = float(offset_px * self.calibration.cm_per_pixel)
        return float(offset_norm), float(offset_px), offset_cm, float(lane_width)

    @staticmethod
    def _classify_lane_state(offset: float | None) -> str:
        """Classify qualitative lane position from lateral offset."""
        if offset is None:
            return "NO_LANE"
        if offset < -0.1:
            return "LEFT_DEVIATION"
        if offset > 0.1:
            return "RIGHT_DEVIATION"
        return "CENTERED"

    def _compute_confidence(
        self,
        leftx: np.ndarray,
        rightx: np.ndarray,
        lefty: np.ndarray,
        righty: np.ndarray,
        left_fit: Tuple[float, float, float],
        right_fit: Tuple[float, float, float],
    ) -> float:
        """Estimate confidence using pixel coverage and lane width consistency."""
        config = self.config
        min_pixels = config.n_windows * config.minpix
        coverage = min(len(leftx), len(rightx)) / max(min_pixels, 1)
        coverage = float(np.clip(coverage, 0.0, 1.0))

        y_eval = self.frame_height - 1
        x_left = left_fit[0] * y_eval**2 + left_fit[1] * y_eval + left_fit[2]
        x_right = right_fit[0] * y_eval**2 + right_fit[1] * y_eval + right_fit[2]
        lane_width = x_right - x_left
        if lane_width <= 0:
            width_score = 0.0
        else:
            expected = config.expected_lane_width
            width_score = 1.0 - abs(lane_width - expected) / expected
            width_score = float(np.clip(width_score, 0.0, 1.0))

        confidence = 0.6 * coverage + 0.4 * width_score
        return float(np.clip(confidence, 0.0, 1.0))

    def _detect_stop_line(self, binary_img: np.ndarray) -> bool:
        """Detect stop line segments in the bottom 20 percent of the binary image."""
        height = binary_img.shape[0]
        start_row = int(height * 0.8)
        roi = binary_img[start_row:, :]
        if roi.size == 0:
            return False

        # Enhance horizontal structures before contour detection.
        kernel = np.ones((3, 15), dtype=np.uint8)
        processed = cv2.morphologyEx(roi, cv2.MORPH_CLOSE, kernel)
        contours, _ = cv2.findContours(processed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        for cnt in contours:
            _, _, w, h = cv2.boundingRect(cnt)
            if w >= 100 and h <= 60:
                return True
        return False

    def _classify_curve(
        self,
        left_fit: Tuple[float, float, float],
        right_fit: Tuple[float, float, float],
        lane_visibility: str,
        offset_norm: float | None,
    ) -> Tuple[str, str]:
        """Classify curvature using a near-field first approach and share the scope."""
        if left_fit is None or right_fit is None:
            return "UNKNOWN", "UNKNOWN"

        if self.frame_counter <= self.curve_warmup_frames:
            return "STRAIGHT", "SUPPRESSED"

        if lane_visibility == "BOTH" and offset_norm is not None and abs(offset_norm) < self.curve_offset_guard:
            return "STRAIGHT", "SUPPRESSED"

        y_bottom = self.frame_height - 1
        y_near = int(self.frame_height * self.curve_near_top_ratio)
        y_far = int(self.frame_height * self.curve_far_top_ratio)
        y_near = min(max(y_near, 0), y_bottom)
        y_far = min(max(y_far, 0), y_bottom)

        def eval_poly(coeffs: Tuple[float, float, float], y_val: int) -> float:
            return coeffs[0] * y_val**2 + coeffs[1] * y_val + coeffs[2]

        x_left_bottom = eval_poly(left_fit, y_bottom)
        x_right_bottom = eval_poly(right_fit, y_bottom)
        x_left_near = eval_poly(left_fit, y_near)
        x_right_near = eval_poly(right_fit, y_near)
        x_left_far = eval_poly(left_fit, y_far)
        x_right_far = eval_poly(right_fit, y_far)

        delta_left_near = x_left_near - x_left_bottom
        delta_right_near = x_right_near - x_right_bottom
        avg_delta_near = (delta_left_near + delta_right_near) / 2.0

        delta_left_far = x_left_far - x_left_bottom
        delta_right_far = x_right_far - x_right_bottom
        avg_delta_far = (delta_left_far + delta_right_far) / 2.0

        near_threshold = max(self.frame_width * 0.0028, 2.2)
        far_threshold = max(self.frame_width * 0.0055, 4.0)
        if lane_visibility != "BOTH":
            near_threshold = max(near_threshold * 0.4, 1.2)
            far_threshold = max(far_threshold * 0.45, 2.2)

        if abs(avg_delta_near) >= near_threshold:
            return ("RIGHT_CURVE", "NEAR") if avg_delta_near > 0 else ("LEFT_CURVE", "NEAR")

        if abs(avg_delta_far) >= far_threshold:
            return ("RIGHT_CURVE", "FAR") if avg_delta_far > 0 else ("LEFT_CURVE", "FAR")

        return "STRAIGHT", "NONE"

    def _update_curve_phase(self, curve_hint: str, lane_visibility: str, offset_norm: float | None) -> str:
        turning = curve_hint in ("LEFT_CURVE", "RIGHT_CURVE")
        single_lane = lane_visibility != "BOTH"
        offset_mag = abs(offset_norm) if offset_norm is not None else 0.0
        phase = self.curve_phase_state

        pre_threshold = self.curve_offset_guard * (0.4 if single_lane else 0.55)
        if turning:
            if offset_mag < pre_threshold:
                phase = "CURVE_PRE"
            else:
                phase = "CURVE_ACTIVE"
        else:
            if self._single_lane_active or self._single_lane_decay_frames > 0:
                phase = "CURVE_RELEASE"
            else:
                phase = "STRAIGHT"

        if phase == "CURVE_RELEASE":
            if not self._single_lane_active and offset_mag < 0.01 and not turning:
                phase = "STRAIGHT"

        self.curve_phase_state = phase
        return phase

    def _stabilize_curve_hint(self, new_hint: str) -> str:
        """Apply hysteresis to curve classification so it doesn't flip every frame."""
        sticky = self._curve_hint_sticky
        if new_hint == sticky:
            self._curve_hint_pending = None
            self._curve_hint_pending_count = 0
            return sticky

        if new_hint not in ("LEFT_CURVE", "RIGHT_CURVE"):
            if sticky in ("LEFT_CURVE", "RIGHT_CURVE"):
                self._curve_hint_pending = None
                self._curve_hint_pending_count = 0
                return sticky
            self._curve_hint_sticky = "STRAIGHT"
            self._curve_hint_pending = None
            self._curve_hint_pending_count = 0
            return "STRAIGHT"

        if new_hint in ("LEFT_CURVE", "RIGHT_CURVE"):
            if sticky in ("LEFT_CURVE", "RIGHT_CURVE") and sticky != new_hint:
                if self._curve_hint_pending == new_hint:
                    self._curve_hint_pending_count += 1
                else:
                    self._curve_hint_pending = new_hint
                    self._curve_hint_pending_count = 1

                if self._curve_hint_pending_count >= self.curve_hint_switch_frames:
                    self._curve_hint_sticky = new_hint
                    self._curve_hint_pending = None
                    self._curve_hint_pending_count = 0
                    return new_hint
                return sticky

            self._curve_hint_sticky = new_hint
            self._curve_hint_pending = None
            self._curve_hint_pending_count = 0
            return new_hint

        # STRAIGHT only overrides once hysteresis is satisfied.
        if sticky in ("LEFT_CURVE", "RIGHT_CURVE"):
            return sticky
        self._curve_hint_sticky = "STRAIGHT"
        self._curve_hint_pending = None
        self._curve_hint_pending_count = 0
        return "STRAIGHT"

    def _compute_safe_band(self, offset_cm: float | None) -> float:
        safe_band = self.lane_center_safe_band
        if offset_cm is None or self.calibration is None:
            return safe_band
        lane_width_cm = getattr(self.calibration, "lane_width_cm", None)
        if not lane_width_cm or lane_width_cm <= 0.0:
            return safe_band
        lane_half_cm = lane_width_cm * 0.5
        allowable = max(
            0.0,
            lane_half_cm - (self.vehicle_width_cm * 0.5) - self.vehicle_margin_cm,
        )
        if lane_half_cm <= 0.0:
            return safe_band
        usable_ratio = allowable / lane_half_cm
        usable_ratio = max(0.01, min(usable_ratio, 0.2))
        return min(safe_band, usable_ratio)

    @staticmethod
    def _result(
        offset: float | None,
        lane_state: str,
        stop_detected: bool,
        confidence: float,
        offset_px: float | None = None,
        offset_cm: float | None = None,
        lane_width_px: float | None = None,
        curve_hint: str | None = None,
        curve_scope: str | None = None,
        curve_phase: str | None = None,
        lane_visibility: str | None = None,
    ) -> Dict[str, float | bool | None]:
        """Helper for formatting analyser results when detection fails."""
        return {
            "offset": offset,
            "offset_px": offset_px,
            "offset_cm": offset_cm,
            "lane_state": lane_state,
            "stop_detected": stop_detected,
            "confidence": confidence,
            "lane_width_px": lane_width_px,
            "curve_hint": curve_hint,
            "curve_scope": curve_scope,
            "curve_phase": curve_phase,
            "lane_visibility": lane_visibility,
        }

    def _compute_perspective_matrix(self) -> np.ndarray:
        """Derive a warp matrix scaled to the configured frame size."""
        src_pts = np.copy(SRC_POINT_RATIOS)
        dst_pts = np.copy(DST_POINT_RATIOS)
        src_pts[:, 0] *= self.frame_width
        src_pts[:, 1] *= self.frame_height
        dst_pts[:, 0] *= self.frame_width
        dst_pts[:, 1] *= self.frame_height
        return cv2.getPerspectiveTransform(src_pts, dst_pts)
