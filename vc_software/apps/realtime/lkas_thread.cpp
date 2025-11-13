#include "shared.h"
#include "vc_common.h"
#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cctype>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <system_error>
#include <string>

namespace {

struct VisionSample {
    double offset_norm = 0.0;
    double offset_cm = 0.0;
    double confidence = 0.0;
    bool stop_detected = false;
    bool has_offset_norm = false;
    bool has_offset_cm = false;
    bool has_confidence = false;
    bool has_stop = false;
    std::string curve_hint;
    bool has_curve_hint = false;
    std::string curve_scope;
    bool has_curve_scope = false;
    std::string lane_visibility;
    bool has_lane_visibility = false;
    std::string curve_phase;
    bool has_curve_phase = false;
};

struct CurveHoldState {
    int right_hold_frames = 0;
    int right_hold_frames_max = 0;
    bool last_right_near = true;
    double right_anchor_offset_cm = 0.0;
    int right_release_guard = 0;
};

CurveHoldState g_curve_hold_state;
static int g_launch_frames_remaining = LKAS_LAUNCH_BOOST_FRAMES;
struct OffsetFilterState {
    double value = 0.0;
    bool initialized = false;
};
OffsetFilterState g_offset_filter_state;
static double g_last_offset_sample = 0.0;
static bool g_has_last_offset_sample = false;
static int g_curve_stall_frames = 0;

namespace fs = std::filesystem;

void set_world_writable(const fs::path& path) {
    std::error_code ec;
    fs::file_status status = fs::status(path, ec);
    if (ec) {
        std::cerr << "[lkas] failed to stat " << path << ": " << ec.message() << "\n";
        return;
    }

    auto perms =
        fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::group_write
        | fs::perms::others_read | fs::perms::others_write;
    if (fs::is_directory(status)) {
        perms |= fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec;
    }

    ec.clear();
    fs::permissions(path, perms, fs::perm_options::replace, ec);
    if (ec) {
        std::cerr << "[lkas] failed to set permissions for " << path << ": " << ec.message() << "\n";
    }
}

void write_latest_marker(const fs::path& dir, const fs::path& latest) {
    try {
        fs::path marker = dir / "lkas_latest.txt";
        std::ofstream meta(marker, std::ios::trunc);
        if (meta) {
            meta << latest.string() << "\n";
        }
        set_world_writable(marker);
    } catch (const std::exception& exc) {
        std::cerr << "[lkas] failed to write latest marker: " << exc.what() << "\n";
    }
}

std::ofstream open_log_stream() {
    std::ofstream stream;
    try {
        fs::path dir(LKAS_JOY_LOG_DIR);
        if (!dir.empty()) {
            fs::create_directories(dir);
            set_world_writable(dir);
        }
        try {
            for (const auto& entry : fs::directory_iterator(dir)) {
                if (entry.is_regular_file() && entry.path().filename().string().find(LKAS_JOY_LOG_PREFIX) == 0) {
                    fs::remove(entry.path());
                }
            }
            set_world_writable(dir);
        } catch (const std::exception& exc) {
            std::cerr << "[lkas] failed to clean log directory: " << exc.what() << "\n";
        }
        fs::path log_path = dir / (std::string(LKAS_JOY_LOG_PREFIX) + "_latest.csv");

        stream.open(log_path, std::ios::trunc);
        if (!stream) {
            std::perror("[lkas] joy log open");
            return stream;
        }
        stream << "timestamp_ms,offset_cm,offset_norm,confidence,stop_detected,steer_cmd,throttle_cmd,source\n";
        set_world_writable(log_path);
        write_latest_marker(dir, log_path);
    } catch (const std::exception& exc) {
        std::cerr << "[lkas] joy log setup failed: " << exc.what() << "\n";
    }
    return stream;
}

void write_log_entry(
    std::ofstream* stream,
    uint64_t timestamp_ms,
    double offset_cm,
    const VisionSample* sample,
    int steer,
    int throttle,
    const char* source) {
    if (stream == nullptr || !stream->is_open()) {
        return;
    }

    auto write_double = [&](double value) {
        if (std::isfinite(value)) {
            (*stream) << value;
        } else {
            (*stream) << "nan";
        }
    };

    (*stream) << timestamp_ms << ",";
    write_double(offset_cm);
    (*stream) << ",";
    if (sample && sample->has_offset_norm) {
        write_double(sample->offset_norm);
    } else {
        (*stream) << "nan";
    }
    (*stream) << ",";
    if (sample && sample->has_confidence) {
        write_double(sample->confidence);
    } else {
        (*stream) << "nan";
    }
    (*stream) << ",";
    if (sample && sample->has_stop) {
        (*stream) << (sample->stop_detected ? 1 : 0);
    } else {
        (*stream) << "nan";
    }
    (*stream) << "," << steer << "," << throttle << ",";
    if (source != nullptr) {
        (*stream) << source;
    } else {
        (*stream) << "vision";
    }
    (*stream) << "\n";
    stream->flush();
}

bool extract_number(const std::string& payload, const std::string& key, double& value) {
    const std::string token = "\"" + key + "\"";
    size_t pos = payload.find(token);
    if (pos == std::string::npos) {
        return false;
    }
    pos = payload.find(':', pos + token.size());
    if (pos == std::string::npos) {
        return false;
    }
    ++pos;
    while (pos < payload.size() && std::isspace(static_cast<unsigned char>(payload[pos]))) {
        ++pos;
    }
    size_t end = pos;
    while (end < payload.size()) {
        char ch = payload[end];
        if ((ch >= '0' && ch <= '9') || ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E') {
            ++end;
        } else {
            break;
        }
    }
    try {
        value = std::stod(payload.substr(pos, end - pos));
        return true;
    } catch (...) {
        return false;
    }
}

bool extract_bool(const std::string& payload, const std::string& key, bool& value) {
    const std::string token = "\"" + key + "\"";
    size_t pos = payload.find(token);
    if (pos == std::string::npos) {
        return false;
    }
    pos = payload.find(':', pos + token.size());
    if (pos == std::string::npos) {
        return false;
    }
    ++pos;
    while (pos < payload.size() && std::isspace(static_cast<unsigned char>(payload[pos]))) {
        ++pos;
    }
    if (payload.compare(pos, 4, "true") == 0) {
        value = true;
        return true;
    }
    if (payload.compare(pos, 5, "false") == 0) {
        value = false;
        return true;
    }
    return false;
}

bool extract_string(const std::string& payload, const std::string& key, std::string& value) {
    const std::string token = "\"" + key + "\"";
    size_t pos = payload.find(token);
    if (pos == std::string::npos) {
        return false;
    }
    pos = payload.find(':', pos + token.size());
    if (pos == std::string::npos) {
        return false;
    }
    ++pos;
    while (pos < payload.size() && std::isspace(static_cast<unsigned char>(payload[pos]))) {
        ++pos;
    }
    if (pos >= payload.size() || payload[pos] != '"') {
        return false;
    }
    ++pos;
    size_t end = pos;
    while (end < payload.size()) {
        if (payload[end] == '"') {
            break;
        }
        if (payload[end] == '\\' && end + 1 < payload.size()) {
            end += 2;
        } else {
            ++end;
        }
    }
    if (end >= payload.size()) {
        return false;
    }
    value = payload.substr(pos, end - pos);
    return true;
}

bool parse_sample(const char* msg, VisionSample& out) {
    std::string payload(msg);
    bool parsed = false;

    double value = 0.0;
    if (extract_number(payload, "offset_cm", value)) {
        out.offset_cm = value;
        out.has_offset_cm = true;
        parsed = true;
    }
    if (extract_number(payload, "offset", value)) {
        out.offset_norm = value;
        out.has_offset_norm = true;
        parsed = true;
    }
    if (extract_number(payload, "confidence", value)) {
        out.confidence = value;
        out.has_confidence = true;
        parsed = true;
    }
    bool bool_value = false;
    if (extract_bool(payload, "stop_detected", bool_value)) {
        out.stop_detected = bool_value;
        out.has_stop = true;
        parsed = true;
    }
    std::string str_value;
    if (extract_string(payload, "curve_hint", str_value)) {
        out.curve_hint = str_value;
        out.has_curve_hint = true;
        parsed = true;
    }
    if (extract_string(payload, "curve_scope", str_value)) {
        out.curve_scope = str_value;
        out.has_curve_scope = true;
        parsed = true;
    }
    if (extract_string(payload, "curve_phase", str_value)) {
        out.curve_phase = str_value;
        out.has_curve_phase = true;
        parsed = true;
    }
    if (extract_string(payload, "lane_visibility", str_value)) {
        out.lane_visibility = str_value;
        out.has_lane_visibility = true;
        parsed = true;
    }
    return parsed;
}

double resolve_offset_cm(const VisionSample& sample) {
    if (sample.has_offset_cm) {
        return sample.offset_cm;
    }
    if (sample.has_offset_norm) {
        return sample.offset_norm * LKAS_VISION_DEFAULT_LANE_WIDTH_CM;
    }
    return 0.0;
}

int clamp_joy_value(int value) {
    return std::clamp(value, 0, 99);
}

int compute_steer_command(double offset_cm) {
    offset_cm = std::clamp(offset_cm, -static_cast<double>(LKAS_MAX_OFFSET_CM), static_cast<double>(LKAS_MAX_OFFSET_CM));
    double steer = static_cast<double>(LKAS_JOY_CENTER) - offset_cm * static_cast<double>(LKAS_STEER_GAIN_PER_CM);
    return clamp_joy_value(static_cast<int>(std::lround(steer)));
}

int compute_throttle_command(const VisionSample& sample) {
    if (sample.has_stop && sample.stop_detected) {
        return LKAS_THROTTLE_STOP;
    }
    double confidence = sample.has_confidence ? sample.confidence : 0.0;
    confidence = std::clamp(confidence, 0.0, 1.0);
    if (confidence < LKAS_CONFIDENCE_THRESHOLD) {
        return LKAS_THROTTLE_MIN_CMD;
    }
    double span = static_cast<double>(LKAS_THROTTLE_BASE_CMD - LKAS_THROTTLE_MIN_CMD);
    double throttle = static_cast<double>(LKAS_THROTTLE_MIN_CMD) + span * confidence;
    return std::clamp(static_cast<int>(std::lround(throttle)), LKAS_THROTTLE_MIN_CMD, 99);
}

void apply_failsafe(std::ofstream* log_stream, uint64_t timestamp_ms) {
    int steer = LKAS_JOY_CENTER;
    int throttle = LKAS_THROTTLE_MIN_CMD;
    {
        std::lock_guard<std::mutex> lk(g_shared.mtx);
        g_shared.joy.x = steer;
        g_shared.joy.y = throttle;
        g_shared.joy.ts_ms = timestamp_ms;
    }
    write_log_entry(log_stream, timestamp_ms, std::numeric_limits<double>::quiet_NaN(), nullptr, steer, throttle, "failsafe");
}

void apply_sample(const VisionSample& sample, uint64_t timestamp_ms, std::ofstream* log_stream) {
    double offset_cm_raw = resolve_offset_cm(sample);
    double offset_cm = offset_cm_raw;
    bool hold_was_active = g_curve_hold_state.right_hold_frames > 0;
    bool stall_force_release = false;

    bool left_curve = sample.has_curve_hint && sample.curve_hint == "LEFT_CURVE";
    bool right_curve_active = sample.has_curve_hint && sample.curve_hint == "RIGHT_CURVE";
    if (left_curve) {
        g_curve_hold_state.right_hold_frames = 0;
    }
    bool right_scope_far = sample.has_curve_scope && sample.curve_scope == "FAR";
    bool right_scope_suppressed =
        sample.has_curve_scope
        && (sample.curve_scope == "SUPPRESSED" || sample.curve_scope == "NONE" || sample.curve_scope == "FAR");
    bool right_curve_near = !right_scope_far;
    if (right_curve_active && right_scope_far) {
        right_curve_active = false;
    }
    bool lane_right_only = sample.has_lane_visibility && sample.lane_visibility == "RIGHT_ONLY";
    bool lane_left_only = sample.has_lane_visibility && sample.lane_visibility == "LEFT_ONLY";
    bool single_lane_view = lane_right_only || lane_left_only;
    bool curve_stage_pre = sample.has_curve_phase && sample.curve_phase == "CURVE_PRE";
    bool curve_stage_release = sample.has_curve_phase && sample.curve_phase == "CURVE_RELEASE";
    bool curve_stage_active = sample.has_curve_phase && sample.curve_phase == "CURVE_ACTIVE";
    if ((curve_stage_pre || curve_stage_release || curve_stage_active) && !right_curve_active) {
        right_curve_active = true;
        right_curve_near = true;
        right_scope_suppressed = false;
    }
    if (right_curve_active) {
        bool restarting_hold = !hold_was_active;
        g_curve_hold_state.right_hold_frames = LKAS_CURVE_HOLD_FRAMES;
        g_curve_hold_state.right_hold_frames_max = LKAS_CURVE_HOLD_FRAMES;
        g_curve_hold_state.last_right_near = right_curve_near;
        right_scope_suppressed = false;
        double anchor_seed = std::min(offset_cm_raw, 0.0);
        if (restarting_hold) {
            g_curve_hold_state.right_anchor_offset_cm = anchor_seed;
            g_curve_hold_state.right_release_guard = 0;
        } else {
            g_curve_hold_state.right_anchor_offset_cm =
                std::min(g_curve_hold_state.right_anchor_offset_cm, anchor_seed);
        }
    } else if (g_curve_hold_state.right_hold_frames > 0) {
        --g_curve_hold_state.right_hold_frames;
        if (g_curve_hold_state.right_hold_frames <= 0) {
            bool lanes_both = sample.has_lane_visibility && sample.lane_visibility == "BOTH";
            if (lanes_both) {
                g_curve_hold_state.right_release_guard =
                    std::min(
                        g_curve_hold_state.right_release_guard + 1,
                        LKAS_CURVE_RELEASE_BOTH_FRAMES * 2);
            } else {
                g_curve_hold_state.right_release_guard = 0;
            }
            bool offset_near_center = std::fabs(offset_cm_raw) <= LKAS_CURVE_RELEASE_OFFSET_TOL_CM;
            if (lanes_both && offset_near_center
                && g_curve_hold_state.right_release_guard >= LKAS_CURVE_RELEASE_BOTH_FRAMES) {
                g_curve_hold_state.right_anchor_offset_cm = 0.0;
                g_curve_hold_state.right_hold_frames_max = 0;
                g_curve_hold_state.right_release_guard = 0;
            } else {
                g_curve_hold_state.right_hold_frames = 1;
            }
        } else {
            right_curve_active = true;
            right_curve_near = g_curve_hold_state.last_right_near;
            right_scope_suppressed = false;
            double anchor_seed = std::min(offset_cm_raw, 0.0);
            g_curve_hold_state.right_anchor_offset_cm =
                std::min(g_curve_hold_state.right_anchor_offset_cm, anchor_seed);
            g_curve_hold_state.right_anchor_offset_cm *= 0.65;
        }
    } else {
        g_curve_hold_state.right_anchor_offset_cm = 0.0;
        g_curve_hold_state.right_hold_frames_max = 0;
    }

    double stall_delta_tol = static_cast<double>(LKAS_CURVE_STALL_DELTA_TOL_CM);
    bool offset_sample_valid = std::isfinite(offset_cm_raw);
    if (!offset_sample_valid) {
        g_has_last_offset_sample = false;
        g_curve_stall_frames = 0;
    } else {
        bool consider_for_stall = std::fabs(offset_cm_raw) >= stall_delta_tol;
        if (g_has_last_offset_sample && consider_for_stall) {
            double delta = std::fabs(offset_cm_raw - g_last_offset_sample);
            if (delta <= stall_delta_tol) {
                ++g_curve_stall_frames;
            } else {
                g_curve_stall_frames = 0;
            }
        } else if (consider_for_stall) {
            g_curve_stall_frames = 1;
        } else {
            g_curve_stall_frames = 0;
        }
        g_last_offset_sample = offset_cm_raw;
        g_has_last_offset_sample = true;
        if (consider_for_stall
            && g_curve_stall_frames >= LKAS_CURVE_STALL_FRAMES
            && (left_curve || right_curve_active || curve_stage_pre || curve_stage_active)) {
            stall_force_release = true;
            curve_stage_pre = false;
            curve_stage_active = false;
            curve_stage_release = true;
            right_curve_active = false;
            g_curve_hold_state.right_hold_frames = 0;
            g_curve_hold_state.right_hold_frames_max = 0;
            g_curve_hold_state.right_release_guard = 0;
            g_curve_hold_state.right_anchor_offset_cm = 0.0;
        }
    }

    bool enforce_visible_lane_follow =
        !stall_force_release && (right_curve_active || g_curve_hold_state.right_hold_frames > 0);
    if (enforce_visible_lane_follow && single_lane_view) {
        offset_cm = std::min(offset_cm, 0.0);
    }

    if (g_curve_hold_state.right_hold_frames > 0) {
        double relax = static_cast<double>(LKAS_CURVE_RIGHT_OFFSET_RELAX_CM);
        if (g_curve_hold_state.right_hold_frames_max > 0) {
            double ratio =
                static_cast<double>(g_curve_hold_state.right_hold_frames)
                / static_cast<double>(g_curve_hold_state.right_hold_frames_max);
            relax *= (0.5 + 0.5 * ratio);
        }
        double max_allowed = g_curve_hold_state.right_anchor_offset_cm + relax;
        offset_cm = std::min(offset_cm, max_allowed);
    }

    if (single_lane_view) {
        offset_cm *= static_cast<double>(LKAS_SINGLE_LANE_OFFSET_SCALE);
    }

    double smooth_alpha =
        right_curve_active ? static_cast<double>(LKAS_CURVE_OFFSET_SMOOTH_ALPHA)
                           : static_cast<double>(LKAS_OFFSET_SMOOTH_ALPHA);
    if (!g_offset_filter_state.initialized || !std::isfinite(g_offset_filter_state.value)) {
        g_offset_filter_state.value = offset_cm;
        g_offset_filter_state.initialized = true;
    } else {
        g_offset_filter_state.value = g_offset_filter_state.value + smooth_alpha * (offset_cm - g_offset_filter_state.value);
    }
    offset_cm = g_offset_filter_state.value;

    int steer = compute_steer_command(offset_cm);
    int throttle = compute_throttle_command(sample);

    if ((left_curve || right_curve_active) && !stall_force_release) {
            bool scope_allows_bias = true;
            bool is_near_scope = true;
            if (right_curve_active) {
        scope_allows_bias = !right_scope_suppressed || curve_stage_pre || curve_stage_release;
        is_near_scope = right_curve_near;
        if (curve_stage_pre || curve_stage_release) {
            is_near_scope = true;
        }
        } else {
            if (sample.has_curve_scope) {
                if (sample.curve_scope == "FAR") {
                    is_near_scope = false;
                } else if (sample.curve_scope == "SUPPRESSED" || sample.curve_scope == "NONE") {
                    scope_allows_bias = false;
                }
            }
        }
        if (scope_allows_bias) {
            float steer_bias = static_cast<float>(LKAS_CURVE_STEER_BIAS);
            int throttle_delta = LKAS_CURVE_THROTTLE_DELTA;
            if (!is_near_scope) {
                steer_bias *= 0.5f;
                throttle_delta = std::max(1, throttle_delta / 2);
            }
            if (sample.has_lane_visibility && sample.lane_visibility != "BOTH") {
                steer_bias += static_cast<float>(LKAS_CURVE_SINGLE_LANE_BONUS);
                throttle_delta += LKAS_CURVE_SINGLE_LANE_EXTRA;
            }
            if (right_curve_active) {
                double offset_factor = 1.0 + std::min(0.6, std::abs(offset_cm) / 20.0);
                steer_bias *= LKAS_CURVE_RIGHT_STEER_MULT * offset_factor;
                throttle_delta = static_cast<int>(
                    std::lround(static_cast<float>(throttle_delta) * LKAS_CURVE_RIGHT_THROTTLE_MULT));
            }
            if (curve_stage_pre) {
                steer_bias *= LKAS_CURVE_PRE_STEER_SCALE;
                throttle_delta = std::max(1, throttle_delta / 3);
            } else if (curve_stage_release) {
                steer_bias *= LKAS_CURVE_RELEASE_STEER_SCALE;
                throttle_delta = std::max(1, throttle_delta / 4);
            }
            if (single_lane_view) {
                steer_bias *= LKAS_SINGLE_LANE_STEER_SCALE;
            }
            throttle_delta = std::max(1, throttle_delta);
            int steer_step = std::max(1, static_cast<int>(std::lround(steer_bias)));
            if (left_curve && !right_curve_active) {
                steer = clamp_joy_value(steer + steer_step);
            } else {
                steer = clamp_joy_value(steer - steer_step);
            }
            throttle = std::max(LKAS_THROTTLE_MIN_CMD, throttle - throttle_delta);
        }
    }

    if (right_curve_active && !stall_force_release) {
        double override_base =
            right_curve_near ? static_cast<double>(LKAS_CURVE_RIGHT_NEAR_STEER_CMD)
                             : static_cast<double>(LKAS_CURVE_RIGHT_FAR_STEER_CMD);
        double offset_for_override =
            offset_cm_raw - static_cast<double>(LKAS_CURVE_RIGHT_OVERRIDE_THRESH_CM);
        double target = override_base;
        if (offset_for_override > 0.0) {
            double extra = offset_for_override * static_cast<double>(LKAS_CURVE_RIGHT_OVERRIDE_GAIN);
            target = override_base - extra;
        } else {
            double relax = (-offset_for_override) * 0.5;
            target = override_base + relax;
        }
        target = std::clamp(
            target,
            static_cast<double>(LKAS_CURVE_RIGHT_OVERRIDE_MIN),
            static_cast<double>(LKAS_CURVE_RIGHT_OVERRIDE_MAX));
        steer = std::min(steer, clamp_joy_value(static_cast<int>(std::lround(target))));
        int throttle_cap = right_curve_near ? LKAS_CURVE_RIGHT_NEAR_THROTTLE : LKAS_CURVE_RIGHT_FAR_THROTTLE;
        if (curve_stage_pre) {
            throttle_cap = std::max(throttle_cap, LKAS_CURVE_PRE_MIN_THROTTLE);
        } else if (curve_stage_release) {
            throttle_cap = std::max(throttle_cap, LKAS_CURVE_RELEASE_MIN_THROTTLE);
        }
        throttle = std::min(throttle, std::max(LKAS_THROTTLE_MIN_CMD, throttle_cap));
        if (curve_stage_pre) {
            throttle = std::max(throttle, LKAS_CURVE_PRE_MIN_THROTTLE);
        } else if (curve_stage_release) {
            throttle = std::max(throttle, LKAS_CURVE_RELEASE_MIN_THROTTLE);
        } else {
            throttle = std::max(throttle, LKAS_CURVE_MIN_THROTTLE);
        }
    }
    if (left_curve && !right_curve_active && !stall_force_release) {
        double override_base =
            sample.has_curve_scope && sample.curve_scope == "FAR"
                ? static_cast<double>(LKAS_CURVE_LEFT_FAR_STEER_CMD)
                : static_cast<double>(LKAS_CURVE_LEFT_NEAR_STEER_CMD);
        double offset_for_override =
            (-offset_cm_raw) - static_cast<double>(LKAS_CURVE_LEFT_OVERRIDE_THRESH_CM);
        if (offset_for_override <= 0.0) {
            steer = std::max(steer, clamp_joy_value(static_cast<int>(std::lround(override_base))));
        } else {
            double extra = offset_for_override * static_cast<double>(LKAS_CURVE_LEFT_OVERRIDE_GAIN);
            double target =
                std::min(
                    static_cast<double>(LKAS_CURVE_LEFT_OVERRIDE_MAX),
                    override_base + extra);
            steer = std::min(steer, clamp_joy_value(static_cast<int>(std::lround(target))));
        }
    }
    if (!right_curve_active && curve_stage_release
        && std::fabs(offset_cm_raw) > LKAS_CURVE_RELEASE_OFFSET_TOL_CM) {
        double recenter_gain = static_cast<double>(LKAS_CURVE_RELEASE_RECENTER_GAIN);
        double delta = offset_cm_raw * recenter_gain;
        steer = clamp_joy_value(static_cast<int>(std::lround(steer - delta)));
    }
    throttle = std::clamp(throttle, LKAS_THROTTLE_MIN_CMD, LKAS_MAX_THROTTLE_CMD);
    if (single_lane_view) {
        throttle = std::max(throttle, LKAS_SINGLE_LANE_MIN_THROTTLE);
    }
    if (curve_stage_release && !stall_force_release) {
        double blend = static_cast<double>(LKAS_CURVE_RELEASE_STEER_BLEND);
        steer = clamp_joy_value(
            static_cast<int>(
                std::lround(
                    steer * (1.0 - blend)
                    + static_cast<double>(LKAS_JOY_CENTER) * blend)));
        throttle = std::max(throttle, LKAS_CURVE_RELEASE_THROTTLE_RECOVER);
    } else if (stall_force_release) {
        double blend_alpha = std::clamp(
            static_cast<double>(LKAS_CURVE_STALL_RELEASE_ALPHA),
            0.0,
            1.0);
        double center = static_cast<double>(LKAS_JOY_CENTER);
        double blended =
            static_cast<double>(steer) * (1.0 - blend_alpha)
            + center * blend_alpha;
        steer = clamp_joy_value(static_cast<int>(std::lround(blended)));
        throttle = std::max(throttle, LKAS_CURVE_STALL_MIN_THROTTLE);
    }

    if (g_launch_frames_remaining > 0) {
        steer = (steer + LKAS_LAUNCH_STEER_CENTER) / 2;
        throttle = std::min(LKAS_MAX_THROTTLE_CMD, std::max(throttle, LKAS_LAUNCH_THROTTLE));
        --g_launch_frames_remaining;
    }

    {
        std::lock_guard<std::mutex> lk(g_shared.mtx);
        g_shared.joy.x = steer;
        g_shared.joy.y = throttle;
        g_shared.joy.ts_ms = timestamp_ms;
    }
    write_log_entry(log_stream, timestamp_ms, offset_cm, &sample, steer, throttle, "vision");
}

}  // namespace

void lkas_thread() {
    set_realtime_sched(PRIO_COMM);
    std::ofstream joy_log = open_log_stream();

    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::perror("[lkas] socket");
        return;
    }

    int reuse = 1;
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    timeval tv{};
    tv.tv_sec = LKAS_VISION_TIMEOUT_MS / 1000;
    tv.tv_usec = (LKAS_VISION_TIMEOUT_MS % 1000) * 1000;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LKAS_VISION_UDP_PORT);
    addr.sin_addr.s_addr = inet_addr(LKAS_VISION_BIND_ADDR);

    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("[lkas] bind");
        ::close(sock);
        return;
    }

    std::cout << "[lkas] waiting for vision telemetry on UDP "
              << LKAS_VISION_BIND_ADDR << ":" << LKAS_VISION_UDP_PORT << std::endl;

    uint64_t last_sample_ms = 0;
    char buffer[512];

    while (true) {
        {
            std::lock_guard<std::mutex> lk(g_shared.mtx);
            if (!g_shared.running) {
                break;
            }
        }

        sockaddr_in src{};
        socklen_t slen = sizeof(src);
        ssize_t n = ::recvfrom(sock, buffer, sizeof(buffer) - 1, 0, reinterpret_cast<sockaddr*>(&src), &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                uint64_t now = now_ms();
                    if (last_sample_ms != 0 && now - last_sample_ms > LKAS_VISION_TIMEOUT_MS) {
                        apply_failsafe(&joy_log, now);
                        last_sample_ms = 0;
                    }
                    continue;
            }
            std::perror("[lkas] recvfrom");
            continue;
        }

        buffer[n] = '\0';

        VisionSample sample{};
        if (!parse_sample(buffer, sample)) {
            continue;
        }

        uint64_t now = now_ms();
        apply_sample(sample, now, &joy_log);
        last_sample_ms = now;
    }

    ::close(sock);
    std::cout << "[lkas] terminated\n";
}
