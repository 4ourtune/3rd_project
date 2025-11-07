#include "shared.h"
#include "vc_common.h"
#include "config.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>

namespace {

constexpr uint64_t kSensorIntervalUs  = static_cast<uint64_t>(PERIOD_SENSOR_MS) * 1000;
constexpr int32_t  kAebBuzzerFreqHz   = 500;
constexpr int32_t  kDoorChirpLowFreqHz  = 350;
constexpr int32_t  kDoorChirpHighFreqHz = 900;
constexpr uint64_t kDoorChirpDurationMs = 180;

static int map_joy_to_throttle(int y){ // 0~99
    return std::clamp(y, -100, 100);
}
static int map_joy_to_steer(int x){    // 0~99
    return std::clamp(x, -100, 100);
}

class AebController {
public:
    bool update(int distance_mm, int forward_speed){
        if (distance_mm < 0){
            state_ = State::Normal;
            return false;
        }

        if (distance_mm <= kEmergencyThresholdMm + kToleranceMm){
            state_ = State::Emergency;
            return true;
        }

        if (forward_speed <= 0){
            state_ = State::Normal;
            return false;
        }

        long long speed_sq = static_cast<long long>(forward_speed) * forward_speed;
        long long numerator = static_cast<long long>(kCoeffA) * speed_sq
                            + static_cast<long long>(kCoeffB) * forward_speed
                            + static_cast<long long>(kCoeffC);
        if (numerator < 0){
            numerator = 0;
        }

        unsigned int braking_distance = static_cast<unsigned int>(numerator / kSpeedDivider);
        if (distance_mm <= static_cast<int>(braking_distance) + kEmergencyThresholdMm){
            state_ = State::Emergency;
        } else {
            state_ = State::Normal;
        }
        return state_ == State::Emergency;
    }

private:
    enum class State { Normal, Emergency };

    static constexpr int kToleranceMm          = 5;
    static constexpr int kEmergencyThresholdMm = 100;
    static constexpr int kCoeffA               = -27;
    static constexpr int kCoeffB               = 6496;
    static constexpr int kCoeffC               = -112642;
    static constexpr int kSpeedDivider         = 1000;

    State state_ = State::Normal;
};

class AutoParkingController {
public:
    void start(){
        reset();
        active_ = true;
    }

    void stop(){
        active_ = false;
        reset();
    }

    bool active() const { return active_; }

    void step(uint64_t now_us, const SensorData& sensor, uint64_t sensor_interval_us){
        if (!active_){
            result_x_ = 50;
            result_y_ = 50;
            sensors_ready_ = false;
            return;
        }

        if (!updateSensors(now_us, sensor, sensor_interval_us)){
            result_x_ = 50;
            result_y_ = 50;
            return;
        }

        computeOutputs(now_us);
    }

    int throttlePercent() const { return mapJoystickValue(result_y_); }
    int steerPercent() const { return mapJoystickValue(result_x_); }
    bool completed() const { return done_; }
    bool sensorsReady() const { return sensors_ready_; }

private:
    enum class ParkingPhase { SpaceDetection, ParkingExecution, Completed };
    enum class WallSpaceState { WallDetected, SpaceDetected };

    struct Config {
        int wall_threshold_mm;
        float vehicle_speed_cm_per_ms;
        float min_space_size_cm;
        int rear_safety_distance_mm;
        int rotate_limit;
    };

    void reset(){
        done_ = false;
        sensors_ready_ = false;
        phase_ = ParkingPhase::SpaceDetection;
        state_ = WallSpaceState::WallDetected;
        execution_state_ = 1;
        wall_reference_initialized_ = false;
        wall_reference_distance_mm_ = 0;
        space_start_time_us_ = 0;
        space_end_time_us_ = 0;
        measured_space_size_cm_ = 0.0f;
        rotate_counter_ = 0;
        result_x_ = 50;
        result_y_ = 50;
        sense_dist_.fill(-1);
        sense_time_.fill(0);
    }

    bool updateSensors(uint64_t now_us, const SensorData& sensor, uint64_t sensor_interval_us){
        auto assign_sensor = [&](int idx, int distance_mm, uint64_t ts_us){
            sense_dist_[idx] = distance_mm;
            sense_time_[idx] = ts_us != 0 ? ts_us : now_us;
        };

        assign_sensor(0,
                      sensor.front_tof_mm >= 0 ? sensor.front_tof_mm : -1,
                      sensor.front_ts_us);
        assign_sensor(1, sensor.left_ultra_mm, sensor.left_ts_us);
        assign_sensor(2, sensor.right_ultra_mm, sensor.right_ts_us);
        assign_sensor(3, sensor.rear_ultra_mm, sensor.rear_ts_us);

        sensors_ready_ = (sense_dist_[1] >= 0 && sense_dist_[3] >= 0);
        if (!sensors_ready_){
            return false;
        }

        uint64_t max_age_us = sensor_interval_us * 5;
        for (size_t i = 0; i < sense_time_.size(); ++i){
            if (sense_time_[i] == 0){
                sense_time_[i] = now_us;
            }
            if (now_us >= sense_time_[i] && (now_us - sense_time_[i]) > max_age_us){
                sensors_ready_ = false;
                return false;
            }
        }
        sensors_ready_ = true;
        return true;
    }

    WallSpaceState analyzeSpace(int distance_mm){
        if (distance_mm < 0){
            return WallSpaceState::WallDetected;
        }

        if (!wall_reference_initialized_){
            wall_reference_distance_mm_ = distance_mm;
            wall_reference_initialized_ = true;
            return WallSpaceState::WallDetected;
        }

        if (distance_mm < wall_reference_distance_mm_){
            wall_reference_distance_mm_ = distance_mm;
        }

        if (distance_mm > wall_reference_distance_mm_ + cfg_.wall_threshold_mm){
            return WallSpaceState::SpaceDetected;
        }
        return WallSpaceState::WallDetected;
    }

    void processStateTransition(WallSpaceState new_state, uint64_t now_us){
        if (state_ == new_state){
            return;
        }

        if (state_ == WallSpaceState::WallDetected && new_state == WallSpaceState::SpaceDetected){
            space_start_time_us_ = now_us;
        } else if (state_ == WallSpaceState::SpaceDetected && new_state == WallSpaceState::WallDetected){
            space_end_time_us_ = now_us;
            measured_space_size_cm_ = calculateSpaceSize(space_start_time_us_, space_end_time_us_);
        }
        state_ = new_state;
    }

    bool detectParkingSpace(uint64_t now_us){
        WallSpaceState analyzed = analyzeSpace(sense_dist_[1]);
        processStateTransition(analyzed, now_us);
        return measured_space_size_cm_ >= cfg_.min_space_size_cm;
    }

    float calculateSpaceSize(uint64_t start_us, uint64_t end_us) const{
        if (end_us <= start_us){
            return 0.0f;
        }
        float diff_ms = static_cast<float>(end_us - start_us) / 1000.0f;
        return diff_ms * cfg_.vehicle_speed_cm_per_ms;
    }

    void computeOutputs(uint64_t now_us){
        int left_distance = sense_dist_[1];
        int rear_distance = sense_dist_[3];

        switch (phase_){
        case ParkingPhase::SpaceDetection:
            result_x_ = 50;
            result_y_ = 70;
            if (detectParkingSpace(now_us)){
                phase_ = ParkingPhase::ParkingExecution;
                execution_state_ = 1;
                rotate_counter_ = 0;
                wall_reference_initialized_ = false;
                state_ = WallSpaceState::WallDetected;
            }
            break;

        case ParkingPhase::ParkingExecution:
            if (execution_state_ == 1){
                state_ = analyzeSpace(left_distance);
                if (state_ == WallSpaceState::SpaceDetected){
                    result_x_ = 50;
                    result_y_ = 50;
                    execution_state_ = 2;
                } else {
                    result_x_ = 50;
                    result_y_ = 35;
                }
            } else {
                if (rotate_counter_ < cfg_.rotate_limit){
                    result_x_ = 64;
                    result_y_ = 45;
                    ++rotate_counter_;
                } else {
                    result_x_ = 50;
                    result_y_ = 35;
                }

                if (rotate_counter_ >= cfg_.rotate_limit &&
                    rear_distance >= 0 &&
                    rear_distance <= cfg_.rear_safety_distance_mm){
                    result_x_ = 50;
                    result_y_ = 50;
                    phase_ = ParkingPhase::Completed;
                    done_ = true;
                }
            }
            break;

        case ParkingPhase::Completed:
            result_x_ = 50;
            result_y_ = 50;
            done_ = true;
            break;
        }
    }

    static int mapJoystickValue(int value){
        value = std::clamp(value, 0, 99);
        return value;
    }

    const Config cfg_{100, 0.5f, 150.0f, 100, 30};
    bool active_ = false;
    bool done_ = false;
    bool sensors_ready_ = false;
    ParkingPhase phase_ = ParkingPhase::SpaceDetection;
    WallSpaceState state_ = WallSpaceState::WallDetected;
    int execution_state_ = 1;
    bool wall_reference_initialized_ = false;
    int wall_reference_distance_mm_ = 0;
    uint64_t space_start_time_us_ = 0;
    uint64_t space_end_time_us_ = 0;
    float measured_space_size_cm_ = 0.0f;
    int rotate_counter_ = 0;
    int result_x_ = 50;
    int result_y_ = 50;
    std::array<int, 4> sense_dist_{};
    std::array<uint64_t, 4> sense_time_{};
};

class HighBeamAssist {
public:
    bool shouldEnableFrontHighBeam(const SensorData& sensor) const{
        if (sensor.ambient_lux < 0){
            return false;
        }
        return sensor.ambient_lux < kLuxThreshold;
    }

private:
    static constexpr int kLuxThreshold = 50;
};

int resolve_front_distance_mm(const SensorData& sen){
    if (sen.front_tof_mm >= 0){
        return sen.front_tof_mm;
    }
    return -1;
}

class ControlLoop {
public:
    void run();

private:
    struct ControlInputs {
        bool engine = false;
        bool door_locked = false;
        ControlMode mode = ControlMode::Assist;
        JoystickData joy{};
        SensorData sensor{};
        uint64_t now_ms = 0;
    };

    ControlInputs snapshotInputs(uint64_t now_ms_value);
    ControlOutput computeOutput(const ControlInputs& inputs);
    void initializeOutput(ControlOutput& out) const;
    void updateAutoParkingState(bool engine_on, ControlMode mode);
    void publishOutput(const ControlOutput& out);
    void handleDoorLockTransition(const ControlInputs& inputs);
    void applyDoorLockFeedback(const ControlInputs& inputs, ControlOutput& out);

    AutoParkingController aps_;
    AebController aeb_;
    HighBeamAssist hba_;
    ControlMode last_mode_ = ControlMode::Assist;
    bool door_state_initialized_ = false;
    bool last_door_locked_ = false;
    enum class DoorBuzzerState { Idle, LowTone, HighTone };
    DoorBuzzerState door_buzzer_state_ = DoorBuzzerState::Idle;
    uint64_t door_buzzer_state_until_ms_ = 0;
    bool door_buzzer_pending_high_ = false;
};

void ControlLoop::run(){
    set_realtime_sched(PRIO_CONTROL);

    uint64_t next_tick_ms = now_ms();
    while (g_shared.running){
        const uint64_t t_ms = now_ms();
        if (t_ms < next_tick_ms){
            sleep_ms(1);
            continue;
        }
        next_tick_ms = t_ms + PERIOD_CTRL_MS;

        ControlInputs inputs = snapshotInputs(t_ms);
        
        ControlOutput out = computeOutput(inputs);
        
        publishOutput(out);
    }
}

//struct SensorData {
//    int dist_cm = 999;      // 앞 장애물 거리(Stub)
//    int ambient_lux = 0;    // 조도(Stub)
//    int front_tof_mm = -1;  // 전방 ToF (mm)
//    int left_ultra_mm = -1; // 좌측 초음파 (mm)
//    int right_ultra_mm = -1; // 우측 초음파 (mm)
//    int rear_ultra_mm = -1;  // 후방 초음파 (mm)
//    uint64_t ts_ms = 0;
//    uint64_t front_ts_us = 0;
//    uint64_t left_ts_us = 0;
//    uint64_t right_ts_us = 0;
//    uint64_t rear_ts_us = 0;
//};

//struct ControlOutput {
//    // buzzer
//    bool buzzerOn = false;
//    int32_t frequency = 500; // 250~1000Hz
//
//    // led
//    bool led_back_on = false;
//    bool led_front_down_on = false;
//    bool led_front_up_on = false;
//
//    // emerAlert
//    int64_t alert_interval_ms = -1; // -1=off, 0=on(지속), >0=점멸주기(ms)
//
//    // motor
//    int throttle = 0; // -100~+100
//    int steer = 0;    // -100~+100
//};

ControlLoop::ControlInputs ControlLoop::snapshotInputs(uint64_t now_ms_value){
    ControlInputs inputs;
    inputs.now_ms = now_ms_value;
    std::lock_guard<std::mutex> lk(g_shared.mtx);
    inputs.engine = g_shared.engine_on;
    inputs.door_locked = g_shared.door_locked;
    inputs.joy    = g_shared.joy;
    inputs.sensor = g_shared.sensor;
    inputs.mode   = g_shared.mode;
    return inputs;
}

void ControlLoop::initializeOutput(ControlOutput& out) const{
    out.buzzerOn    = false;
    out.frequency   = 0;
    out.alert_interval_ms = -1;
    out.throttle    = 0;
    out.steer       = 0;

    out.led_back_on        = false;
    out.led_front_down_on  = false;
    out.led_front_up_on    = false;
}

void ControlLoop::updateAutoParkingState(bool engine_on, ControlMode mode){
    if (!engine_on){
        aps_.stop();
        return;
    }

    if (mode == ControlMode::Auto && last_mode_ != ControlMode::Auto){
        aps_.start();
    } else if (last_mode_ == ControlMode::Auto && mode != ControlMode::Auto){
        aps_.stop();
    }

    if (mode == ControlMode::Auto && !aps_.active()){
        aps_.start();
    }
}

void ControlLoop::handleDoorLockTransition(const ControlInputs& inputs){
    if (!door_state_initialized_){
        last_door_locked_ = inputs.door_locked;
        door_state_initialized_ = true;
        return;
    }

    if (inputs.door_locked != last_door_locked_){
        last_door_locked_ = inputs.door_locked;
        door_buzzer_state_ = DoorBuzzerState::LowTone;
        door_buzzer_pending_high_ = true;
        door_buzzer_state_until_ms_ = inputs.now_ms + kDoorChirpDurationMs;
    }
}

void ControlLoop::applyDoorLockFeedback(const ControlInputs& inputs, ControlOutput& out){
    if (door_buzzer_state_ == DoorBuzzerState::Idle){
        return;
    }

    if (inputs.now_ms >= door_buzzer_state_until_ms_){
        if (door_buzzer_state_ == DoorBuzzerState::LowTone && door_buzzer_pending_high_){
            door_buzzer_state_ = DoorBuzzerState::HighTone;
            door_buzzer_pending_high_ = false;
            door_buzzer_state_until_ms_ = inputs.now_ms + kDoorChirpDurationMs;
        } else {
            door_buzzer_state_ = DoorBuzzerState::Idle;
            door_buzzer_state_until_ms_ = 0;
            door_buzzer_pending_high_ = false;
            return;
        }
    }

    if (door_buzzer_state_ == DoorBuzzerState::Idle){
        return;
    }

    if (!out.buzzerOn){
        out.buzzerOn = true;
        out.alert_interval_ms = 0;
        out.frequency = (door_buzzer_state_ == DoorBuzzerState::LowTone)
                            ? kDoorChirpLowFreqHz
                            : kDoorChirpHighFreqHz;
    }
}

ControlOutput ControlLoop::computeOutput(const ControlInputs& inputs){
    handleDoorLockTransition(inputs);

    ControlOutput out{};
    initializeOutput(out);

    if (!inputs.engine){
        applyDoorLockFeedback(inputs, out);
        last_mode_ = inputs.mode;
        return out;
    }

    updateAutoParkingState(inputs.engine, inputs.mode);

    if (inputs.mode == ControlMode::Auto && aps_.active()){
        aps_.step(inputs.now_ms * 1000, inputs.sensor, kSensorIntervalUs);
        out.throttle = aps_.throttlePercent();
        out.steer    = aps_.steerPercent();
    } else {
        int thr = map_joy_to_throttle(inputs.joy.y);
        int str = map_joy_to_steer(inputs.joy.x);

        if (inputs.mode == ControlMode::Assist){
            str = std::clamp(str, -80, 80);
        }

        out.throttle = std::clamp(thr, -100, 100);
        out.steer    = std::clamp(str, -100, 100);
    }

    const bool high_beam_active = inputs.engine && hba_.shouldEnableFrontHighBeam(inputs.sensor);
    out.led_front_up_on   = high_beam_active;
    out.led_front_down_on = inputs.engine;

    int front_distance_mm = resolve_front_distance_mm(inputs.sensor);
    int forward_speed = std::max(out.throttle, 0);
    if (aeb_.update(front_distance_mm, forward_speed)){
        out.buzzerOn    = true;
        out.frequency   = kAebBuzzerFreqHz;
        out.alert_interval_ms = 0;
        out.throttle    = -100;
        out.led_back_on = true;
    }

    applyDoorLockFeedback(inputs, out);

    last_mode_ = inputs.mode;
    return out;
}

void ControlLoop::publishOutput(const ControlOutput& out){
    std::lock_guard<std::mutex> lk(g_shared.mtx);
    g_shared.out = out;
}

} // namespace

void control_thread(){
    ControlLoop loop;
    loop.run();
}
