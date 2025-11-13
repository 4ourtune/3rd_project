#ifndef CONFIG_H
#define CONFIG_H

// Joystick(Bluetooth RFCOMM)
#define JOY_DEV_PATH      "/dev/rfcomm0"
#define JOY_BAUD          9600

// 주기(ms)
#define PERIOD_CTRL_MS    20   // 50 Hz control loop
#define PERIOD_SENSOR_MS  20   // 50 Hz sensor poll (stub)
#define PERIOD_COMM_MS    20   // 50 Hz command TX
#define PERIOD_LOG_MS     500  // 상태 로그 주기

// RT 우선순위 (1~99)
#define PRIO_JOYSTICK     85
#define PRIO_SENSOR       80
#define PRIO_CONTROL      90
#define PRIO_COMM         75

// 간단한 안전 임계값(예: AEB)
#define AEB_DISTANCE_CM   20


// 기존 내용 유지하고 아래 두 줄만 추가
#define JOY_BIND_ADDR   "0.0.0.0"  // VC가 바인드할 주소(모든 NIC)
#define JOY_UDP_PORT    5002       // 조이스틱 RPi가 쏘는 UDP 포트

// LKAS 제어 스레드 옵션
#define LKAS_STEER_MIN        -40
#define LKAS_STEER_MAX         40
#define LKAS_STEER_STEP         5
#define LKAS_THROTTLE_MIN      10
#define LKAS_THROTTLE_MAX      40
#define LKAS_THROTTLE_STEP      5
#define LKAS_PERIOD_MS         50

#define LKAS_VISION_BIND_ADDR             "127.0.0.1"
#define LKAS_VISION_UDP_PORT              6000
#define LKAS_VISION_TIMEOUT_MS            1000
#define LKAS_VISION_DEFAULT_LANE_WIDTH_CM 25.0f

#define LKAS_JOY_CENTER                   50
#define LKAS_MAX_OFFSET_CM                35.0f
#define LKAS_STEER_GAIN_PER_CM             2.0f

#define LKAS_THROTTLE_STOP                54   // slight creep but no reverse
#define LKAS_THROTTLE_MIN_CMD             58
#define LKAS_THROTTLE_BASE_CMD            62
#define LKAS_MAX_THROTTLE_CMD             66
#define LKAS_CONFIDENCE_THRESHOLD         0.35f
#define LKAS_CURVE_STEER_BIAS            15
#define LKAS_CURVE_SINGLE_LANE_BONUS      5
#define LKAS_CURVE_THROTTLE_DELTA         12
#define LKAS_CURVE_SINGLE_LANE_EXTRA      6
#define LKAS_CURVE_RIGHT_STEER_MULT       1.44f
#define LKAS_CURVE_RIGHT_THROTTLE_MULT    1.30f
#define LKAS_CURVE_RIGHT_NEAR_STEER_CMD   37
#define LKAS_CURVE_RIGHT_FAR_STEER_CMD    53
#define LKAS_CURVE_RIGHT_NEAR_THROTTLE    65
#define LKAS_CURVE_RIGHT_FAR_THROTTLE     68
#define LKAS_CURVE_RIGHT_OVERRIDE_MIN     19
#define LKAS_CURVE_RIGHT_OVERRIDE_MAX     68
#define LKAS_CURVE_RIGHT_OVERRIDE_GAIN     2.1f
#define LKAS_CURVE_RIGHT_OVERRIDE_THRESH_CM 1.6f
#define LKAS_CURVE_LEFT_NEAR_STEER_CMD    71
#define LKAS_CURVE_LEFT_FAR_STEER_CMD     61
#define LKAS_CURVE_LEFT_OVERRIDE_MAX      84
#define LKAS_CURVE_LEFT_OVERRIDE_GAIN      1.8f
#define LKAS_CURVE_LEFT_OVERRIDE_THRESH_CM 1.5f
#define LKAS_CURVE_HOLD_FRAMES            8
#define LKAS_CURVE_MIN_THROTTLE           60
#define LKAS_CURVE_RIGHT_OFFSET_RELAX_CM  3.4f
#define LKAS_OFFSET_SMOOTH_ALPHA          0.35f
#define LKAS_CURVE_OFFSET_SMOOTH_ALPHA    0.55f
#define LKAS_SINGLE_LANE_OFFSET_SCALE     0.75f
#define LKAS_SINGLE_LANE_STEER_SCALE      0.90f
#define LKAS_SINGLE_LANE_MIN_THROTTLE     63
#define LKAS_CURVE_RELEASE_BOTH_FRAMES    4
#define LKAS_CURVE_RELEASE_OFFSET_TOL_CM  1.2f
#define LKAS_CURVE_PRE_STEER_SCALE        0.90f
#define LKAS_CURVE_RELEASE_STEER_SCALE    0.7f
#define LKAS_CURVE_PRE_MIN_THROTTLE       66
#define LKAS_CURVE_RELEASE_MIN_THROTTLE   62
#define LKAS_CURVE_RELEASE_RECENTER_GAIN  0.35f
#define LKAS_CURVE_RELEASE_STEER_BLEND    0.55f
#define LKAS_CURVE_RELEASE_THROTTLE_RECOVER 63
#define LKAS_CURVE_STALL_DELTA_TOL_CM     0.5f
#define LKAS_CURVE_STALL_FRAMES           30
#define LKAS_CURVE_STALL_RELEASE_ALPHA    0.4f
#define LKAS_CURVE_STALL_MIN_THROTTLE     65
#define LKAS_LAUNCH_BOOST_FRAMES          12
#define LKAS_LAUNCH_THROTTLE              72
#define LKAS_LAUNCH_STEER_CENTER          50

#define LKAS_JOY_LOG_DIR                  "logs"
#define LKAS_JOY_LOG_PREFIX               "lkas_joy"

#endif
