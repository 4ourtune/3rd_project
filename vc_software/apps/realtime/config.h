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


#endif
