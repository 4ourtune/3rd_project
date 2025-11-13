#ifndef ASW_APS_APS_H_
#define ASW_APS_APS_H_

#include <stdbool.h>
#include <stdint.h>

#include "ToF.h"
#include "eru.h"
#include "stm.h"


#define CYCLE_DELAY_US                100000    // 100ms
#define SENSOR_DATA_COUNT             4
#define APS_WALL_THRESHOLD_CM         30
#define MIN_PARKING_SPACE_CM          50
#define APS_REAR_SAFETY_DISTANCE_CM   5
#define APS_VEHICLE_SPEED_CM_PER_MS   0.5f
#define APS_MAX_SPACE_SIZE_CM         1000

typedef enum {
    WALL_DETECTED,
    SPACE_DETECTED
} APS_WallSpaceState_t;

typedef enum {
    PHASE_SPACE_DETECTION,
    PHASE_PARKING_EXECUTION,
    PHASE_COMPLETED
} APS_ParkingPhase_t;

// // APS 내부 상태 및 결과 관리
// extern volatile int aps_state;
// extern int result_x;        // APS가 판단한 조향 명령 (0~99, 50: 중립)
// extern int result_y;        // APS가 판단한 속도 명령 (0~99, 50: 정지)
// extern int is_APS_done;     // APS 주차 완료 플래그 (0: 진행중, 1: 완료)

// // 센서 데이터 배열
// extern unsigned int sense_dist[SENSOR_DATA_COUNT];
// extern uint64_t sense_time[SENSOR_DATA_COUNT];

// APS 상태 관리
int Get_APS_State(void);
void Set_APS_State(int state);

// // 공간 탐지 및 상태 관리 함수
// APS_WallSpaceState_t APS_AnalyzeSpace(int distance);
// void APS_ProcessStateTransition(APS_WallSpaceState_t new_state);
float APS_CalculateSpaceSize(uint64_t start_time, uint64_t end_time);
// bool APS_DetectParkingSpace(void);

// // APS 명령 및 상태 관리 함수
void Calc_APS_Result(void);
int Update_APS_Result (ToFData_t *tof_latest_data, UltrasonicData_t ult_latest_data[], uint64 interval_us);
// int APS_CalculateSteeringFromSensor(int sensor_distance);

// APS 외부 인터페이스
void Get_APS_Result(int *res_x, int *res_y, int *is_done);

// APS 재시작 함수
void APS_Restart(void);

// APS 초기화 함수
void APS_Init(void);


#endif /* ASW_APS_APS_H_ */