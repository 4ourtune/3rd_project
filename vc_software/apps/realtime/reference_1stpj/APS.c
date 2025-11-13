#include "aps.h"
#include "my_stdio.h"
#include <stdbool.h> // bool 타입 사용
#include "emer_light.h"

// 후진 두 군데 38에서 35로 변경함

#define SENSOR_DATA_COUNT 4
#define APS_WALL_THRESHOLD_CM 100
#define MIN_PARKING_SPACE_CM 150 // 20cm
#define APS_REAR_SAFETY_DISTANCE_CM 100 // 후진 시 최소 안전 거리
#define APS_VEHICLE_SPEED_CM_PER_MS 0.5f
#define APS_MAX_SPACE_SIZE_CM 1000

static uint64 sense_time[SENSOR_DATA_COUNT];
static int sense_dist[SENSOR_DATA_COUNT]; // 0: ToF_front, 1: Ult_left, 2: Ult_right, 3: Ult_rear

static volatile int aps_state = 0;
static int result_x;               // APS가 판단한 조향 명령 (0~99, 50: 중립)
static int result_y;               // APS가 판단한 속도 명령 (0~99, 50: 정지)
static int is_APS_done;            // APS 주차 완료 플래그 (0: 진행중, 1: 완료)

static APS_ParkingPhase_t current_phase = PHASE_SPACE_DETECTION;
static APS_WallSpaceState_t current_state = WALL_DETECTED;
static int wall_reference_distance = 0;
static bool wall_reference_initialized = false;
static uint64 space_start_time = 0;
static uint64 space_end_time = 0;
static float measured_space_size = 0.0f;

static int rotate_counter = 0;
const int ROTATE_LIMIT = 30; // 실제 차량에 맞게 조정 필요 - 45가 원래 잘 돌아가던 코드였음

static uint64 last_toggle_time = 0;

void APS_Init (void)
{
    // APS 초기화 로직
    // 센서 데이터 초기화
    for (int i = 0; i < SENSOR_DATA_COUNT; i++)
    {
        sense_dist[i] = 0;
        sense_time[i] = 0;
    }

    aps_state = 0;
    result_x = 50; // 중립
    result_y = 50; // 정지
    is_APS_done = 0;

    current_phase = PHASE_SPACE_DETECTION;
    current_state = WALL_DETECTED;
    wall_reference_distance = 0;
    wall_reference_initialized = false;
    space_start_time = 0;
    space_end_time = 0;
    measured_space_size = 0.0f;

    rotate_counter = 0;
}

void APS_Restart (void)
{
    APS_Init();
    Set_APS_State(1);
}

int Get_APS_State (void)
{
    return aps_state;
}

// 공간 탐지 상태 분석
static APS_WallSpaceState_t APS_AnalyzeSpace (int distance)
{
    if (!wall_reference_initialized)
    {
        my_printf("[APS] Wall reference initialized: %d\n", distance);
        wall_reference_distance = distance;
        wall_reference_initialized = true;
        return WALL_DETECTED;
    }
    // 디버깅용 출력(APS_WALL_THRESHOLD_CM 포함)
    // my_printf("[APS] Analyzing space: %d mm, Wall reference: %d mm, APS_WALL_THRESHOLD_CM = 30 \n", distance, wall_reference_distance);

    if (distance < wall_reference_distance)
    {
        wall_reference_distance = distance;
    }
    if (distance > (wall_reference_distance + APS_WALL_THRESHOLD_CM))
    {
        my_printf("[APS] SPACE_DETECTED: %d\n", distance);
        return SPACE_DETECTED;
    }
    else
    {
        my_printf("[APS] WALL_DETECTED: %d\n", distance);
        return WALL_DETECTED;
    }
}

// 공간 탐지 상태 전이 및 시간 기록
static void APS_ProcessStateTransition (APS_WallSpaceState_t new_state)
{
    if (current_state != new_state)
    {
        // 상태 변경 문자열로 처리
        my_printf("[APS] State transition: %s -> %s\n",
                (current_state == WALL_DETECTED) ? "WALL_DETECTED" : "SPACE_DETECTED",
                (new_state == WALL_DETECTED) ? "WALL_DETECTED" : "SPACE_DETECTED");

        if (current_state == WALL_DETECTED)
        {
            space_start_time = getTimeUs();
            current_state = SPACE_DETECTED;
            my_printf("[APS] Space start time: %u\n", getTimeUs());
        }
        else if (current_state == SPACE_DETECTED)
        {
            space_end_time = getTimeUs();
            measured_space_size = APS_CalculateSpaceSize(space_start_time, space_end_time);
            current_state = WALL_DETECTED;
            my_printf("[APS] Space end time: %u\n", getTimeUs());
            my_printf("[APS] Measured space size: %.1f\n", measured_space_size);
        }
    }
}

// 공간 크기 계산
float APS_CalculateSpaceSize (uint64 start_time, uint64 end_time)
{
    if (end_time < start_time)
        return 0.0f;
    uint64 time_diff_us = end_time - start_time;
    float time_diff_ms = time_diff_us / 1000.0f;
    float space_size = time_diff_ms * APS_VEHICLE_SPEED_CM_PER_MS;
    // if (space_size > APS_MAX_SPACE_SIZE_CM) return 0.0f;
    return space_size;
}

// 공간 탐지 및 주차 가능 판단
static bool APS_DetectParkingSpace (void)
{
    int left_distance = sense_dist[1];
    APS_WallSpaceState_t analyzed_state = APS_AnalyzeSpace(left_distance);
    APS_ProcessStateTransition(analyzed_state);

    if (measured_space_size >= MIN_PARKING_SPACE_CM)
    {
        // measured_space_size 출력
        my_printf("[APS] Parking space detected: %.1f cm\n", measured_space_size);
        return true;
    }
    return false;
}

/**
 * @brief 센서 데이터를 갱신하고, APS 명령을 계산하는 함수
 */
int Update_APS_Result (ToFData_t *tof_latest_data, UltrasonicData_t ult_latest_data[], uint64 interval_us)
{
    sense_dist[0] = (int) (tof_latest_data->distance_m * 1000);
    sense_time[0] = tof_latest_data->received_time_us;
    for (int i = 0; i < ULTRASONIC_COUNT; i++)
    {
        sense_dist[i + 1] = ult_latest_data[i].distance_mm;
        sense_time[i + 1] = ult_latest_data[i].received_time_us;
    }
    // 디버깅용으로 센서값 관련된 변수 모두 출력
    // my_printf("[APS] ToF: %d mm, Ult_L: %d mm, Ult_R: %d mm, Ult_R: %d mm\n",
    //           sense_dist[0], sense_dist[1], sense_dist[2], sense_dist[3]);

    uint64 cur_time = getTimeUs();
    // 디버깅용으로 현재 시간 출력
    // my_printf("[APS] Current time: %llu us\n", cur_time);

    for (int i = 1; i < SENSOR_DATA_COUNT; i++)
    {
        uint64 sensor_delay = cur_time - sense_time[i];
        // 디버깅용으로 센서 지연 시간 출력, 상수인 interval_us값도 출력
        // my_printf("[APS] Sensor %d delay: %llu us (Interval: %llu us)\n", i, sensor_delay, interval_us);
        if (sensor_delay > interval_us)
        {
            // my_printf("[APS] Sensor %d data is too old, skipping...\n", i);
            return 0;
        }
    }

    // 수신한 센서 데이터 디버깅용으로 출력
    my_printf("[APS] Sensor Data: ToF: %d mm, Ult_L: %d mm, Ult_R: %d mm, Ult_R: %d mm\n", sense_dist[0], sense_dist[1],
            sense_dist[2], sense_dist[3]);
    Calc_APS_Result();
    return 1;
}

static int APS_Test_MapJoystickValue (int value)
{
    if (value < 0)
        value = 0;
    if (value > 99)
        value = 99;
    
    return (value * 200 / 99) - 100;
}
/**
 * @brief APS가 판단한 조향/속도 명령을 계산하는 함수
 */
int PHASE_PARKING_EXECUTION_STATE = 1;
// static APS_WallSpaceState_t PHASE_PARKING_EXECUTION_NEW_STATE = WALL_DETECTED;
void Calc_APS_Result (void)
{
    int left_distance = sense_dist[1]; // 근데 어차피 안쓰고있음
    int rear_distance = sense_dist[3];

    switch (current_phase)
    {
        case PHASE_SPACE_DETECTION :
            result_x = 50; // 중립(직진)
            result_y = 70; // 저속 전진
            if (APS_DetectParkingSpace())
            {
                current_phase = PHASE_PARKING_EXECUTION;
                rotate_counter = 0; // 여기서 초기화!^^^
                PHASE_PARKING_EXECUTION_STATE = 1;
                wall_reference_initialized = false; // 공간 탐지 상태 초기

            }
            return;

        case PHASE_PARKING_EXECUTION :
            // 해당 PHASE는 2가지로 나뉨
            // PHASE_PARKING_EXECUTION-1. 공간 탐지 상태가 전이가 될 때까지 후진, 이후 정지.
            // PHASE_PARKING_EXECUTION-2. 회전 후 후진
            
            // PHASE_PARKING_EXECUTION-1
            if (PHASE_PARKING_EXECUTION_STATE == 1)
            {
                current_state = APS_AnalyzeSpace(left_distance);
                // state 출력
                my_printf("[APS] Current state: %s\n",
                        (current_state == WALL_DETECTED) ? "WALL_DETECTED" : "SPACE_DETECTED");
                // 공간 탐지 상태 전이가 되면 정지함
                if (current_state == SPACE_DETECTED)
                {
                    result_x = 50; // 중립
                    result_y = 50; // 정지
                    PHASE_PARKING_EXECUTION_STATE = 2; // 다음 단계로 전이
                    my_printf("[APS] Transition to PHASE_PARKING_EXECUTION-2\n");
                    return;
                }
                else
                {
                    result_x = 50; // 중립
                    result_y = 35; // 후진
                    return;
                }
            }
            // PHASE_PARKING_EXECUTION-2
            else
            {
                my_printf("[APS] Transition to PHASE_PARKING_EXECUTION-2 START--------\n");
                // 90도 회전 후 후진 로직 (rotate_counter 사용)
                if (rotate_counter < ROTATE_LIMIT)
                {
                    result_x = 64;      // 우회전 (값 줄였음)
                    result_y = 45;      // 후진
                    rotate_counter++;
                    my_printf("[APS] Rotating: %d/%d, X: %d, Y: %d\n", rotate_counter, ROTATE_LIMIT, result_x,
                            result_y);
                    
                    int x_speed = APS_Test_MapJoystickValue(result_x);
                    int y_speed = APS_Test_MapJoystickValue(result_y);
                    int left_speed = y_speed + x_speed;
                    int right_speed = y_speed - x_speed;
                    my_printf("[APS] Joystick X:%d Y:%d | Mapped X:%d Y:%d | Left:%d Right:%d\n", result_x, result_y,
                            x_speed, y_speed, left_speed, right_speed);
                    // left_speed = 20, right_speed = -40 이려면 result_x = 70, result_y = 45
                }
                else
                {
                    // 3. 회전 완료 후 센서 기반 조향으로 후진
                    result_x = 50;      // 중립
                    result_y = 35;      // 후진
                    // rear_distance 값을 찍어봄
                    my_printf("[APS] Rotate completed, ready to reverse. Rear distance: %d\n", rear_distance);
                    // my_printf("[APS] After rotate, Steering: %d, Y: %d\n", result_x, result_y);

                    /* 여기에 거리 기반 부저 기능 넣어야함 */
                    // read_distance 값에 따라 3단계로 부저 및 LED 달라짐
                    Emer_Light_Blink_For_APS(rear_distance);

                }

                // 후방 안전거리 도달 시 주차 완료 처리
                if ((rotate_counter >= ROTATE_LIMIT) && (rear_distance <= APS_REAR_SAFETY_DISTANCE_CM))
                {
                    result_x = 50;      // 중립
                    result_y = 50;      // 정지
                    current_phase = PHASE_COMPLETED;
                    my_printf("[APS] Parking completed! Rear distance: %d\n", rear_distance);
                    return;
                }
            }
            return;

        case PHASE_COMPLETED :

            if (Emer_Light_APS_DONE())
            {
                my_printf("[APS] Parking completed and APS_DONE signal received.\n");
                // APS 완료 상태로 전환
                aps_state = 0; // APS off
                is_APS_done = 1; // APS 완료 플래그 설정
                result_x = 50; // 중립
                result_y = 50; // 정지
            }
            return;

        default :
            result_x = 50;
            result_y = 50;
            return;
    }
    my_printf("[APS] Phase: %d, X: %d, Y: %d, Done: %d\n", current_phase, result_x, result_y, is_APS_done);
}

/**
 * @brief 센서 거리값을 기반으로 조향 명령(x값)을 계산하는 함수
 */
int APS_CalculateSteeringFromSensor (int sensor_distance)
{
    int base_steering = 30;
    if (sensor_distance < 15)
    {
        base_steering = 70;
    }
    else if (sensor_distance > 40)
    {
        base_steering = 20;
    }
    if (base_steering < 0)
        base_steering = 0;
    if (base_steering > 99)
        base_steering = 99;
    return base_steering;
}

/**
 * @brief APS가 판단한 결과(조향/속도 명령, 주차 완료 여부)를 외부로 반환하는 함수
 */
void Get_APS_Result (int *res_x, int *res_y, int *is_done)
{
    *res_x = result_x;
    *res_y = result_y;
    *is_done = is_APS_done;
}

/**
 * @brief APS 상태를 설정하는 함수
 */
void Set_APS_State (int state)
{
    if (state < 0 || state > 1)
    {
        my_printf("[APS] Invalid state value: %d\n", state);
        return;
    }
    aps_state = state;

    if (aps_state == 0)
    {
        APS_Init();
    }
}