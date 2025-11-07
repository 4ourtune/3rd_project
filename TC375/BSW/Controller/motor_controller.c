#include "motor_controller.h"

#include "motor.h"

#include "my_math.h"

// 상수 정의
#define MOTOR_SPEED_MAX     100
#define MOTOR_SPEED_MIN     -100
#define MOTOR_SPEED_CENTER  0
#define JOYSTICK_MAX        99
#define JOYSTICK_MIN        0
#define JOYSTICK_CENTER     50
#define JOYSTICK_DEADZONE   8

// 내부 상태
static MotorControllerData_t latest_data;

// 데이터 가져오기
MotorControllerData_t MotorController_GetData (void)
{
    return latest_data;
}

// 좌/우 모터 속도 설정
static void MotorController_SetSpeed (int left_speed, int right_speed)
{
    latest_data.motorChA_speed = right_speed;
    latest_data.motorChB_speed = left_speed;

    bool left_direction = (left_speed >= 0) ? 1 : 0;
    left_speed = my_abs(left_speed);

    bool right_direction = (right_speed >= 0) ? 1 : 0;
    right_speed = my_abs(right_speed);

    Motor_SetChA(right_speed, right_direction);
    Motor_SetChB(left_speed, left_direction);
}

// 조이스틱 값 매핑 (데드존 포함)
static int MotorController_MapJoystickValue (int value, int deadzone)
{
    int offset = value - JOYSTICK_CENTER;

    if (my_abs(offset) < deadzone)
        return 0;

    offset += (offset > 0) ? -deadzone : deadzone;

    int max_offset = JOYSTICK_CENTER - deadzone;
    if (max_offset <= 0)
        max_offset = 1;

    return (offset * 100) / max_offset;
}

// 조이스틱 입력 처리
bool MotorController_ProcessJoystickInput (int x, int y)
{
    static int pre_x;
    static int pre_y;

    if (x < JOYSTICK_MIN || x > JOYSTICK_MAX || y < JOYSTICK_MIN || y > JOYSTICK_MAX)
        return false;

    if (x == pre_x && y == pre_y)
        return false;

    pre_x = x;
    pre_y = y;
    latest_data.x = x;
    latest_data.y = y;

    int x_speed = MotorController_MapJoystickValue(x, JOYSTICK_DEADZONE);
    int y_speed = MotorController_MapJoystickValue(y, 0); // Y축은 데드존 없음

    x_speed = (x_speed * 60) / 100; // X축 영향 축소 (-60 ~ +60)

    int left_speed = my_clamp(y_speed + x_speed, MOTOR_SPEED_MIN, MOTOR_SPEED_MAX);
    int right_speed = my_clamp(y_speed - x_speed, MOTOR_SPEED_MIN, MOTOR_SPEED_MAX);

    MotorController_SetSpeed(left_speed, right_speed);
    return true;
}

// WASD 입력 처리
bool MotorController_ProcessWASDInput (char key)
{
    static int base_speed = MOTOR_SPEED_CENTER; // 기본 전/후진 속도
    int turn_offset = MOTOR_SPEED_CENTER; // 좌/우 회전 속도 차이

    switch (key)
    {
        case 'w' :
        case 'W' :
            base_speed = MOTOR_SPEED_MAX;
            break; // 전진
        case 's' :
        case 'S' :
            base_speed = MOTOR_SPEED_MIN;
            break; // 후진
        case 'a' :
        case 'A' :
            turn_offset = MOTOR_SPEED_MAX / 2;
            break; // 좌회전
        case 'd' :
        case 'D' :
            turn_offset = MOTOR_SPEED_MIN / 2;
            break; // 우회전
        case 'x' :
        case 'X' :
            base_speed = MOTOR_SPEED_CENTER;
            break; // 정지
        default :
            return false; // 유효하지 않은 키
    }

    // 방향에 따라 실제 좌/우 모터 속도 계산
    int left_speed = base_speed - turn_offset;
    int right_speed = base_speed + turn_offset;

    // 속도 범위 클램핑
    left_speed = my_clamp(left_speed, MOTOR_SPEED_MIN, MOTOR_SPEED_MAX);
    right_speed = my_clamp(right_speed, MOTOR_SPEED_MIN, MOTOR_SPEED_MAX);

    MotorController_SetSpeed(left_speed, right_speed);
    return true;
}
