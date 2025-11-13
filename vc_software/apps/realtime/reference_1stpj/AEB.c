#include "aeb.h"
#include "motor_controller.h"
#include "my_stdio.h"

static volatile int aeb_state = AEB_STATE_NORMAL;

static bool AEB_IsEmergencyBrakingRequired (const ToFData_t *tof_latest_data)
{
    int distance_mm;
    distance_mm = (int) (tof_latest_data->distance_m * 1000);

    // 1순위: 10cm + 허용오차 이하면 무조건 긴급제동
    if (distance_mm <= AEB_EMERGENCY_THRESHOLD_MM + AEB_TOLERANCE_MM)
    {
        return true;
    }

    int motorA_speed = MotorController_GetMotorChA();
    int motorB_speed = MotorController_GetMotorChB();

    int vehicle_speed = (motorA_speed + motorB_speed) / 2;

    /* -100 <= vehicle_speed <= 100, 제자리 회전 안됨 */
    if (vehicle_speed <= 0)
    {
        return false;
    }

    // 실측 데이터 기반 제동거리 계산 (완전이차 모델: ax²+bx+c)
    // braking_distance = (AEB_SPEED_COEFF_A * speed² + AEB_SPEED_COEFF_B * speed + AEB_SPEED_COEFF_C) / AEB_SPEED_DIVIDER
    int speed_squared = vehicle_speed * vehicle_speed;
    int numerator = AEB_SPEED_COEFF_A * speed_squared + AEB_SPEED_COEFF_B * vehicle_speed + AEB_SPEED_COEFF_C;
    unsigned int braking_distance_mm = (unsigned int) (numerator / AEB_SPEED_DIVIDER);

    // 제동 조건: 제동 후 목표 정지거리(10cm)에 정확히 멈추도록
    // distance_mm = braking_distance_mm + AEB_EMERGENCY_THRESHOLD_MM 일 때 제동 시작
    if (distance_mm <= (braking_distance_mm + AEB_EMERGENCY_THRESHOLD_MM))
    {
        return true;
    }

    return false;
}

int AEB_UpdateState (const ToFData_t *tof_latest_data, uint64 interval_us)
{
    // interval_us보다 오래된 센서 값이 있으면 return false (업데이트 실패)

    if (AEB_IsEmergencyBrakingRequired(tof_latest_data))
    {
        aeb_state = AEB_STATE_EMERGENCY;
    }
    else
    {
        aeb_state = AEB_STATE_NORMAL;
    }
    return true;
}

int AEB_GetState (void)
{
    return aeb_state;
}

void AEB_SetState (int state)
{
    if (state == AEB_STATE_NORMAL || state == AEB_STATE_EMERGENCY)
    {
        aeb_state = state;
    }
}