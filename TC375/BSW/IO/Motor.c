#include "motor.h"

#include "gpio.h"
#include "gtm_atom_pwm.h"

void Motor_Init (void)
{
    /* Initialize */
    GtmAtomPwm_Init(); // Init GTM for PWM generation
    GPIO_InitMotor(); // Set dir, break pin as output

    /* Set initial state */
    GtmAtomPwmA_SetDutyCycle(0); // Set duty 0
    GtmAtomPwmB_SetDutyCycle(0); // Set duty 0

    GPIO_SetMotorDir(1, true); // Set to forward
    GPIO_SetMotorDir(2, true);

    GPIO_SetMotorBrake(1, true); // Activate the brakes
    GPIO_SetMotorBrake(2, true);
}

void Motor_SetChA (uint32_t duty, bool dir)
{
    GtmAtomPwmA_SetDutyCycle(duty * 10); // Max input == 100 * 10 (100% PWM duty)
    GPIO_SetMotorDir(1, dir); // true(1): 정방향, false(0): 역방향

    if (duty > 0)
    {
        GPIO_SetMotorBrake(1, false); // 모터 Brake 비활성화 (true: 정지, false: PWM-A에 따라 동작)
    }
    else
    {
        GPIO_SetMotorBrake(1, true); // 모터 Brake 활성화
    }
}

void Motor_SetChB (uint32_t duty, bool dir)
{
    GtmAtomPwmB_SetDutyCycle(duty * 10);
    GPIO_SetMotorDir(2, dir);

    if (duty > 0)
    {
        GPIO_SetMotorBrake(2, false);
    }
    else
    {
        GPIO_SetMotorBrake(2, true);
    }
}
