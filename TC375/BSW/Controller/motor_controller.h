#ifndef BSW_CONTROLLER_MOTOR_CONTROLLER_H_
#define BSW_CONTROLLER_MOTOR_CONTROLLER_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    int32_t x;
    int32_t y;
    int32_t motorChA_speed;
    int32_t motorChB_speed;
} MotorControllerData_t;

MotorControllerData_t MotorController_GetData (void);
bool MotorController_ProcessJoystickInput (int x, int y);
bool MotorController_ProcessWASDInput (char key);

#endif /* BSW_CONTROLLER_MOTOR_CONTROLLER_H_ */
