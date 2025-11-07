#ifndef BSW_DRIVER_GPIO_H_
#define BSW_DRIVER_GPIO_H_

#include <stdbool.h>

/* For buzzer */
void GPIO_InitBuzzer (void);
void GPIO_SetBuzzer (bool state);
void GPIO_ToggleBuzzer (void);

/* For led */
void GPIO_InitLed (void);
void GPIO_SetLed (int led_num, bool state);
void GPIO_ToggleLed (int led_num);

/* For motor */
void GPIO_InitMotor (void);
void GPIO_SetMotorDir (int channel, bool dir);
void GPIO_SetMotorBrake (int channel, bool state);

/* For ultrasonic */
void GPIO_InitUltTrig (void);
void GPIO_SetUltTrig (bool state);
void GPIO_ToggleUltTrig (void);

#endif /* BSW_DRIVER_GPIO_H_ */
