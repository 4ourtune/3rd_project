#ifndef BSW_IO_MOTOR_H_
#define BSW_IO_MOTOR_H_

#include <stdbool.h>
#include <stdint.h>

void Motor_Init (void);
void Motor_SetChA (uint32_t duty, bool dir);
void Motor_SetChB (uint32_t duty, bool dir);

#endif /* BSW_IO_MOTOR_H_ */
