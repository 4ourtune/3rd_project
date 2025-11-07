#ifndef BSW_DRIVER_STM_H_
#define BSW_DRIVER_STM_H_

#include <stdbool.h>
#include <stdint.h>

uint64_t STM0_getTime10ns (void);
uint64_t STM0_getTimeUs (void);
uint64_t STM0_getTimeMs (void);

void Stm0_Init (void);
void Stm0_InterruptAfter (uint64_t delay_us);

#endif /* BSW_DRIVER_STM_H_ */
