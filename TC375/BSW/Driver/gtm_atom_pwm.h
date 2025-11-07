#ifndef BSW_DRIVER_GTM_ATOM_PWM_H_
#define BSW_DRIVER_GTM_ATOM_PWM_H_

#include <stdbool.h>
#include <stdint.h>

void GtmAtomPwm_Init (void);
void GtmAtomPwmA_SetDutyCycle (uint32_t dutyCycle);
void GtmAtomPwmB_SetDutyCycle (uint32_t dutyCycle);

#endif /* BSW_DRIVER_GTM_ATOM_PWM_H_ */
