#ifndef BSW_IO_LED_H_
#define BSW_IO_LED_H_

#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    LED_BACK = 0, LED_FRONT_DOWN, LED_FRONT_UP, LED_SIDE_COUNT
} LedSide;

typedef struct
{
    LedSide side;
    bool isOn;
} LedData_t;

void LED_Init (void);
LedData_t LED_GetData (LedSide side);
void LED_On (LedSide side);
void LED_Off (LedSide side);
void LED_Toggle (LedSide side);

#endif /* BSW_IO_LED_H_ */
