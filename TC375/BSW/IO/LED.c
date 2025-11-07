#include "led.h"

#include "gpio.h"

static bool isOn[LED_SIDE_COUNT];

void LED_Init (void)
{
    /* Initialize */
    GPIO_InitLed();

    /* Set initial state */
    for (int i = 1; i <= 4; i++)
    {
        GPIO_SetLed(i, false);
    }

    for (int i = 0; i < LED_SIDE_COUNT; i++)
    {
        isOn[i] = false;
    }
}

LedData_t LED_GetData (LedSide side)
{
    LedData_t ret = {side, isOn[side]};
    return ret;
}

void LED_On (LedSide side)
{
    switch (side)
    {
        case LED_BACK :
            GPIO_SetLed(3, true);
            GPIO_SetLed(4, true);
            break;
        case LED_FRONT_DOWN :
            GPIO_SetLed(2, true);
            break;
        case LED_FRONT_UP :
            GPIO_SetLed(1, true);
            break;
        default :
            return;
    }
    isOn[side] = true;
}

void LED_Off (LedSide side)
{
    switch (side)
    {
        case LED_BACK :
            GPIO_SetLed(3, false);
            GPIO_SetLed(4, false);
            break;
        case LED_FRONT_DOWN :
            GPIO_SetLed(2, false);
            break;
        case LED_FRONT_UP :
            GPIO_SetLed(1, false);
            break;
        default :
            return;
    }
    isOn[side] = false;
}

void LED_Toggle (LedSide side)
{
    switch (side)
    {
        case LED_BACK :
            GPIO_ToggleLed(3);
            GPIO_ToggleLed(4);
            break;
        case LED_FRONT_DOWN :
            GPIO_ToggleLed(2);
            break;
        case LED_FRONT_UP :
            GPIO_ToggleLed(1);
            break;
        default :
            return;
    }
    isOn[side] = !isOn[side];
}
