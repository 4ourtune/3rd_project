#include "gpio.h"

#include "Ifx_reg.h"

/* For buzzer */
void GPIO_InitBuzzer (void)
{
    MODULE_P23.IOCR0.B.PC1 = 0x10;
    MODULE_P23.OUT.B.P1 = 0;
}

void GPIO_SetBuzzer (bool state)
{
    MODULE_P23.OUT.B.P1 = state;
}

void GPIO_ToggleBuzzer (void)
{
    MODULE_P23.OUT.B.P1 ^= 1;
}

/* For led */
void GPIO_InitLed (void)
{
    MODULE_P02.IOCR4.B.PC4 = 0x10;
    MODULE_P02.IOCR4.B.PC5 = 0x10;
    MODULE_P21.IOCR0.B.PC0 = 0x10;
    MODULE_P21.IOCR4.B.PC4 = 0x10;

    MODULE_P02.OUT.B.P4 = 0;
    MODULE_P02.OUT.B.P5 = 0;
    MODULE_P21.OUT.B.P0 = 0;
    MODULE_P21.OUT.B.P4 = 0;
}

void GPIO_SetLed (int led_num, bool state)
{
    switch (led_num)
    {
        case 1 :
            MODULE_P02.OUT.B.P4 = state;
            break;
        case 2 :
            MODULE_P02.OUT.B.P5 = state;
            break;
        case 3 :
            MODULE_P21.OUT.B.P0 = state;
            break;
        case 4 :
            MODULE_P21.OUT.B.P4 = state;
            break;
    }
}

void GPIO_ToggleLed (int led_num)
{
    switch (led_num)
    {
        case 1 :
            MODULE_P02.OUT.B.P4 ^= 1;
            break;
        case 2 :
            MODULE_P02.OUT.B.P5 ^= 1;
            break;
        case 3 :
            MODULE_P21.OUT.B.P0 ^= 1;
            break;
        case 4 :
            MODULE_P21.OUT.B.P4 ^= 1;
            break;
    }
}

/* For motor */
void GPIO_InitMotor (void)
{
    MODULE_P10.IOCR0.B.PC1 = 0x10;  // PWM A DIR
    MODULE_P02.IOCR4.B.PC7 = 0x10;  // PWM A Break
    MODULE_P10.IOCR0.B.PC2 = 0x10;  // PWM B DIR
    MODULE_P02.IOCR4.B.PC6 = 0x10;  // PWM B Break
}

void GPIO_SetMotorDir (int channel, bool dir)
{
    switch (channel)
    {
        case 1 : // chA
            MODULE_P10.OUT.B.P1 = dir;
            break;
        case 2 : // chB
            MODULE_P10.OUT.B.P2 = dir;
            break;
    }
}

void GPIO_SetMotorBrake (int channel, bool state)
{
    switch (channel)
    {
        case 1 : // chA
            MODULE_P02.OUT.B.P7 = state;
            break;
        case 2 : // chB
            MODULE_P02.OUT.B.P6 = state;
            break;
    }
}

/* For ultrasonic */
void GPIO_InitUltTrig (void)
{
    MODULE_P10.IOCR4.B.PC4 = 0x10; // Set P10.4 as output
    MODULE_P10.OUT.B.P4 = 0;
}

void GPIO_SetUltTrig (bool state)
{
    MODULE_P10.OUT.B.P4 = state;
}

void GPIO_ToggleUltTrig (void)
{
    MODULE_P10.OUT.B.P4 ^= 1;
}
