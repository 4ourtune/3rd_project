#include "buzzer.h"

#include "gpio.h"
#include "gpt12.h"

#define MAX_FREQ 250000

static int frequency;
static int cntMax;
static bool isOn;

void Buzzer_Init (void)
{
    /* Initialize */
    GPIO_InitBuzzer();
    Gpt2_Init();

    /* Set initial state */
    Stop_Gpt12_T6();
    GPIO_SetBuzzer(false);
    frequency = MAX_FREQ;
    cntMax = 1;
    isOn = false;
}

BuzzerData_t Buzzer_GetData (void)
{
    BuzzerData_t ret = {isOn, frequency};
    return ret;
}

bool Buzzer_SetFrequency (int freq)
{
    if (!(1 <= freq && freq <= MAX_FREQ))
        return false;

    frequency = freq;
    cntMax = (int) (MAX_FREQ / freq);
    return true;
}

void Buzzer_On (void)
{
    if (!isOn)
    {
        Run_Gpt12_T6();
        isOn = true;
    }
}

void Buzzer_Off (void)
{
    if (isOn)
    {
        Stop_Gpt12_T6();
        isOn = false;
    }
}

void Buzzer_Buzz (void)
{
    static int cntDelay = 0;

    if (cntDelay == 0)
    {
        GPIO_ToggleBuzzer();
    }

    cntDelay = (cntDelay + 1) % cntMax;
}
