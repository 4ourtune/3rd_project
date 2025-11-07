#include "emer_alert.h"

#include "stm.h"

#include "Buzzer.h"
#include "LED.h"

static bool isAlertOn = false;
static int64_t g_toggle_interval_ms = -1;

static void EmerAlert_On (void)
{
    if (!isAlertOn)
    {
        LED_On(LED_BACK);
        Buzzer_SetFrequency(500);
        Buzzer_On();
        isAlertOn = true;
    }
}

static void EmerAlert_Off (void)
{
    if (isAlertOn)
    {
        LED_Off(LED_BACK);
        Buzzer_Off();
        isAlertOn = false;
    }
}

static void EmerAlert_Toggle (void)
{
    isAlertOn = !isAlertOn;

    if (isAlertOn)
    {
        LED_On(LED_BACK);
        Buzzer_SetFrequency(500);
        Buzzer_On();
    }
    else
    {
        LED_Off(LED_BACK);
        Buzzer_Off();
    }
}

void EmerAlert_Update_Periodic (void)
{
    static uint64_t last_toggle_time_ms = 0;

    if (g_toggle_interval_ms > 0) // toggle_interval_ms > 0 -> toggle
    {
        uint64_t cur_time_ms = STM0_getTimeMs();

        if (cur_time_ms - last_toggle_time_ms >= (uint64_t) g_toggle_interval_ms)
        {
            EmerAlert_Toggle();
            last_toggle_time_ms = cur_time_ms;
        }
    }
    else if (g_toggle_interval_ms < 0) // toggle_interval_ms < 0 -> off
    {
        EmerAlert_Off();
        last_toggle_time_ms = 0;
    }
    else // toggle_interval_ms == 0 -> on
    {
        EmerAlert_On();
        last_toggle_time_ms = 0;
    }
}

EmerAlertData_t EmerAlert_GetData (void)
{
    EmerAlertData_t ret = {g_toggle_interval_ms};
    return ret;
}

bool EmerAlert_Set_Interval (int64_t toggle_interval_ms)
{
    if (toggle_interval_ms == g_toggle_interval_ms)
        return false;

    g_toggle_interval_ms = toggle_interval_ms;
    return true;
}
