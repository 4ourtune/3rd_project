#include "ultrasonic.h"

#include "eru.h"
#include "gpio.h"
#include "gpt12.h"
#include "stm.h"

#include "eru_event_queue.h"
#include "avg_filter.h"

#define ULT_AVG_FILTER_SIZE 5
#define CALCULATE_DISTANCE(fall_time, rise_time) (((int32_t)((fall_time) - (rise_time)) * 343) / 2000) // mm, Speed of sound : 0.343 mm/us

static EruEventQueue rx_queues[ULTRASONIC_COUNT];
static AverageFilter filters[ULTRASONIC_COUNT];
static int max_events_per_call;

static UltrasonicData_t latest_data[ULTRASONIC_COUNT];
static bool data_ready[ULTRASONIC_COUNT] = {false};

bool Ultrasonic_Init (int buffer_size, int max_events)
{
    /* Initialize */
    for (int i = 0; i < ULTRASONIC_COUNT; ++i)
    {
        if (!EruEventQueue_Init(&rx_queues[i], buffer_size) || !Filter_Init(&filters[i], ULT_AVG_FILTER_SIZE))
            return false;
    }

    max_events_per_call = max_events;

    ScuEru_Init0();
    ScuEru_Init1();
    ScuEru_Init2();
    GPIO_InitUltTrig();
    Gpt1_Init();
//    Stm0_Init();

    /* Set initial state */
    GPIO_SetUltTrig(false);
//    Stm0_InterruptAfter(0);
    Run_Gpt12_T3();

    return true;
}

void Ultrasonic_Trigger (int cntMax)
{
    static int cntDelay = 0;

    if (cntDelay < 2)
    {
        GPIO_ToggleUltTrig();
    }

    cntDelay = (cntDelay + 1) % cntMax;
}

void Ultrasonic_EchoHandler (UltrasonicSide side, bool input_pin_state)
{
    if (side >= ULTRASONIC_COUNT)
        return;

    uint64_t now = STM0_getTimeUs();
    EruEvent evt = {.pin_state = input_pin_state, .timestamp_us = now};
    EruEventQueue_Push(&rx_queues[side], &evt);
}

void Ultrasonic_ProcessQueue (void)
{
    static uint64_t last_rise_time[ULTRASONIC_COUNT] = {0}; // 센서별 마지막 Rising 시각 저장

    for (int ult_idx = 0; ult_idx < ULTRASONIC_COUNT; ++ult_idx)
    {
        EruEvent evt;
        int events_processed = 0;

        while (events_processed < max_events_per_call && EruEventQueue_Pop(&rx_queues[ult_idx], &evt))
        {
            if (evt.pin_state) // Rising edge
            {
                last_rise_time[ult_idx] = evt.timestamp_us;
            }
            else // Falling edge
            {
                if (last_rise_time[ult_idx] > 0) // Rising 기록이 있을 때만 계산
                {
                    int32_t dist_raw = CALCULATE_DISTANCE(evt.timestamp_us, last_rise_time[ult_idx]);
                    int32_t dist_filt = Filter_Update(&filters[ult_idx], dist_raw);

                    latest_data[ult_idx].dist_raw_mm = dist_raw;
                    latest_data[ult_idx].dist_filt_mm = dist_filt;
                    latest_data[ult_idx].received_time_us = last_rise_time[ult_idx];
                    data_ready[ult_idx] = true;
                }
                last_rise_time[ult_idx] = 0; // 다음 측정을 위해 초기화
            }

            events_processed++;
        }
    }
}

bool Ultrasonic_GetLatestData (UltrasonicSide side, UltrasonicData_t *out)
{
    if (side >= ULTRASONIC_COUNT)
        return false;

    if (!data_ready[side])
        return false;

    *out = latest_data[side];
    data_ready[side] = false;
    return true;
}
