#ifndef BSW_IO_ULTRASONIC_H_
#define BSW_IO_ULTRASONIC_H_

#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    ULTRASONIC_LEFT = 0, ULTRASONIC_RIGHT, ULTRASONIC_REAR, ULTRASONIC_COUNT
} UltrasonicSide;

typedef struct
{
    int32_t dist_raw_mm;
    int32_t dist_filt_mm;
    uint64_t received_time_us;
} UltrasonicData_t;

bool Ultrasonic_Init (int buffer_size, int max_events);
void Ultrasonic_Trigger (int cntMax);
void Ultrasonic_EchoHandler (UltrasonicSide side, bool input_pin_state);
void Ultrasonic_ProcessQueue (void);
bool Ultrasonic_GetLatestData (UltrasonicSide side, UltrasonicData_t *out);

#endif /* BSW_IO_ULTRASONIC_H_ */
