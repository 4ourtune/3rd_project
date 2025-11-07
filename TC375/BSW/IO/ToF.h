#ifndef BSW_IO_TOF_H_
#define BSW_IO_TOF_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    uint8_t id;
    uint32_t system_time_ms;
    float distance_m;
    uint8_t distance_status;
    uint16_t signal_strength;
    uint64_t received_time_us;
} ToFData_t;

// 초기화
bool ToF_Init (int buffer_size, int max_bytes);

// 인터럽트에서 호출
void ToF_RxHandler (uint8_t byte);

// 메인 루프에서 호출
void ToF_ProcessQueue (void);

// 최신 데이터 가져오기
bool ToF_GetLatestData (ToFData_t *out);

#endif /* BSW_IO_TOF_H_ */
