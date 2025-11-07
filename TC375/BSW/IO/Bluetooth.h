#ifndef BSW_IO_BLUETOOTH_H_
#define BSW_IO_BLUETOOTH_H_

#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    BLUETOOTH_CMD_INVALID = 0, BLUETOOTH_CMD_MOVE, BLUETOOTH_CMD_PARK
} BluetoothCmdType_t;

typedef struct
{
    BluetoothCmdType_t type;
    int32_t param1;
    int32_t param2;
    uint64_t received_time_us;
} BluetoothData_t;

// 초기화
bool Bluetooth_Init (int buffer_size, int max_bytes);

// 인터럽트에서 호출
void Bluetooth_RxHandler (uint8_t byte);

// 메인 루프에서 호출
void Bluetooth_ProcessQueue (void);

// 최신 데이터 가져오기
bool Bluetooth_GetLatestData (BluetoothData_t *out);

#endif /* BSW_IO_BLUETOOTH_H_ */
