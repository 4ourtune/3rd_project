#include "bluetooth.h"

#include "asclin.h"
#include "stm.h"

#include "byte_queue.h"
#include "my_ctype.h"

#define BLUETOOTH_PACKET_MAX_LEN 8
#define BLUETOOTH_PACKET_TERMINATOR '\0'

static ByteQueue rx_queue;
static uint64_t header_timestamp_us[BYTE_QUEUE_MAX_BUF_SIZE];
static int max_bytes_per_call;

static BluetoothData_t latest_data;
static bool data_ready = false;

bool Bluetooth_Init (int buffer_size, int max_bytes)
{
    /* Initialize */
    if (!ByteQueue_Init(&rx_queue, buffer_size))
        return false;

    max_bytes_per_call = max_bytes;

    Asclin1_InitUart();

    return true;
}

void Bluetooth_RxHandler (uint8_t byte)
{
    static uint8_t pre_byte = BLUETOOTH_PACKET_TERMINATOR;

    if (byte == '\n') // 필터링
        return;

    if (pre_byte == BLUETOOTH_PACKET_TERMINATOR)
    {
        header_timestamp_us[rx_queue.tail] = STM0_getTimeUs();
    }

    ByteQueue_Push(&rx_queue, byte);

    pre_byte = byte;
}

static bool parseTwoDigits (const uint8_t *str, int32_t *out_value)
{
    if (!str || !out_value)
        return false;

    if (!my_isdigit((unsigned char) str[0]) || !my_isdigit((unsigned char) str[1]))
        return false;

    *out_value = (int32_t) ((str[0] - '0') * 10 + (str[1] - '0'));
    return true;
}

static bool parseBluetoothPacket (const uint8_t *packet, BluetoothData_t *out)
{
    if (packet[0] == 'M') // Move
    {
        int32_t mx, my;
        bool valid_x = parseTwoDigits(&packet[1], &mx);
        bool valid_y = parseTwoDigits(&packet[3], &my);

        if (!valid_x || !valid_y)
            return false; // 형식 오류

        out->type = BLUETOOTH_CMD_MOVE;
        out->param1 = mx;
        out->param2 = my;
        return true;
    }
    else if (packet[0] == 'P') // Parking
    {
        out->type = BLUETOOTH_CMD_PARK;
        out->param1 = 0;
        out->param2 = 0;
        return true;
    }

    return false; // 알 수 없는 명령
}

void Bluetooth_ProcessQueue (void)
{
    static uint8_t packet[BLUETOOTH_PACKET_MAX_LEN];
    static int packet_index = 0;
    static uint64_t packet_start_time_us = 0;
    static uint8_t pre_byte = BLUETOOTH_PACKET_TERMINATOR;

    uint8_t byte;
    int bytes_processed = 0;

    while (bytes_processed < max_bytes_per_call && ByteQueue_Pop(&rx_queue, &byte))
    {
        /* 새 패킷 시작 시점 기록 */
        if (pre_byte == BLUETOOTH_PACKET_TERMINATOR)
        {
            int head = (rx_queue.head - 1 + rx_queue.capacity) % rx_queue.capacity;
            packet_start_time_us = header_timestamp_us[head];
        }

        /* 패킷에 바이트 저장 */
        packet[packet_index++] = byte;

        /* 패킷 종료 또는 오버플로 처리 */
        if (byte == BLUETOOTH_PACKET_TERMINATOR) // 패킷 종료
        {
            if (parseBluetoothPacket(packet, &latest_data))
            {
                latest_data.received_time_us = packet_start_time_us;
                data_ready = true;
            }
            packet_index = 0; // 다음 패킷 준비
        }
        else if (packet_index >= BLUETOOTH_PACKET_MAX_LEN) // 오버플로 방지
        {
            packet_index = 0; // 강제 리셋
        }

        pre_byte = byte;
        bytes_processed++;
    }
}

bool Bluetooth_GetLatestData (BluetoothData_t *out)
{
    if (!data_ready)
        return false;

    *out = latest_data;
    data_ready = false;
    return true;
}
