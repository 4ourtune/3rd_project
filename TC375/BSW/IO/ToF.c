#include "tof.h"

#include "asclin.h"
#include "stm.h"

#include "byte_queue.h"

#define TOF_PACKET_LENGTH 16
#define TOF_PACKET_HEADER 0x57

static ByteQueue rx_queue;
static uint64_t header_timestamp_us[BYTE_QUEUE_MAX_BUF_SIZE];
static int max_bytes_per_call;

static ToFData_t latest_data;
static bool data_ready = false;

bool ToF_Init (int buffer_size, int max_bytes)
{
    /* Initialize */
    if (!ByteQueue_Init(&rx_queue, buffer_size))
        return false;

    max_bytes_per_call = max_bytes;

    Asclin2_InitUart();

    return true;
}

void ToF_RxHandler (uint8_t byte)
{
    if (byte == TOF_PACKET_HEADER)
    {
        header_timestamp_us[rx_queue.tail] = STM0_getTimeUs();
    }

    ByteQueue_Push(&rx_queue, byte);
}

static bool verifyCheckSum (const uint8_t *data, int length)
{
    uint8_t sum = 0;
    for (int i = 0; i < length - 1; ++i)
    {
        sum += data[i];
    }
    return sum == data[length - 1];
}

static bool parseToFPacket (const uint8_t *packet, ToFData_t *out)
{
    if (packet[0] != TOF_PACKET_HEADER)
        return false;
    if (!verifyCheckSum(packet, TOF_PACKET_LENGTH))
        return false;

    out->id = packet[3];

    out->system_time_ms = ((uint32_t) packet[4]) | ((uint32_t) packet[5] << 8) | ((uint32_t) packet[6] << 16)
            | ((uint32_t) packet[7] << 24);

    int32_t dist_raw = (int32_t) (((uint32_t) packet[8] << 8) | ((uint32_t) packet[9] << 16)
            | ((uint32_t) packet[10] << 24)) / 256;
    out->distance_m = dist_raw / 1000.0f;

    out->distance_status = packet[11];

    out->signal_strength = ((uint16_t) packet[12]) | ((uint16_t) packet[13] << 8);

    return true;
}

void ToF_ProcessQueue (void)
{
    static uint8_t packet[TOF_PACKET_LENGTH];
    static int packet_index = 0;
    static uint64_t packet_start_time_us = 0;

    uint8_t byte;
    int bytes_processed = 0;

    while (bytes_processed < max_bytes_per_call && ByteQueue_Pop(&rx_queue, &byte))
    {
        if (packet_index == 0) // 패킷 시작 대기 중
        {
            if (byte == TOF_PACKET_HEADER)
            {
                packet[packet_index++] = byte;
                int head = (rx_queue.head - 1 + rx_queue.capacity) % rx_queue.capacity;
                packet_start_time_us = header_timestamp_us[head];
            }
        }
        else // 패킷 수집 중
        {
            packet[packet_index++] = byte;
            if (packet_index >= TOF_PACKET_LENGTH) // 패킷 길이 도달
            {
                if (parseToFPacket(packet, &latest_data))
                {
                    latest_data.received_time_us = packet_start_time_us;
                    data_ready = true;
                }
                packet_index = 0; // 다음 패킷 준비
            }
        }

        bytes_processed++;
    }
}

bool ToF_GetLatestData (ToFData_t *out)
{
    if (!data_ready)
        return false;

    *out = latest_data;
    data_ready = false;
    return true;
}
