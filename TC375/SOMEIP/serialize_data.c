#include "serialize_data.h"

#include <string.h>
#include <lwip/inet.h>

uint16_t Serialize_PRData (uint8_t *txBuf, uint16_t txLen, const PRData_t *data)
{
    // 1) val (uint32_t → big-endian)
    uint32_t val = htonl(data->val);
    memcpy(&txBuf[txLen], &val, 4);
    txLen += 4;

    // 2) received_time_us (uint64_t → 상/하위 32비트 나눠서 big-endian)
    uint64_t time_val = data->received_time_us;
    uint32_t high = htonl((uint32_t ) (time_val >> 32));
    uint32_t low = htonl((uint32_t ) (time_val & 0xFFFFFFFF));
    memcpy(&txBuf[txLen], &high, 4);
    memcpy(&txBuf[txLen + 4], &low, 4);
    txLen += 8;

    return txLen;
}

uint16_t Serialize_ToFData (uint8_t *txBuf, uint16_t txLen, const ToFData_t *data)
{
    // 1) id
    txBuf[txLen++] = data->id;

    // 2) system_time_ms (uint32_t → big-endian)
    uint32_t t = htonl(data->system_time_ms);
    memcpy(&txBuf[txLen], &t, 4);
    txLen += 4;

    // 3) distance_m (float → uint32_t 비트 단위로 변환 후 big-endian)
    uint32_t f;
    memcpy(&f, &data->distance_m, 4);
    f = htonl(f);
    memcpy(&txBuf[txLen], &f, 4);
    txLen += 4;

    // 4) distance_status
    txBuf[txLen++] = data->distance_status;

    // 5) signal_strength (uint16_t → big-endian)
    uint16_t s = htons(data->signal_strength);
    memcpy(&txBuf[txLen], &s, 2);
    txLen += 2;

    // 6) received_time_us (uint64_t → 상/하위 32비트 분리 후 big-endian)
    uint64_t val = data->received_time_us;
    uint32_t high = htonl((uint32_t ) (val >> 32));
    uint32_t low = htonl((uint32_t ) (val & 0xFFFFFFFF));
    memcpy(&txBuf[txLen], &high, 4);
    memcpy(&txBuf[txLen + 4], &low, 4);
    txLen += 8;

    return txLen;
}

uint16_t Serialize_UltrasonicData (uint8_t *txBuf, uint16_t txLen, const UltrasonicData_t *data)
{
    // 1) dist_raw_mm (int32_t → big-endian)
    int32_t raw = htonl(data->dist_raw_mm);
    memcpy(&txBuf[txLen], &raw, 4);
    txLen += 4;

    // 2) dist_filt_mm (int32_t → big-endian)
    int32_t filt = htonl(data->dist_filt_mm);
    memcpy(&txBuf[txLen], &filt, 4);
    txLen += 4;

    // 3) received_time_us (uint64_t → 상/하위 32비트 나눠서 big-endian)
    uint64_t val = data->received_time_us;
    uint32_t high = htonl((uint32_t ) (val >> 32));
    uint32_t low = htonl((uint32_t ) (val & 0xFFFFFFFF));
    memcpy(&txBuf[txLen], &high, 4);
    memcpy(&txBuf[txLen + 4], &low, 4);
    txLen += 8;

    return txLen;
}

uint16_t Serialize_BuzzerData (uint8_t *txBuf, uint16_t txLen, const BuzzerData_t *data)
{
    // 1) isOn (bool → 1 byte)
    txBuf[txLen++] = data->isOn ? 0x01 : 0x00;

    // 2) frequency (int32_t → big-endian)
    int32_t freq = htonl(data->frequency);
    memcpy(&txBuf[txLen], &freq, 4);
    txLen += 4;

    return txLen;
}

uint16_t Serialize_LedData (uint8_t *txBuf, uint16_t txLen, const LedData_t *data)
{
    // 1) side (LedSide → 1 byte)
    txBuf[txLen++] = (uint8_t) data->side;

    // 2) isOn (bool → 1 byte)
    txBuf[txLen++] = data->isOn ? 0x01 : 0x00;

    return txLen;
}

uint16_t Serialize_EmerAlertData (uint8_t *txBuf, uint16_t txLen, const EmerAlertData_t *data)
{
    // 1) interval_ms (int64_t → Big Endian)
    int64_t interval = data->interval_ms;
    uint32_t interval_high = htonl((uint32_t )(interval >> 32));
    uint32_t interval_low = htonl((uint32_t )(interval & 0xFFFFFFFF));
    memcpy(&txBuf[txLen], &interval_high, 4);
    memcpy(&txBuf[txLen + 4], &interval_low, 4);
    txLen += 8;

    return txLen;
}

uint16_t Serialize_MotorControllerData (uint8_t *txBuf, uint16_t txLen, const MotorControllerData_t *data)
{
    // 1) x (int32_t → Big Endian)
    int32_t x_be = htonl(data->x);
    memcpy(&txBuf[txLen], &x_be, 4);
    txLen += 4;

    // 2) y (int32_t → Big Endian)
    int32_t y_be = htonl(data->y);
    memcpy(&txBuf[txLen], &y_be, 4);
    txLen += 4;

    // 3) motorChA_speed (int32_t → Big Endian)
    int32_t a_be = htonl(data->motorChA_speed);
    memcpy(&txBuf[txLen], &a_be, 4);
    txLen += 4;

    // 4) motorChB_speed (int32_t → Big Endian)
    int32_t b_be = htonl(data->motorChB_speed);
    memcpy(&txBuf[txLen], &b_be, 4);
    txLen += 4;

    return txLen;
}
