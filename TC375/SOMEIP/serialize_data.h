#ifndef SOMEIP_SERIALIZE_DATA_H_
#define SOMEIP_SERIALIZE_DATA_H_

#include <stdint.h>

#include "Buzzer.h"
#include "LED.h"
#include "PR.h"
#include "ToF.h"
#include "Ultrasonic.h"

#include "motor_controller.h"
#include "emer_alert.h"

uint16_t Serialize_PRData (uint8_t *txBuf, uint16_t txLen, const PRData_t *data);
uint16_t Serialize_ToFData (uint8_t *txBuf, uint16_t txLen, const ToFData_t *data);
uint16_t Serialize_UltrasonicData (uint8_t *txBuf, uint16_t txLen, const UltrasonicData_t *data);

uint16_t Serialize_BuzzerData (uint8_t *txBuf, uint16_t txLen, const BuzzerData_t *data);
uint16_t Serialize_LedData (uint8_t *txBuf, uint16_t txLen, const LedData_t *data);

uint16_t Serialize_EmerAlertData (uint8_t *txBuf, uint16_t txLen, const EmerAlertData_t *data);
uint16_t Serialize_MotorControllerData (uint8_t *txBuf, uint16_t txLen, const MotorControllerData_t *data);

#endif /* SOMEIP_SERIALIZE_DATA_H_ */
