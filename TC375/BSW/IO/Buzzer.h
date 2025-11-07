#ifndef BSW_IO_BUZZER_H_
#define BSW_IO_BUZZER_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    bool isOn;
    int32_t frequency;
} BuzzerData_t;

void Buzzer_Init (void);
BuzzerData_t Buzzer_GetData (void);
bool Buzzer_SetFrequency (int freq);
void Buzzer_On (void);
void Buzzer_Off (void);
void Buzzer_Buzz (void);

#endif /* BSW_IO_BUZZER_H_ */
