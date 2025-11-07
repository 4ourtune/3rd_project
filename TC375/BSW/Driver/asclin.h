#ifndef BSW_DRIVER_ASCLIN_H_
#define BSW_DRIVER_ASCLIN_H_

#include <stdbool.h>

/* ASCLIN0 for micro 5-pin serial communication */
void Asclin0_InitUart (void);
void Asclin0_OutUart (const unsigned char ch);
unsigned char Asclin0_InUart (void);
unsigned char Asclin0_InUartNonBlock (void);
bool Asclin0_PollUart (unsigned char *ch);

/* ASCLIN1 for Bluetooth */
void Asclin1_InitUart (void);
void Asclin1_OutUart (const unsigned char ch);
unsigned char Asclin1_InUart (void);
unsigned char Asclin1_InUartNonBlock (void);
bool Asclin1_PollUart (unsigned char *ch);

/* ASCLIN2 for ToF */
void Asclin2_InitUart (void);
void Asclin2_OutUart (const unsigned char ch);
unsigned char Asclin2_InUart (void);
unsigned char Asclin2_InUartNonBlock (void);
bool Asclin2_PollUart (unsigned char *ch);

#endif /* BSW_DRIVER_ASCLIN_H_ */
