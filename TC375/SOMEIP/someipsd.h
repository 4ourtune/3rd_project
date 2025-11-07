#ifndef SOMEIP_SOMEIPSD_H_
#define SOMEIP_SOMEIPSD_H_

#include <stdbool.h>

bool SOMEIPSD_Init (void);
void SOMEIPSD_SendSubEvtGrpAck (unsigned char ip_a, unsigned char ip_b, unsigned char ip_c, unsigned char ip_d);
void SOMEIPSD_SendOfferService (unsigned char ip_a, unsigned char ip_b, unsigned char ip_c, unsigned char ip_d);

#endif /* SOMEIP_SOMEIPSD_H_ */
