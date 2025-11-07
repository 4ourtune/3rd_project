#ifndef BSW_IO_PR_H_
#define BSW_IO_PR_H_

#include <stdint.h>

typedef struct
{
    uint32_t val;
    uint64_t received_time_us;
} PRData_t;

void PR_Init (void);
PRData_t PR_GetData (void);

#endif /* BSW_IO_PR_H_ */
