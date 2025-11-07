#include "PR.h"

#include "evadc.h"
#include "stm.h"

void PR_Init (void)
{
    Evadc_Init();
}

PRData_t PR_GetData (void)
{
    PRData_t ret;
    ret.val = Evadc_readPR();
    ret.received_time_us = STM0_getTimeUs();
    return ret;
}
