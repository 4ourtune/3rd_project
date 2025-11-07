#ifndef BSW_CONTROLLER_EMER_ALERT_H_
#define BSW_CONTROLLER_EMER_ALERT_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    int64_t interval_ms;
} EmerAlertData_t;

EmerAlertData_t EmerAlert_GetData (void);
bool EmerAlert_Set_Interval (int64_t toggle_interval_ms);
void EmerAlert_Update_Periodic (void);

#endif /* BSW_CONTROLLER_EMER_ALERT_H_ */
