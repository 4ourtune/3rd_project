#include "Cpu0_Init.h"

#include "Ifx_Lwip.h"

#include "stm.h"

#include "my_stdio.h"
#include "tof.h"
#include "ultrasonic.h"

#include "emer_alert.h"

#include "someipsd.h"

void core0_main (void)
{
    if (!core0_init())
        return;

    while (true)
    {
        /* Process data queues */
        ToF_ProcessQueue();
        Ultrasonic_ProcessQueue();

        /* Check ethernet data & process */
        Ifx_Lwip_pollTimerFlags(); /* Poll LwIP timers and trigger protocols execution if required */
        Ifx_Lwip_pollReceiveFlags(); /* Receive data package through ETH */

        /* Send someip-sd service offer periodically */
        static uint64_t pre_t = 0;
        uint64_t cur_t = STM0_getTimeUs();
        if (cur_t - pre_t > 10000000)
        {
            SOMEIPSD_SendOfferService(192, 168, 2, 255);
            pre_t = cur_t;
        }

        /* Run emer alert */
        EmerAlert_Update_Periodic();
    }
}
