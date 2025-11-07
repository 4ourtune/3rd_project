#include "Cpu0_Init.h"

#include "Ifx_Types.h"
#include "IfxCpu.h"
#include "IfxScuWdt.h"

//#include "bluetooth.h"
#include "buzzer.h"
#include "led.h"
#include "motor.h"
#include "my_stdio.h"
#include "PR.h"
#include "tof.h"
#include "ultrasonic.h"

#include "Ifx_Lwip.h"
#include "geth_lwip.h"
#include "someip.h"
#include "someipsd.h"

//#define BLUETOOTH_BUFFER_SIZE 64
#define TOF_BUFFER_SIZE 64
#define ULTRASONIC_BUFFER_SIZE 64

//#define BLUETOOTH_MAX_BYTES_PER_CALL 6 // 주행 명령(크기: 6) 덮어쓰기 가능성 있음. 주차 명령(크기: 2) 덮어쓰기 가능성 없음
#define TOF_MAX_BYTES_PER_CALL 16 // ToF 센서 패킷 사이즈. 덮어쓰기 안되도록 조절
#define ULTRASONIC_MAX_EVENTS_PER_CALL (ULTRASONIC_BUFFER_SIZE / 2) // 덮어쓰기 상관 X. 초음파 처리에 너무 시간 걸리지 않도록만 횟수 조절

static bool module_init (void)
{
    bool modules_init_success = true;

//    modules_init_success = modules_init_success && Bluetooth_Init(BLUETOOTH_BUFFER_SIZE, BLUETOOTH_MAX_BYTES_PER_CALL);
    modules_init_success = modules_init_success && ToF_Init(TOF_BUFFER_SIZE, TOF_MAX_BYTES_PER_CALL);
    modules_init_success = modules_init_success
            && Ultrasonic_Init(ULTRASONIC_BUFFER_SIZE, ULTRASONIC_MAX_EVENTS_PER_CALL);

    Buzzer_Init();
    LED_Init();
    Motor_Init();
    MyStdio_Init();
    PR_Init();

    /* Define a MAC Address */
    eth_addr_t ethAddr = {.addr[0] = 0x00, .addr[1] = 0x00, .addr[2] = 0x0c, .addr[3] = 0x11, .addr[4] = 0x11, .addr[5
            ] = 0x11};
    initLwip(ethAddr); /* Initialize LwIP with the MAC address */

    modules_init_success = modules_init_success && SOMEIP_Init();
    modules_init_success = modules_init_success && SOMEIPSD_Init();

    return modules_init_success;
}

IFX_ALIGN(4) IfxCpu_syncEvent g_cpuSyncEvent = 0;

bool core0_init (void)
{
    IfxCpu_enableInterrupts();

    /* !!WATCHDOG0 AND SAFETY WATCHDOG ARE DISABLED HERE!!
     * Enable the watchdogs and service them periodically if it is required
     */
    IfxScuWdt_disableCpuWatchdog(IfxScuWdt_getCpuWatchdogPassword());
    IfxScuWdt_disableSafetyWatchdog(IfxScuWdt_getSafetyWatchdogPassword());

    /* Wait for CPU sync event */
    IfxCpu_emitEvent(&g_cpuSyncEvent);
    IfxCpu_waitEvent(&g_cpuSyncEvent, 1);

    return module_init();
}
