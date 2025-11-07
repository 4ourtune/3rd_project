#include "eru.h"

#include "IfxCpu.h"

#include "isr_priority.h"

#include "ultrasonic.h"

IFX_INTERRUPT(SCUERU_Int0_Handler, 0, ISR_PRIORITY_SCUERU0);
void SCUERU_Int0_Handler (void)
{
    bool input_pin_state = MODULE_P15.IN.B.P4;
    Ultrasonic_EchoHandler(ULTRASONIC_LEFT, input_pin_state);
}

IFX_INTERRUPT(SCUERU_Int1_Handler, 0, ISR_PRIORITY_SCUERU1);
void SCUERU_Int1_Handler (void)
{
    bool input_pin_state = MODULE_P15.IN.B.P5;
    Ultrasonic_EchoHandler(ULTRASONIC_RIGHT, input_pin_state);
}

IFX_INTERRUPT(SCUERU_Int2_Handler, 0, ISR_PRIORITY_SCUERU2);
void SCUERU_Int2_Handler (void)
{
    bool input_pin_state = MODULE_P02.IN.B.P0;
    Ultrasonic_EchoHandler(ULTRASONIC_REAR, input_pin_state);
}

void ScuEru_Init0 (void)
{
    uint16_t password = IfxScuWdt_getSafetyWatchdogPasswordInline();
    IfxScuWdt_clearSafetyEndinitInline(password);

    MODULE_P15.IOCR4.B.PC4 = 0x02; /* Set P15.4 as pull-up input */

    /* EICR.EXIS 레지스터 설정 */
    MODULE_SCU.EICR[0].B.EXIS0 = 0;
    /* rising, falling edge 트리거 설정 */
    MODULE_SCU.EICR[0].B.REN0 = 1;
    MODULE_SCU.EICR[0].B.FEN0 = 1;
    /* Enable Trigger Pulse */
    MODULE_SCU.EICR[0].B.EIEN0 = 1;
    /* Determination of output channel for trigger event (Register INP) */
    MODULE_SCU.EICR[0].B.INP0 = 0;
    /* Configure Output channels, outputgating unit OGU (Register IGPy) */
    MODULE_SCU.IGCR[0].B.IGP0 = 1;

    volatile Ifx_SRC_SRCR *src;
    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.SCU.SCUERU[0]);
    src->B.SRPN = ISR_PRIORITY_SCUERU0;
    src->B.TOS = 0;
    src->B.CLRR = 1; /* clear request */
    src->B.SRE = 1; /* interrupt enable */

    IfxScuWdt_setSafetyEndinitInline(password);
}

void ScuEru_Init1 (void)
{
    uint16_t password = IfxScuWdt_getSafetyWatchdogPasswordInline();
    IfxScuWdt_clearSafetyEndinitInline(password);

    MODULE_P15.IOCR4.B.PC5 = 0x02; /* Set P15.5 as pull-up input */

    /* EICR.EXIS 레지스터 설정 */
    MODULE_SCU.EICR[2].B.EXIS0 = 3;
    /* rising, falling edge 트리거 설정 */
    MODULE_SCU.EICR[2].B.REN0 = 1;
    MODULE_SCU.EICR[2].B.FEN0 = 1;
    /* Enable Trigger Pulse */
    MODULE_SCU.EICR[2].B.EIEN0 = 1;
    /* Determination of output channel for trigger event (Register INP) */
    MODULE_SCU.EICR[2].B.INP0 = 1;
    /* Configure Output channels, outputgating unit OGU (Register IGPy) */
    MODULE_SCU.IGCR[0].B.IGP1 = 1;

    volatile Ifx_SRC_SRCR *src;
    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.SCU.SCUERU[1]);
    src->B.SRPN = ISR_PRIORITY_SCUERU1;
    src->B.TOS = 0;
    src->B.CLRR = 1; /* clear request */
    src->B.SRE = 1; /* interrupt enable */

    IfxScuWdt_setSafetyEndinitInline(password);
}

void ScuEru_Init2 (void)
{
    uint16_t password = IfxScuWdt_getSafetyWatchdogPasswordInline();
    IfxScuWdt_clearSafetyEndinitInline(password);

    MODULE_P02.IOCR0.B.PC0 = 0x02; /* Set P02.0 as pull-up input */

    /* EICR.EXIS 레지스터 설정 */
    MODULE_SCU.EICR[1].B.EXIS1 = 2;
    /* rising, falling edge 트리거 설정 */
    MODULE_SCU.EICR[1].B.REN1 = 1;
    MODULE_SCU.EICR[1].B.FEN1 = 1;
    /* Enable Trigger Pulse */
    MODULE_SCU.EICR[1].B.EIEN1 = 1;
    /* Determination of output channel for trigger event (Register INP) */
    MODULE_SCU.EICR[1].B.INP1 = 2;
    /* Configure Output channels, outputgating unit OGU (Register IGPy) */
    MODULE_SCU.IGCR[1].B.IGP0 = 1;

    volatile Ifx_SRC_SRCR *src;
    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.SCU.SCUERU[2]);
    src->B.SRPN = ISR_PRIORITY_SCUERU2;
    src->B.TOS = 0;
    src->B.CLRR = 1; /* clear request */
    src->B.SRE = 1; /* interrupt enable */

    IfxScuWdt_setSafetyEndinitInline(password);
}
