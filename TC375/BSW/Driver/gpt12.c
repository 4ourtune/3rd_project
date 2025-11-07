#include "gpt12.h"

#include "IfxGpt12.h"

#include "isr_priority.h"
#include "gpio.h"
#include "stm.h"

#include "buzzer.h"
#include "Ultrasonic.h"

/* fGPT = 100MHz = 10^8Hz = (2^8 * 5^8)Hz */
static const uint32_t GPT1_BLOCK_PRESCALER = 0x2; // Set GPT1 block prescaler: 2^5 = 32
static const uint32_t TIMER_T3_INPUT_PRESCALER = 0x1; // Set T3 input prescaler: 2^1 = 2
static const uint32_t TIMER_T3_T2_VALUE = 15625; // Set timer T3, T2 value: 5^6 = 15625

IFX_INTERRUPT(IsrGpt1T3Handler, 0, ISR_PRIORITY_GPT1T3_TIMER);
void IsrGpt1T3Handler (void) // (2^2 * 5^2)Hz = 100Hz = 0.01sec = 10ms
{
    /* Ultrasonic sensor: Set the period to 100ms. 38ms(Max echo back pulse duration) + Margin including trigger pulse */
    Ultrasonic_Trigger(10); // 10ms * 10 = 100ms
}

void Run_Gpt12_T3 ()
{
    IfxGpt12_T3_run(&MODULE_GPT120, IfxGpt12_TimerRun_start);
}

void Stop_Gpt12_T3 ()
{
    IfxGpt12_T3_run(&MODULE_GPT120, IfxGpt12_TimerRun_stop);
}

void Gpt1_Init (void)
{
    IfxScuWdt_clearCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    MODULE_GPT120.CLC.U = 0;
    IfxScuWdt_setCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());

    /* Initialize the Timer T3 */
    MODULE_GPT120.T3CON.B.T3M = 0x0; // Set T3 to timer mode
    MODULE_GPT120.T3CON.B.T3UD = 0x1; // Set T3 count direction(down)
    MODULE_GPT120.T3CON.B.BPS1 = GPT1_BLOCK_PRESCALER; // Set GPT1 block prescaler
    MODULE_GPT120.T3CON.B.T3I = TIMER_T3_INPUT_PRESCALER; // Set T3 input prescaler

    /* Calculate dutyUpTime and dutyDownTime for reloading timer T3 */
    MODULE_GPT120.T3.U = TIMER_T3_T2_VALUE; // Set timer T3 value

    /* Timer T2: reloads the value DutyDownTime in timer T3 */
    MODULE_GPT120.T2CON.B.T2M = 0x4; // Set the timer T2 in reload mode
    MODULE_GPT120.T2CON.B.T2I = 0x7; // Reload Input Mode : Rising/Falling Edge T3OTL
    MODULE_GPT120.T2.U = TIMER_T3_T2_VALUE;

    /* Initialize the interrupt */
    volatile Ifx_SRC_SRCR *src;
    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.GPT12.GPT12[0].T3);
    src->B.SRPN = ISR_PRIORITY_GPT1T3_TIMER;
    src->B.TOS = 0;
    src->B.CLRR = 1; // Clear request
    src->B.SRE = 1; // Interrupt enable
}

IFX_INTERRUPT(IsrGpt2T6Handler, 0, ISR_PRIORITY_GPT2T6_TIMER);
void IsrGpt2T6Handler (void)
{
    Buzzer_Buzz();
}

void Run_Gpt12_T6 (void)
{
    IfxGpt12_T6_run(&MODULE_GPT120, IfxGpt12_TimerRun_start);
}

void Stop_Gpt12_T6 (void)
{
    IfxGpt12_T6_run(&MODULE_GPT120, IfxGpt12_TimerRun_stop);
}

void Gpt2_Init (void)
{
    IfxScuWdt_clearCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    MODULE_GPT120.CLC.U = 0;
    IfxScuWdt_setCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());

    /* Initialize the Timer T6 */
    MODULE_GPT120.T6CON.B.BPS2 = 0x0; // Set GPT2 block prescaler
    MODULE_GPT120.T6CON.B.T6M = 0x0; // Set T6 to timer mode
    MODULE_GPT120.T6CON.B.T6UD = 0x1; // Set T6 count direction(down)
    MODULE_GPT120.T6CON.B.T6I = 0x0; // Set T6 input prescaler
    MODULE_GPT120.T6CON.B.T6OE = 0x1; // Overflow/Underflow Output Enable
    MODULE_GPT120.T6CON.B.T6SR = 0x1; // Reload from register CAPREL Enabled
    MODULE_GPT120.T6.U = 25u; // Set T6 start value

    MODULE_GPT120.CAPREL.U = 25u; // Set CAPREL reload value

    /* Initialize the interrupt */
    volatile Ifx_SRC_SRCR *src;
    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.GPT12.GPT12[0].T6);
    src->B.SRPN = ISR_PRIORITY_GPT2T6_TIMER;
    src->B.TOS = 0;
    src->B.CLRR = 1; // Clear request
    src->B.SRE = 1; // Interrupt enable
}
