#include "gtm_atom_pwm.h"

#include "IfxGtm_Atom_Pwm.h"

#define CLK_FREQ 1000000.0f                     // CMU clock frequency, in Hertz
#define PWM_PERIOD 1000                         // PWM period for the ATOM, in ticks

#define PWM_A IfxGtm_ATOM0_1_TOUT1_P02_1_OUT
#define PWM_B IfxGtm_ATOM1_3_TOUT105_P10_3_OUT

IfxGtm_Atom_Pwm_Config g_atomConfig_PwmA;       // Timer configuration structure
IfxGtm_Atom_Pwm_Config g_atomConfig_PwmB;
IfxGtm_Atom_Pwm_Driver g_atomDriver_PwmA;       // Timer Driver structure
IfxGtm_Atom_Pwm_Driver g_atomDriver_PwmB;

void GtmAtomPwm_Init (void)
{
    /* Enable GTM */
    IfxGtm_enable(&MODULE_GTM);

    /* PWM A */
    IfxGtm_Cmu_setClkFrequency(&MODULE_GTM, IfxGtm_Cmu_Clk_0, CLK_FREQ);    // Set frequency of CMU clock 0
    IfxGtm_Cmu_enableClocks(&MODULE_GTM, IFXGTM_CMU_CLKEN_CLK0);            // Enable CMU clock 0

    IfxGtm_Atom_Pwm_initConfig(&g_atomConfig_PwmA, &MODULE_GTM);            // Initialize default PWM configuration

    g_atomConfig_PwmA.atom = PWM_A.atom;                                    // Select ATOM module
    g_atomConfig_PwmA.atomChannel = PWM_A.channel;                          // Select ATOM channel
    g_atomConfig_PwmA.period = PWM_PERIOD;                                  // Set timer period
    g_atomConfig_PwmA.pin.outputPin = &PWM_A;                               // Assign output pin for PWM
    g_atomConfig_PwmA.synchronousUpdateEnabled = true;                      // Enable synchronous update

    IfxGtm_Atom_Pwm_init(&g_atomDriver_PwmA, &g_atomConfig_PwmA);           // Initialize the PWM
    IfxGtm_Atom_Pwm_start(&g_atomDriver_PwmA, true);                        // Start PWM output

    /* PWM B */
    IfxGtm_Cmu_setClkFrequency(&MODULE_GTM, IfxGtm_Cmu_Clk_1, CLK_FREQ);
    IfxGtm_Cmu_enableClocks(&MODULE_GTM, IFXGTM_CMU_CLKEN_CLK1);

    IfxGtm_Atom_Pwm_initConfig(&g_atomConfig_PwmB, &MODULE_GTM);

    g_atomConfig_PwmB.atom = PWM_B.atom;
    g_atomConfig_PwmB.atomChannel = PWM_B.channel;
    g_atomConfig_PwmB.period = PWM_PERIOD;
    g_atomConfig_PwmB.pin.outputPin = &PWM_B;
    g_atomConfig_PwmB.synchronousUpdateEnabled = true;

    IfxGtm_Atom_Pwm_init(&g_atomDriver_PwmB, &g_atomConfig_PwmB);
    IfxGtm_Atom_Pwm_start(&g_atomDriver_PwmB, true);
}

void GtmAtomPwmA_SetDutyCycle (uint32_t dutyCycle)
{
    g_atomConfig_PwmA.dutyCycle = dutyCycle;                        // Set duty cycle
    IfxGtm_Atom_Pwm_init(&g_atomDriver_PwmA, &g_atomConfig_PwmA);   // Re-initialize the PWM
}

void GtmAtomPwmB_SetDutyCycle (uint32_t dutyCycle)
{
    g_atomConfig_PwmB.dutyCycle = dutyCycle;
    IfxGtm_Atom_Pwm_init(&g_atomDriver_PwmB, &g_atomConfig_PwmB);
}
