#include "asclin.h"

#include "IfxAsclin_Asc.h"
#include "IfxAsclin_bf.h"

#include "isr_priority.h"

#include "bluetooth.h"
#include "tof.h"

//IFX_INTERRUPT(Asclin0RxIsrHandler, 0, ISR_PRIORITY_ASCLIN0_RX);
//void Asclin0RxIsrHandler (void)
//{
//    unsigned char ch = Asclin0_InUart();
//    Asclin0_OutUart(ch);
//}

void Asclin0_InitUart (void)
{
    /* set numerator and denominator for 115200 baudrate */
    unsigned int numerator = 576;
    unsigned int denominator = 3125;

    /* RXA/P14.1, TX/P14.0 */
    /* Set TX/P14.0 to "output" and "high" */
    MODULE_P14.IOCR0.B.PC0 = 0x12;
    MODULE_P14.OUT.B.P0 = 1;

    /* Enable ASCn */
    IfxScuWdt_clearCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    MODULE_ASCLIN0.CLC.U = 0;
    IfxScuWdt_setCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    /* read back for activating module */
    (void) MODULE_ASCLIN0.CLC.U;

    /* select RX as input pin */
    MODULE_ASCLIN0.IOCR.B.ALTI = 0; // Select Alternate Input A

    /* Program ASC0 */
    MODULE_ASCLIN0.CSR.U = 0;

    /* configure TX and RX FIFOs */
    MODULE_ASCLIN0.TXFIFOCON.U = (1 << 6) /* INW: (1 == 1 byte) */
    | (1 << 1) /* ENO */
    | (1 << 0); /* FLUSH */
    MODULE_ASCLIN0.RXFIFOCON.U = (1 << 31) /* BUF: (1 == Single Stage RX Buffer) */
    | (1 << 6) /* OUTW: (1 == 1 byte) */
    | (1 << 1) /* ENI */
    | (1 << 0); /* FLUSH */

    /* 115200 */
    MODULE_ASCLIN0.BITCON.U = (9 << 0) /* PRESCALER: 10 */
    | (15 << 16) /* OVERSAMPLING: 16 */
    | (9 << 24) /* SAMPLEPOINT: position 7,8,9 */
    | (1u << 31); /* SM: 3 samples per bit */
    /* data format: 8N1 */
    MODULE_ASCLIN0.FRAMECON.U = (1 << 9) /* STOP: 1 bit */
    | (0 << 16) /* MODE: Init */
    | (0 << 30); /* PEN: no parity */
    MODULE_ASCLIN0.DATCON.U = (7 << 0); /* DATLEN: 8 bit */

    /* set baudrate value */
    MODULE_ASCLIN0.BRG.U = (denominator << 0) /* DENOMINATOR */
    | (numerator << 16); /* NUMERATOR */

    MODULE_ASCLIN0.FRAMECON.B.MODE = 1; /* ASC mode */
    MODULE_ASCLIN0.CSR.U = 1; /* select CLC as clock source */

    MODULE_ASCLIN0.FLAGSSET.U = (IFX_ASCLIN_FLAGSSET_TFLS_MSK << IFX_ASCLIN_FLAGSSET_TFLS_OFF);

    /* Initialize ASCLIN0 RX interrupt */
//    volatile Ifx_SRC_SRCR *src;
//    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.ASCLIN.ASCLIN[0].RX);
//    src->B.SRPN = ISR_PRIORITY_ASCLIN0_RX;
//    src->B.TOS = 0;
//    src->B.CLRR = 1; /* clear request */
//    MODULE_ASCLIN0.FLAGSENABLE.B.RFLE = 1; /* enable rx fifo fill level flag */
//    src->B.SRE = 1; /* interrupt enable */
}

/* Send character CHR via the serial line */
void Asclin0_OutUart (const unsigned char ch)
{
    /* wait until space is available in the FIFO */
    while (!(MODULE_ASCLIN0.FLAGS.B.TFL != 0))
        ;

    /* TX Clear */
    MODULE_ASCLIN0.FLAGSCLEAR.U = (IFX_ASCLIN_FLAGSCLEAR_TFLC_MSK << IFX_ASCLIN_FLAGSCLEAR_TFLC_OFF);

    /* send the character */
    MODULE_ASCLIN0.TXDATA.U = ch;
}

/* Receive (and wait for) a character from the serial line */
unsigned char Asclin0_InUart (void)
{
    unsigned char ch;

    /* wait for a new character */
    while (Asclin0_PollUart(&ch) == 0)
        ;

    return ch;
}

unsigned char Asclin0_InUartNonBlock (void)
{
    unsigned char ch = 0;
    bool res = Asclin0_PollUart(&ch);

    return res == true ? ch : -1;
}

/* Check the serial line if a character has been received.
 returns 1 and the character in *chr if there is one
 else 0
 */
bool Asclin0_PollUart (unsigned char *ch)
{
    unsigned char ret;
    bool res = false;

    if (MODULE_ASCLIN0.FLAGS.B.RFL != 0) /* If RX Ready */
    {
        ret = (unsigned char) MODULE_ASCLIN0.RXDATA.U;
        /* acknowledge receive */
        MODULE_ASCLIN0.FLAGSCLEAR.U = (IFX_ASCLIN_FLAGSCLEAR_RFLC_MSK << IFX_ASCLIN_FLAGSCLEAR_RFLC_OFF); // RX Clear
        /* check for error condition */
        if ((MODULE_ASCLIN0.FLAGS.U)
                & ((IFX_ASCLIN_FLAGS_PE_MSK << IFX_ASCLIN_FLAGS_PE_OFF)
                        | (IFX_ASCLIN_FLAGS_FE_MSK << IFX_ASCLIN_FLAGS_FE_OFF)
                        | (IFX_ASCLIN_FLAGS_RFO_MSK << IFX_ASCLIN_FLAGS_RFO_OFF)))
        {
            /* reset error flags */
            MODULE_ASCLIN0.FLAGSCLEAR.U = ((IFX_ASCLIN_FLAGSCLEAR_PEC_MSK << IFX_ASCLIN_FLAGSCLEAR_PEC_OFF)
                    | (IFX_ASCLIN_FLAGSCLEAR_FEC_MSK << IFX_ASCLIN_FLAGSCLEAR_FEC_OFF)
                    | (IFX_ASCLIN_FLAGSCLEAR_RFOC_MSK << IFX_ASCLIN_FLAGSCLEAR_RFOC_OFF));
            /* Buffer clear, reset module */
        }
        else
        {
            /* this is a valid character */
            *ch = ret;
            res = true;
        }
    }

    return res;
}

IFX_INTERRUPT(Asclin1RxIsrHandler, 0, ISR_PRIORITY_ASCLIN1_RX);
void Asclin1RxIsrHandler (void)
{
    unsigned char ch = Asclin1_InUart();
    Bluetooth_RxHandler(ch);
}

/* Initialise asynchronous interface to operate at baudrate,8,n,1 */
/* ASCLIN1 for mikroBUS */
void Asclin1_InitUart (void)
{
    /* set numerator and denominator for 9600 baudrate */
    unsigned int numerator = 48;
    unsigned int denominator = 3125;

    /* RXA/P15.1, TX/P15.0 */
    /* Set TX/P15.0 to "output" and "high" */
    MODULE_P15.IOCR0.B.PC0 = 0x12;
    MODULE_P15.OUT.B.P0 = 1;

    /* Enable ASCn */
    IfxScuWdt_clearCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    MODULE_ASCLIN1.CLC.U = 0;
    IfxScuWdt_setCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    /* read back for activating module */
    (void) MODULE_ASCLIN1.CLC.U;

    /* select RX as input pin */
    MODULE_ASCLIN1.IOCR.B.ALTI = 0; // Select Alternate Input A

    /* Program ASC1 */
    MODULE_ASCLIN1.CSR.U = 0;

    /* configure TX and RX FIFOs */
    MODULE_ASCLIN1.TXFIFOCON.U = (1 << 6) /* INW: (1 == 1 byte) */
    | (1 << 1) /* ENO */
    | (1 << 0); /* FLUSH */
    MODULE_ASCLIN1.RXFIFOCON.U = (1 << 31) /* BUF: (1 == Single Stage RX Buffer) */
    | (1 << 6) /* OUTW: (1 == 1 byte) */
    | (1 << 1) /* ENI */
    | (1 << 0); /* FLUSH */

    MODULE_ASCLIN1.BITCON.U = (9 << 0) /* PRESCALER: 10 */
    | (15 << 16) /* OVERSAMPLING: 16 */
    | (9 << 24) /* SAMPLEPOINT: position 7,8,9 */
    | (1u << 31); /* SM: 3 samples per bit */
    /* data format: 8N1 */
    MODULE_ASCLIN1.FRAMECON.U = (1 << 9) /* STOP: 1 bit */
    | (0 << 16) /* MODE: Init */
    | (0 << 30); /* PEN: no parity */
    MODULE_ASCLIN1.DATCON.U = (7 << 0); /* DATLEN: 8 bit */

    /* set baudrate value */
    MODULE_ASCLIN1.BRG.U = (denominator << 0) /* DENOMINATOR */
    | (numerator << 16); /* NUMERATOR */

    MODULE_ASCLIN1.FRAMECON.B.MODE = 1; /* ASC mode */
    MODULE_ASCLIN1.CSR.U = 1; /* select CLC as clock source */

    MODULE_ASCLIN1.FLAGSSET.U = (IFX_ASCLIN_FLAGSSET_TFLS_MSK << IFX_ASCLIN_FLAGSSET_TFLS_OFF);

    /* Initialize ASCLIN1 RX interrupt */
    volatile Ifx_SRC_SRCR *src;
    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.ASCLIN.ASCLIN[1].RX);
    src->B.SRPN = ISR_PRIORITY_ASCLIN1_RX;
    src->B.TOS = 0;
    src->B.CLRR = 1; /* clear request */
    MODULE_ASCLIN1.FLAGSENABLE.B.RFLE = 1; /* enable rx fifo fill level flag */
    src->B.SRE = 1; /* interrupt enable */
}

/* Send character CHR via the serial line */
void Asclin1_OutUart (const unsigned char ch)
{
    /* wait until space is available in the FIFO */
    while (!(MODULE_ASCLIN1.FLAGS.B.TFL != 0))
        ;

    /* TX Clear */
    MODULE_ASCLIN1.FLAGSCLEAR.U = (IFX_ASCLIN_FLAGSCLEAR_TFLC_MSK << IFX_ASCLIN_FLAGSCLEAR_TFLC_OFF);

    /* send the character */
    MODULE_ASCLIN1.TXDATA.U = ch;
}

/* Receive (and wait for) a character from the serial line */
unsigned char Asclin1_InUart (void)
{
    unsigned char ch;

    /* wait for a new character */
    while (Asclin1_PollUart(&ch) == 0)
        ;

    return ch;
}

unsigned char Asclin1_InUartNonBlock (void)
{
    unsigned char ch = 0;
    bool res = Asclin1_PollUart(&ch);

    return res == true ? ch : -1;
}

/* Check the serial line if a character has been received.
 returns 1 and the character in *chr if there is one
 else 0
 */
bool Asclin1_PollUart (unsigned char *ch)
{
    unsigned char ret;
    bool res = false;

    if (MODULE_ASCLIN1.FLAGS.B.RFL != 0) /* If RX Ready */
    {
        ret = (unsigned char) MODULE_ASCLIN1.RXDATA.U;
        /* acknowledge receive */
        MODULE_ASCLIN1.FLAGSCLEAR.U = (IFX_ASCLIN_FLAGSCLEAR_RFLC_MSK << IFX_ASCLIN_FLAGSCLEAR_RFLC_OFF); // RX Clear
        /* check for error condition */
        if ((MODULE_ASCLIN1.FLAGS.U)
                & ((IFX_ASCLIN_FLAGS_PE_MSK << IFX_ASCLIN_FLAGS_PE_OFF)
                        | (IFX_ASCLIN_FLAGS_FE_MSK << IFX_ASCLIN_FLAGS_FE_OFF)
                        | (IFX_ASCLIN_FLAGS_RFO_MSK << IFX_ASCLIN_FLAGS_RFO_OFF)))
        {
            /* reset error flags */
            MODULE_ASCLIN1.FLAGSCLEAR.U = ((IFX_ASCLIN_FLAGSCLEAR_PEC_MSK << IFX_ASCLIN_FLAGSCLEAR_PEC_OFF)
                    | (IFX_ASCLIN_FLAGSCLEAR_FEC_MSK << IFX_ASCLIN_FLAGSCLEAR_FEC_OFF)
                    | (IFX_ASCLIN_FLAGSCLEAR_RFOC_MSK << IFX_ASCLIN_FLAGSCLEAR_RFOC_OFF));
            /* Buffer clear, reset module */
        }
        else
        {
            /* this is a valid character */
            *ch = ret;
            res = true;
        }
    }

    return res;
}

IFX_INTERRUPT(Asclin2RxIsrHandler, 0, ISR_PRIORITY_ASCLIN2_RX);
void Asclin2RxIsrHandler (void)
{
    unsigned char ch = Asclin2_InUart();
    ToF_RxHandler(ch);
}

void Asclin2_InitUart (void)
{
    /* set numerator and denominator for 921600 baudrate */
    unsigned int numerator = 2304;
    unsigned int denominator = 3125;

    // ASCLIN2:ATX to P33.9:ALT(2) Transmit output
    /* Set TX/P33.9 to "output" and "high" */
    MODULE_P33.IOCR8.B.PC9 = 0x12;
    MODULE_P33.OUT.B.P9 = 1;

    /* Enable ASCn */
    IfxScuWdt_clearCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    MODULE_ASCLIN2.CLC.U = 0;
    IfxScuWdt_setCpuEndinit(IfxScuWdt_getGlobalEndinitPassword());
    /* read back for activating module */
    (void) MODULE_ASCLIN2.CLC.U;

    // ASCLIN2:ARXE from P33.8:IN Receive input
    /* select RX as input pin */
    MODULE_ASCLIN2.IOCR.B.ALTI = 0x4; // Select Alternate Input E

    /* Program ASC2 */
    MODULE_ASCLIN2.CSR.U = 0;

    /* configure TX and RX FIFOs */
    MODULE_ASCLIN2.TXFIFOCON.U = (1 << 6) /* INW: (1 == 1 byte) */
    | (1 << 1) /* ENO */
    | (1 << 0); /* FLUSH */
    MODULE_ASCLIN2.RXFIFOCON.U = (1 << 31) /* BUF: (1 == Single Stage RX Buffer) */
    | (1 << 6) /* OUTW: (1 == 1 byte) */
    | (1 << 1) /* ENI */
    | (1 << 0); /* FLUSH */

    MODULE_ASCLIN2.BITCON.U = (4 << 0) /* PRESCALER: 5 */
    | (15 << 16) /* OVERSAMPLING: 16 */
    | (9 << 24) /* SAMPLEPOINT: position 7,8,9 */
    | (1u << 31); /* SM: 3 samples per bit */
    /* data format: 8N1 */
    MODULE_ASCLIN2.FRAMECON.U = (1 << 9) /* STOP: 1 bit */
    | (0 << 16) /* MODE: Init */
    | (0 << 30); /* PEN: no parity */
    MODULE_ASCLIN2.DATCON.U = (7 << 0); /* DATLEN: 8 bit */

    /* set baudrate value */
    MODULE_ASCLIN2.BRG.U = (denominator << 0) /* DENOMINATOR */
    | (numerator << 16); /* NUMERATOR */

    MODULE_ASCLIN2.FRAMECON.B.MODE = 1; /* ASC mode */
    MODULE_ASCLIN2.CSR.U = 1; /* select CLC as clock source */

    MODULE_ASCLIN2.FLAGSSET.U = (IFX_ASCLIN_FLAGSSET_TFLS_MSK << IFX_ASCLIN_FLAGSSET_TFLS_OFF);

    /* Initialize ASCLIN2 RX interrupt */
    volatile Ifx_SRC_SRCR *src;
    src = (volatile Ifx_SRC_SRCR*) (&MODULE_SRC.ASCLIN.ASCLIN[2].RX);
    src->B.SRPN = ISR_PRIORITY_ASCLIN2_RX;
    src->B.TOS = 0;
    src->B.CLRR = 1; /* clear request */
    MODULE_ASCLIN2.FLAGSENABLE.B.RFLE = 1; /* enable rx fifo fill level flag */
    src->B.SRE = 1; /* interrupt enable */
}

/* Send character CHR via the serial line */
void Asclin2_OutUart (const unsigned char ch)
{
    /* wait until space is available in the FIFO */
    while (!(MODULE_ASCLIN2.FLAGS.B.TFL != 0))
        ;

    /* TX Clear */
    MODULE_ASCLIN2.FLAGSCLEAR.U = (IFX_ASCLIN_FLAGSCLEAR_TFLC_MSK << IFX_ASCLIN_FLAGSCLEAR_TFLC_OFF);

    /* send the character */
    MODULE_ASCLIN2.TXDATA.U = ch;
}

/* Receive (and wait for) a character from the serial line */
unsigned char Asclin2_InUart (void)
{
    unsigned char ch;

    /* wait for a new character */
    while (Asclin2_PollUart(&ch) == 0)
        ;

    return ch;
}

unsigned char Asclin2_InUartNonBlock (void)
{
    unsigned char ch = 0;
    bool res = Asclin2_PollUart(&ch);

    return res == true ? ch : -1;
}

/* Check the serial line if a character has been received.
 returns 1 and the character in *chr if there is one
 else 0
 */
bool Asclin2_PollUart (unsigned char *ch)
{
    unsigned char ret;
    bool res = false;

    if (MODULE_ASCLIN2.FLAGS.B.RFL != 0) /* If RX Ready */
    {
        ret = (unsigned char) MODULE_ASCLIN2.RXDATA.U;
        /* acknowledge receive */
        MODULE_ASCLIN2.FLAGSCLEAR.U = (IFX_ASCLIN_FLAGSCLEAR_RFLC_MSK << IFX_ASCLIN_FLAGSCLEAR_RFLC_OFF); // RX Clear
        /* check for error condition */
        if ((MODULE_ASCLIN2.FLAGS.U)
                & ((IFX_ASCLIN_FLAGS_PE_MSK << IFX_ASCLIN_FLAGS_PE_OFF)
                        | (IFX_ASCLIN_FLAGS_FE_MSK << IFX_ASCLIN_FLAGS_FE_OFF)
                        | (IFX_ASCLIN_FLAGS_RFO_MSK << IFX_ASCLIN_FLAGS_RFO_OFF)))
        {
            /* reset error flags */
            MODULE_ASCLIN2.FLAGSCLEAR.U = ((IFX_ASCLIN_FLAGSCLEAR_PEC_MSK << IFX_ASCLIN_FLAGSCLEAR_PEC_OFF)
                    | (IFX_ASCLIN_FLAGSCLEAR_FEC_MSK << IFX_ASCLIN_FLAGSCLEAR_FEC_OFF)
                    | (IFX_ASCLIN_FLAGSCLEAR_RFOC_MSK << IFX_ASCLIN_FLAGSCLEAR_RFOC_OFF));
            /* Buffer clear, reset module */
        }
        else
        {
            /* this is a valid character */
            *ch = ret;
            res = true;
        }
    }

    return res;
}
