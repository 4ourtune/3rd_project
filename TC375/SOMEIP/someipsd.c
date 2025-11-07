#include "someipsd.h"
#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/udp.h"
#include "Configuration.h"
#include "Ifx_Lwip.h"
#include <string.h>
#include "etc.h"
#include "my_stdio.h"

#if LWIP_UDP

struct udp_pcb *g_SOMEIPSD_PCB;

void SOMEIPSD_Recv_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port);

bool SOMEIPSD_Init (void)
{
    /* SOME/IP-SD Init */
    g_SOMEIPSD_PCB = udp_new();
    if (g_SOMEIPSD_PCB)
    {
        /* bind pcb to the 30490 port */
        /* Using IP_ADDR_ANY allow the pcb to be used by any local interface */
        err_t err = udp_bind(g_SOMEIPSD_PCB, IP_ADDR_ANY, PN_SOMEIPSD);
        delay_ms(100);
        if (err == ERR_OK)
        {
            /* Set a receive callback for the pcb */
            udp_recv(g_SOMEIPSD_PCB, (void*) SOMEIPSD_Recv_Callback, NULL);
            my_printf("SOME/IP-SD PCB Initialized! (Port: %d)\n", PN_SOMEIPSD);
        }
        else
        {
            udp_remove(g_SOMEIPSD_PCB);
            my_printf("SOME/IP-SD PCB init failed\n");
            return false;
        }
    }
    else
    {
        my_printf("Failed to create UDP PCB\n");
        return false;
    }

    return true;
}

void SOMEIPSD_SendOfferService (unsigned char ip_a, unsigned char ip_b, unsigned char ip_c, unsigned char ip_d)
{
    err_t err;
    uint8_t MSG_OfferService[] = {
    /* SOME/IP Header */
    0xFF, 0xFF, 0x81, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00,
    /* SD HEADER */
    0x00, 0x00, 0x00, 0x00,
    /* ENTRIES ARRAY LENGTH */
    0x00, 0x00, 0x00, 0x30,
    /* Entry 1 */
    0x01, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x01,
    /* Entry 2 */
    0x01, 0x01, 0x00, 0x10, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x01,
    /* Entry 3 */
    0x01, 0x02, 0x00, 0x10, 0x03, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x01,
    /* OPTIONS ARRAY LENGTH */
    0x00, 0x00, 0x00, 0x24,
    /* Option 1 */
    0x00, 0x09, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* Option 2 */
    0x00, 0x09, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* Option 3 */
    0x00, 0x09, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t *ip = Ifx_Lwip_getIpAddrPtr();

    // Options Array 1
    MSG_OfferService[80] = ip[0];
    MSG_OfferService[81] = ip[1];
    MSG_OfferService[82] = ip[2];
    MSG_OfferService[83] = ip[3];

    MSG_OfferService[85] = 0x11; // UDP

    MSG_OfferService[86] = (uint8) (PN_SERVICE_1 >> 8) & 0xff;
    MSG_OfferService[87] = (uint8) PN_SERVICE_1 & 0xff;

    // Options Array 2
    MSG_OfferService[92] = ip[0];
    MSG_OfferService[93] = ip[1];
    MSG_OfferService[94] = ip[2];
    MSG_OfferService[95] = ip[3];

    MSG_OfferService[97] = 0x11;

    MSG_OfferService[98] = (uint8) (PN_SERVICE_2 >> 8) & 0xff;
    MSG_OfferService[99] = (uint8) PN_SERVICE_2 & 0xff;

    // Options Array 3
    MSG_OfferService[104] = ip[0];
    MSG_OfferService[105] = ip[1];
    MSG_OfferService[106] = ip[2];
    MSG_OfferService[107] = ip[3];

    MSG_OfferService[109] = 0x11;

    MSG_OfferService[110] = (uint8) (PN_SERVICE_3 >> 8) & 0xff;
    MSG_OfferService[111] = (uint8) PN_SERVICE_3 & 0xff;

    struct pbuf *txbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(MSG_OfferService), PBUF_RAM);
    if (txbuf != NULL)
    {
        udp_connect(g_SOMEIPSD_PCB, IP_ADDR_BROADCAST, PN_SOMEIPSD);
        pbuf_take(txbuf, MSG_OfferService, sizeof(MSG_OfferService));

        ip_addr_t destination_ip;
        IP4_ADDR(&destination_ip, ip_a, ip_b, ip_c, ip_d);
        u16_t destination_port = PN_SOMEIPSD;

        err = udp_sendto(g_SOMEIPSD_PCB, txbuf, &destination_ip, destination_port);
        if (err == ERR_OK)
        {
            my_printf("Send Offer Service Success !!\n");
            my_printf("Offering 0x0100/0x0200/0x0300 from %d.%d.%d.%d to %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3],
                    ip_a, ip_b, ip_c, ip_d);
        }
        else
        {
            my_printf("Send Offer Service Failed !! (Error: %d)\n", err);
        }
        udp_disconnect(g_SOMEIPSD_PCB);

        pbuf_free(txbuf);
    }
    else
    {
        my_printf("Failed to allocate memory for UDP packet buffer.\n");
    }
}

void SOMEIPSD_SendSubEvtGrpAck (unsigned char ip_a, unsigned char ip_b, unsigned char ip_c, unsigned char ip_d)
{
    err_t err;
    uint8_t MSG_SubEvtGrpAck[] = {0xFF, 0xFF, 0x81, 0x00, /* SOMEIP Header */
    0x00, 0x00, 0x00, 0x28, /* SOMEIP Header Length */
    0x00, 0x00, 0x00, 0x01, /* Request ID */
    0x01, 0x01, 0x02, 0x00, /* SOMEIP version information */
    0xC0, 0x00, 0x00, 0x00, /* SOMEIP-SD Flags*/
    0x00, 0x00, 0x00, 0x10, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
            0x01};

    struct pbuf *txbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(MSG_SubEvtGrpAck), PBUF_RAM);
    if (txbuf != NULL)
    {
        udp_connect(g_SOMEIPSD_PCB, IP_ADDR_BROADCAST, PN_SERVICE_1);
        pbuf_take(txbuf, MSG_SubEvtGrpAck, sizeof(MSG_SubEvtGrpAck));

        ip_addr_t destination_ip;
        IP4_ADDR(&destination_ip, ip_a, ip_b, ip_c, ip_d);
        u16_t destination_port = PN_SOMEIPSD;

        err = udp_sendto(g_SOMEIPSD_PCB, txbuf, &destination_ip, destination_port);
        if (err == ERR_OK)
        {
            my_printf("Send SOMEIP Test Message !!\n");
        }
        else
        {
            my_printf("udp_sendto fail!!\n");
        }
        udp_disconnect(g_SOMEIPSD_PCB);

        pbuf_free(txbuf);
    }
    else
    {
        my_printf("Failed to allocate memory for UDP packet buffer.\n");
    }
}

void SOMEIPSD_Recv_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port)
{
    volatile uint16_t ServiceID = 0;
    volatile uint16_t MethodID = 0;
    volatile uint8_t SD_Type = 0;

    if (p != NULL)
    {
        ServiceID = *(uint16_t*) (p->payload);
        MethodID = (*(((uint8_t*) p->payload) + 2) << 8) + *(((uint8_t*) p->payload) + 3);

        unsigned char a = (unsigned char) (addr->addr);
        unsigned char b = (unsigned char) (addr->addr >> 8);
        unsigned char c = (unsigned char) (addr->addr >> 16);
        unsigned char d = (unsigned char) (addr->addr >> 24);

        /* Received SOME/IP-SD */
        if (ServiceID == 0xFFFFU && MethodID == 0x8100U)
        {
            SD_Type = *(((uint8_t*) p->payload) + 24);
            if (SD_Type == 0x00)
            {
                SOMEIPSD_SendOfferService(a, b, c, d);
            }
            else if (SD_Type == 0x06)
            {
                SOMEIPSD_SendSubEvtGrpAck(a, b, c, d);
            }
        }
        pbuf_free(p);
    }
}

#endif /* LWIP_UDP */
