#include "someip.h"
#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/udp.h"
#include "Configuration.h"
#include "Ifx_Lwip.h"

#include <string.h>

#include "Buzzer.h"
#include "LED.h"
#include "my_stdio.h"
#include "PR.h"
#include "ToF.h"
#include "Ultrasonic.h"

#include "emer_alert.h"
#include "motor_controller.h"

#include "serialize_data.h"

#if LWIP_UDP

static bool SOMEIP_UPCB_Init (struct udp_pcb **pcb_ptr, uint16_t port, udp_recv_fn recv);
void SOMEIP_Service1_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port);
void SOMEIP_Service2_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port);
void SOMEIP_Service3_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port);
static inline void SOMEIP_Update_Length (uint8_t *txBuf, uint16_t txLen);
static void SOMEIP_Send_Data (struct udp_pcb *upcb, uint8_t *txBuf, uint16_t txLen, const ip_addr_t *addr,
        uint16_t port);

struct udp_pcb *g_SOMEIP_SERVICE1_PCB;
struct udp_pcb *g_SOMEIP_SERVICE2_PCB;
struct udp_pcb *g_SOMEIP_SERVICE3_PCB;

bool SOMEIP_Init (void)
{
    if (!SOMEIP_UPCB_Init(&g_SOMEIP_SERVICE1_PCB, PN_SERVICE_1, (void*) SOMEIP_Service1_Callback))
        return false;
    if (!SOMEIP_UPCB_Init(&g_SOMEIP_SERVICE2_PCB, PN_SERVICE_2, (void*) SOMEIP_Service2_Callback))
        return false;
    if (!SOMEIP_UPCB_Init(&g_SOMEIP_SERVICE3_PCB, PN_SERVICE_3, (void*) SOMEIP_Service3_Callback))
        return false;

    return true;
}

static bool SOMEIP_UPCB_Init (struct udp_pcb **pcb_ptr, uint16_t port, udp_recv_fn recv)
{
    struct udp_pcb *SOMEIP_SERVICE_PCB = udp_new();
    if (SOMEIP_SERVICE_PCB)
    {
        /* bind pcb to the port */
        /* Using IP_ADDR_ANY allow the pcb to be used by any local interface */
        err_t err = udp_bind(SOMEIP_SERVICE_PCB, IP_ADDR_ANY, port);
        if (err == ERR_OK)
        {
            /* Set a receive callback for the pcb */
            udp_recv(SOMEIP_SERVICE_PCB, recv, NULL);
            my_printf("SOME/IP Service PCB Initialized! (Port: %d)\n", port);
        }
        else
        {
            udp_remove(SOMEIP_SERVICE_PCB);
            my_printf("SOME/IP Service PCB init failed!\n");
            return false;
        }
    }
    else
    {
        my_printf("Failed to create UDP PCB\n");
        return false;
    }

    *pcb_ptr = SOMEIP_SERVICE_PCB;
    return true;
}

void SOMEIP_Service1_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port)
{
    static PRData_t pr_latest_data;
    static ToFData_t tof_latest_data;
    static UltrasonicData_t ult_latest_data[ULTRASONIC_COUNT];

    if (p == NULL)
    {
        return;
    }

    // 수신 버퍼 크기 검증 (SOME/IP 최소 헤더: 16 bytes)
    if (p->len < 16 || p->len > 512)
    {
        my_printf("Invalid packet size: %d\n", p->len);
        pbuf_free(p);
        return;
    }

    uint8_t rxBuf[512];
    memcpy(rxBuf, p->payload, p->len);

    uint16_t ServiceID = (rxBuf[0] << 8) + rxBuf[1];
    uint16_t MethodID = (rxBuf[2] << 8) + rxBuf[3];
    uint8_t MessageType = rxBuf[14];

    // Service ID 및 Message Type 확인
    if (ServiceID == 0x0100U && MessageType == 0x00)
    {
        uint8_t txBuf[256];
        uint16_t txLen = 0;

        // SOME/IP 헤더 복사 (16 bytes)
        memcpy(txBuf, rxBuf, 16);
        // Message Type을 Response로 변경
        txBuf[14] = 0x80;

        // Method ID에 따라 처리
        if (MethodID == 0x0101U)
        {
            txLen = 16;
            pr_latest_data = PR_GetData();
            my_printf("PR: val=%lu, t=%llu\n", pr_latest_data.val, pr_latest_data.received_time_us);
            txLen = Serialize_PRData(txBuf, txLen, &pr_latest_data);
        }
        else if (MethodID == 0x0102U)
        {
            txLen = 16;
            ToF_GetLatestData(&tof_latest_data);
            my_printf("ToF: dist=%f, t=%llu\n", tof_latest_data.distance_m, tof_latest_data.received_time_us);
            txLen = Serialize_ToFData(txBuf, txLen, &tof_latest_data);
        }
        else if (MethodID == 0x0103U)
        {
            txLen = 16;
            txBuf[txLen++] = ULTRASONIC_COUNT;

            for (int i = 0; i < ULTRASONIC_COUNT; i++)
            {
                Ultrasonic_GetLatestData(i, &ult_latest_data[i]);
                my_printf("Ult%d: dist_raw=%d, dist_filt=%d, t=%llu\n", i, ult_latest_data[i].dist_raw_mm,
                        ult_latest_data[i].dist_filt_mm, ult_latest_data[i].received_time_us);
                txLen = Serialize_UltrasonicData(txBuf, txLen, &ult_latest_data[i]);
            }
        }

        if (txLen > 0)
        {
            // SOME/IP Length 필드 업데이트
            SOMEIP_Update_Length(txBuf, txLen);

            // 응답 전송
            SOMEIP_Send_Data(upcb, txBuf, txLen, addr, port);
        }
    }
    else if (ServiceID != 0x0100U)
    {
        my_printf("Requested Unknown Service ID\n");
    }

    pbuf_free(p);
}

void SOMEIP_Service2_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port)
{
    static BuzzerData_t buzzer_latest_data;
    static LedData_t led_latest_data;

    if (p == NULL)
    {
        return;
    }

    // 수신 버퍼 크기 검증 (SOME/IP 최소 헤더: 16 bytes)
    if (p->len < 16 || p->len > 512)
    {
        my_printf("Invalid packet size: %d\n", p->len);
        pbuf_free(p);
        return;
    }

    uint8_t rxBuf[512];
    memcpy(rxBuf, p->payload, p->len);

    uint16_t ServiceID = (rxBuf[0] << 8) + rxBuf[1];
    uint16_t MethodID = (rxBuf[2] << 8) + rxBuf[3];
    uint8_t MessageType = rxBuf[14];

    // Service ID 및 Message Type 확인
    if (ServiceID == 0x0200U && MessageType == 0x00)
    {
        uint8_t txBuf[256];
        uint16_t txLen = 0;

        // SOME/IP 헤더 복사 (16 bytes)
        memcpy(txBuf, rxBuf, 16);
        // Message Type을 Response로 변경
        txBuf[14] = 0x80;

        bool isEmerAlertOn = EmerAlert_GetData().interval_ms >= 0 ? true : false;

        // Method ID에 따라 처리
        if (MethodID == 0x0201U)
        {
            if (!isEmerAlertOn)
            {
                // Buzzer Control - Payload에서 값 추출
                uint8_t buzzer_command = rxBuf[16];  // 0: Off, 1: On
                int32_t frequency = (rxBuf[17] << 24) | (rxBuf[18] << 16) | (rxBuf[19] << 8) | rxBuf[20];

                // 부저 제어 수행
                Buzzer_SetFrequency(frequency);

                if (buzzer_command == 0x00)
                {
                    Buzzer_Off();
                }
                else if (buzzer_command == 0x01)
                {
                    Buzzer_On();
                }
            }

            buzzer_latest_data = Buzzer_GetData();
            my_printf("Buzzer Control: isOn=%d, frequency=%d\n", buzzer_latest_data.isOn, buzzer_latest_data.frequency);

            // Response payload 구성
            txLen = 16;
            txLen = Serialize_BuzzerData(txBuf, txLen, &buzzer_latest_data);
        }
        else if (MethodID == 0x0202U)
        {
            // LED Control - Payload에서 led_side 및 led_command 값 추출
            uint8_t led_side = rxBuf[16];       // LED_BACK, LED_FRONT_DOWN, LED_FRONT_UP
            uint8_t led_command = rxBuf[17];    // 0: Off, 1: On, 2: Toggle

            LedSide side = (LedSide) led_side;

            if (!(side == LED_BACK && isEmerAlertOn))
            {
                // LED 제어 수행
                if (led_command == 0x00)
                {
                    LED_Off(side);
                }
                else if (led_command == 0x01)
                {
                    LED_On(side);
                }
                else if (led_command == 0x02)
                {
                    LED_Toggle(side);
                }
            }

            led_latest_data = LED_GetData(side);
            my_printf("LED Control: side=%d, isOn=%d\n", led_latest_data.side, led_latest_data.isOn);

            // Response payload 구성
            txLen = 16;
            txLen = Serialize_LedData(txBuf, txLen, &led_latest_data);
        }

        if (txLen > 0)
        {
            // SOME/IP Length 필드 업데이트
            SOMEIP_Update_Length(txBuf, txLen);

            // 응답 전송
            SOMEIP_Send_Data(upcb, txBuf, txLen, addr, port);
        }
    }
    else if (ServiceID != 0x0200U)
    {
        my_printf("Requested Unknown Service ID\n");
    }

    pbuf_free(p);
}

void SOMEIP_Service3_Callback (void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, uint16_t port)
{
    static EmerAlertData_t emerAlert_latest_data;
    static MotorControllerData_t motor_controller_latest_data;

    if (p == NULL)
    {
        return;
    }

    // 수신 버퍼 크기 검증 (SOME/IP 최소 헤더: 16 bytes)
    if (p->len < 16 || p->len > 512)
    {
        my_printf("Invalid packet size: %d\n", p->len);
        pbuf_free(p);
        return;
    }

    uint8_t rxBuf[512];
    memcpy(rxBuf, p->payload, p->len);

    uint16_t ServiceID = (rxBuf[0] << 8) + rxBuf[1];
    uint16_t MethodID = (rxBuf[2] << 8) + rxBuf[3];
    uint8_t MessageType = rxBuf[14];

    // Service ID 및 Message Type 확인
    if (ServiceID == 0x0300U && MessageType == 0x00)
    {
        uint8_t txBuf[256];
        uint16_t txLen = 0;

        // SOME/IP 헤더 복사 (16 bytes)
        memcpy(txBuf, rxBuf, 16);
        // Message Type을 Response로 변경
        txBuf[14] = 0x80;

        // Method ID에 따라 처리
        if (MethodID == 0x0301U)
        {
            // Emergency Alert Control - Payload에서 emerAlert_cycle_ms 값 추출
            int64_t emerAlert_cycle_ms = ((int64_t) rxBuf[16] << 56) | ((int64_t) rxBuf[17] << 48)
                    | ((int64_t) rxBuf[18] << 40) | ((int64_t) rxBuf[19] << 32) | ((int64_t) rxBuf[20] << 24)
                    | ((int64_t) rxBuf[21] << 16) | ((int64_t) rxBuf[22] << 8) | (int64_t) rxBuf[23];

            // Emergency Alert 업데이트 수행
            if (EmerAlert_Set_Interval(emerAlert_cycle_ms))
            {
                emerAlert_latest_data = EmerAlert_GetData();
            }
            my_printf("Emergency Alert Control: cycle=%lld ms\n", emerAlert_latest_data.interval_ms);

            // Response payload 구성
            txLen = 16;
            txLen = Serialize_EmerAlertData(txBuf, txLen, &emerAlert_latest_data);
        }
        else if (MethodID == 0x0302U)
        {
            // Motor Control - Payload에서 motor_x, motor_y 값 추출
            int motor_x = (rxBuf[16] << 24) | (rxBuf[17] << 16) | (rxBuf[18] << 8) | rxBuf[19];
            int motor_y = (rxBuf[20] << 24) | (rxBuf[21] << 16) | (rxBuf[22] << 8) | rxBuf[23];

            // 모터 제어 수행
            if (MotorController_ProcessJoystickInput(motor_x, motor_y))
            {
                motor_controller_latest_data = MotorController_GetData();
            }
            my_printf("Motor Control: x=%d, y=%d, chA=%d, chB=%d\n", motor_controller_latest_data.x,
                    motor_controller_latest_data.y, motor_controller_latest_data.motorChA_speed,
                    motor_controller_latest_data.motorChB_speed);

            // Response payload 구성
            txLen = 16;
            txLen = Serialize_MotorControllerData(txBuf, txLen, &motor_controller_latest_data);
        }

        if (txLen > 0)
        {
            // SOME/IP Length 필드 업데이트
            SOMEIP_Update_Length(txBuf, txLen);

            // 응답 전송
            SOMEIP_Send_Data(upcb, txBuf, txLen, addr, port);
        }
    }
    else if (ServiceID != 0x0300U)
    {
        my_printf("Requested Unknown Service ID\n");
    }

    pbuf_free(p);
}

static inline void SOMEIP_Update_Length (uint8_t *txBuf, uint16_t txLen)
{
    // SOME/IP Length 필드 업데이트 (Byte 4-7)
    // Length = Payload 크기 + 8 (Message ID부터 Payload까지)
    uint32_t length = txLen - 8;
    txBuf[4] = (length >> 24) & 0xFF;
    txBuf[5] = (length >> 16) & 0xFF;
    txBuf[6] = (length >> 8) & 0xFF;
    txBuf[7] = length & 0xFF;
}

static void SOMEIP_Send_Data (struct udp_pcb *upcb, uint8_t *txBuf, uint16_t txLen, const ip_addr_t *addr,
        uint16_t port)
{
    err_t err;
    struct pbuf *txbuf = pbuf_alloc(PBUF_TRANSPORT, txLen, PBUF_RAM);

    if (txbuf == NULL)
    {
        my_printf("Failed to allocate memory for UDP packet buffer.\n");
        return;
    }

    pbuf_take(txbuf, txBuf, txLen);

    // 요청자의 IP 주소 재구성
    ip_addr_t destination_ip;
    unsigned char a = (unsigned char) (addr->addr);
    unsigned char b = (unsigned char) (addr->addr >> 8);
    unsigned char c = (unsigned char) (addr->addr >> 16);
    unsigned char d = (unsigned char) (addr->addr >> 24);

    IP4_ADDR(&destination_ip, a, b, c, d);
    u16_t destination_port = port;

    // 응답 전송
    err = udp_sendto(upcb, txbuf, &destination_ip, destination_port);

    if (err == ERR_OK)
    {
        my_printf("[SOME/IP] Data transfer success!!\n");
    }
    else
    {
        my_printf("[SOME/IP] Data transfer failed!! \n");
    }

    pbuf_free(txbuf);
}

#endif /* LWIP_UDP */
