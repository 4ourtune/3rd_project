#include "shared.h"
#include "vc_common.h"
#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

static bool parse_udp_format(const char* msg, int& x, int& y, int& btn, bool& is_motor){
    // "motor:x,y" or "button:p" (조이스틱 RPi의 Python 포맷)
    if (std::strncmp(msg, "motor:", 6) == 0) {
        if (sscanf(msg + 6, "%d,%d", &x, &y) == 2) { is_motor = true; return true; }
    } else if (std::strncmp(msg, "button:", 7) == 0) {
        if (sscanf(msg + 7, "%d", &btn) == 1) { is_motor = false; return true; }
    }
    return false;
}

// 혹시 원시 포맷이 오는 경우(Mxxxyy / Ppp)도 허용
static bool parse_raw_format(const char* msg, int& x, int& y, int& btn, bool& is_motor) {
    size_t len = std::strlen(msg);
    if (len >= 5 && msg[0] == 'M') {
        int a=-1,b=-1;
        if (sscanf(msg+1, "%2d%2d", &a, &b) == 2 || sscanf(msg+1, "%3d%2d", &a, &b) == 2) {
            x=a; y=b; is_motor=true; return true;
        }
    } else if (len >= 2 && msg[0] == 'P') {
        int p=-1; if (sscanf(msg+1, "%2d", &p) == 1) { btn=p; is_motor=false; return true; }
    }
    return false;
}

void joystick_thread(){
    set_realtime_sched(PRIO_JOYSTICK);

    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { std::perror("[joy] socket"); return; }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(JOY_UDP_PORT);
    addr.sin_addr.s_addr = inet_addr(JOY_BIND_ADDR); // 0.0.0.0

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::perror("[joy] bind");
        ::close(sock);
        return;
    }
    
    std::printf("[JOY] Enter while loop\n");

    char buf[256];
    //while (g_shared.running) {
    while (true) {
        sockaddr_in src{}; socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&src, &slen);
        if (n <= 0) continue;
        buf[n] = '\0';

        // 개행/널 제거(안전)
        for (ssize_t i=0;i<n;i++){ if (buf[i]=='\r'||buf[i]=='\n'||buf[i]=='\0'){ buf[i]='\0'; break; } }

        int x=0,y=0,btn=-1; bool is_motor=false;
        // bool ok = parse_udp_format(buf, x, y, btn, is_motor) || parse_raw_format(buf, x, y, btn, is_motor);
        bool ok = parse_raw_format(buf, x, y, btn, is_motor);

        if (!ok) continue;

        {
            std::lock_guard<std::mutex> lk(g_shared.mtx);
            std::printf("[JOY] is_motor: %d\n", is_motor);
            if (is_motor) {
                g_shared.joy.x   = x;
                g_shared.joy.y   = y;
                g_shared.joy.ts_ms = now_ms();
                std::printf("[JOY] recv (%d,%d) @%llu ms\n",
                            g_shared.joy.x,
                            g_shared.joy.y,
                            static_cast<unsigned long long>(g_shared.joy.ts_ms));
            } else {
                // 버튼 정책 예시: 1 → 엔진 ON, 0 → OFF
                g_shared.engine_on = (btn == 1);
                std::printf("[JOY] button=%d -> engine_on=%d\n",
                            btn, g_shared.engine_on ? 1 : 0);
            }
        }
    }

    ::close(sock);
}
