#include "vsomeip_manager.h"
#include "shared.h"
#include "config.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <algorithm>

using namespace std;

extern SharedData g_shared;

void comm_thread() {
    VSomeIPManager& someip = VSomeIPManager::getInstance();

    const int PERIOD_MS = 50; // 20Hz
    ControlOutput prev_out;

    cout << "[comm_thread] started successfully" << endl;

    // 서비스 연결 대기
    cout << "[comm_thread] Waiting for service routing..." << endl;
    bool ctrl_ready = someip.waitForService(SERVICE_ID_CONTROL, 3000);
    bool sys_ready  = someip.waitForService(SERVICE_ID_SYSTEM, 3000);
    if (!ctrl_ready || !sys_ready) {
        cerr << "[comm_thread] WARNING: Some services not ready, waiting extra 1s..." << endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    cout << "[comm_thread] Routing stabilized, start sending..." << endl;

    auto map_logical_to_hw_steer = [](int logical_cmd) {
        int clamped = std::clamp(logical_cmd, 0, static_cast<int>(LKAS_JOY_CENTER * 2));
        int mirrored = static_cast<int>(LKAS_JOY_CENTER * 2) - clamped;
        return std::clamp(mirrored, -100, 100);
    };

    while (g_shared.running) {
        ControlOutput cur;
        {
            lock_guard<mutex> lock(g_shared.mtx);
            cur = g_shared.out;
        }

        // -------------------------------------------------------------
        // 1~4. 제어 명령 순차 전송 (Order Guarantee)
        // -------------------------------------------------------------
        if (cur.buzzerOn != prev_out.buzzerOn || cur.frequency != prev_out.frequency) {
            someip.requestBuzzerControl(cur.buzzerOn ? 1 : 0, cur.frequency);
            cout << "[comm_thread] Buzzer "
                 << (cur.buzzerOn ? "ON" : "OFF")
                 << " (" << cur.frequency << " Hz)" << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        if (cur.led_back_on != prev_out.led_back_on) {
            someip.requestLedControl(LED_BACK, cur.led_back_on ? 1 : 0);
            cout << "[comm_thread] LED_BACK " << (cur.led_back_on ? "ON" : "OFF") << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        if (cur.led_front_down_on != prev_out.led_front_down_on) {
            someip.requestLedControl(LED_FRONT_DOWN, cur.led_front_down_on ? 1 : 0);
            cout << "[comm_thread] LED_FRONT_DOWN " << (cur.led_front_down_on ? "ON" : "OFF") << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        if (cur.led_front_up_on != prev_out.led_front_up_on) {
            someip.requestLedControl(LED_FRONT_UP, cur.led_front_up_on ? 1 : 0);
            cout << "[comm_thread] LED_FRONT_UP " << (cur.led_front_up_on ? "ON" : "OFF") << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        if (cur.alert_interval_ms != prev_out.alert_interval_ms) {
            someip.requestAlertControl(cur.alert_interval_ms);
            cout << "[comm_thread] EmerAlert interval_ms = " << cur.alert_interval_ms << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        if (cur.throttle != prev_out.throttle || cur.steer != prev_out.steer) {
            int steer_hw = map_logical_to_hw_steer(cur.steer);
            someip.requestMotorControl(steer_hw, cur.throttle);
            cout << "[comm_thread] Motor steer(logical)=" << cur.steer
                 << " steer(hw)=" << steer_hw
                 << " throttle=" << cur.throttle << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        prev_out = cur;
        std::this_thread::sleep_for(std::chrono::milliseconds(PERIOD_MS));
    }

    cout << "[comm_thread] terminated" << endl;
}
