#include "vsomeip_manager.h"
#include "shared.h"
#include <iostream>
#include <thread>
#include <chrono>

using namespace std;

extern SharedData g_shared;   // 전역 공유 데이터

void sensor_thread() {
    VSomeIPManager& someip = VSomeIPManager::getInstance();

    cout << "[sensor_thread] started successfully" << endl;

    const int PERIOD_MS = 100; // 0.1초 주기

    while (true) {
        // -------------------------------------------------------------
        // 1️. vsomeip 요청 송신
        // -------------------------------------------------------------
        someip.requestPRData();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        someip.requestToFData();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        someip.requestUltrasonicData();

        // -------------------------------------------------------------
        // 2️. 최신 데이터 읽기
        // -------------------------------------------------------------
        PRData_t pr = someip.getLatestPR();
        ToFData_t tof = someip.getLatestToF();
        vector<UltrasonicData_t> ult = someip.getLatestUltrasonic();

        // -------------------------------------------------------------
        // 3️. 공유 메모리에 쓰기 (mutex 보호)
        // -------------------------------------------------------------
        {
            std::lock_guard<std::mutex> lock(g_shared.mtx);

            // PR → ambient_lux
            g_shared.sensor.ambient_lux = static_cast<int>(pr.val);
            g_shared.sensor.ts_ms = chrono::duration_cast<chrono::milliseconds>(
                                        chrono::steady_clock::now().time_since_epoch()).count();

            // ToF → front_tof_mm
            g_shared.sensor.front_tof_mm = static_cast<int>(tof.distance_m * 1000.0f);
            g_shared.sensor.front_ts_us = tof.received_time_us;

            // 초음파 → 좌/우/후방 (순서 임의: 0,1,2)
            if (ult.size() >= 3) {
                g_shared.sensor.left_ultra_mm  = ult[0].dist_filt_mm;
                g_shared.sensor.right_ultra_mm = ult[1].dist_filt_mm;
                g_shared.sensor.rear_ultra_mm  = ult[2].dist_filt_mm;
                g_shared.sensor.left_ts_us  = ult[0].received_time_us;
                g_shared.sensor.right_ts_us = ult[1].received_time_us;
                g_shared.sensor.rear_ts_us  = ult[2].received_time_us;
            }
            else if (ult.size() == 1) { // 단일 초음파만 들어오는 경우
                g_shared.sensor.front_tof_mm = ult[0].dist_filt_mm;
                g_shared.sensor.front_ts_us  = ult[0].received_time_us;
            }
        }

        // -------------------------------------------------------------
        // 4️. 로그 출력
        // -------------------------------------------------------------
//cout << "[sensor_thread] Lux=" << pr.val
//<< " | ToF=" << tof.distance_m * 1000 << " mm"
//<< " | Ultrasonic(mm): L=" << g_shared.sensor.left_ultra_mm
//<< ", R=" << g_shared.sensor.right_ultra_mm
//<< ", Rear=" << g_shared.sensor.rear_ultra_mm
//<< endl;

        // -------------------------------------------------------------
        // 5️. 주기 제어
        // -------------------------------------------------------------
        std::this_thread::sleep_for(std::chrono::milliseconds(PERIOD_MS));
    }
}