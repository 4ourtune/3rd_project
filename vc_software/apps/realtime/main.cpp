#include <iostream>
#include <csignal>
#include <thread>
#include <atomic>
#include "shared.h"
#include "vc_common.h"
#include "config.h"
#include "vsomeip_manager.h"

//SharedData g_shared;

void joystick_thread();
void sensor_thread();
void control_thread();
void comm_thread();
void ipc_thread();

static std::atomic<bool> g_stop_requested{false};

static void sigint_handler(int){
    g_stop_requested.store(true);
}

int main(){
    // 1?. vsomeip √ ±‚»≠
    VSomeIPManager& someip = VSomeIPManager::getInstance();
    if (!someip.init()) {
        std::cout << "[main] ERROR: vsomeip init failed\n";
        return -1;
    }
    std::cout << "[main] vsomeip initialized successfully\n";

    std::signal(SIGINT, sigint_handler);

    std::thread t_joy(joystick_thread);
    std::thread t_sensor(sensor_thread);
    std::thread t_ctrl(control_thread);
    std::thread t_comm(comm_thread);
    std::thread t_ipc(ipc_thread);

    uint64_t last_log = 0;
    while (true){
        if (g_stop_requested.exchange(false)) {
            std::lock_guard<std::mutex> lk(g_shared.mtx);
            g_shared.running = false;
        }

        uint64_t t = now_ms();
        bool running_snapshot;
        {
            std::lock_guard<std::mutex> lk(g_shared.mtx);
            running_snapshot = g_shared.running;
            if (running_snapshot && t - last_log >= PERIOD_LOG_MS) {

                last_log = t;
            }
        }
        if (!running_snapshot) {
            break;
        }

        sleep_ms(50);
    }

    t_joy.join();
    t_sensor.join();
    t_ctrl.join();
    t_comm.join();
    t_ipc.join();
    return 0;
}
