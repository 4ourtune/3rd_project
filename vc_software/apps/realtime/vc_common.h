#ifndef VC_COMMON_H
#define VC_COMMON_H

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <chrono>
#include <thread>
#include <pthread.h>
#include <sys/time.h>

inline uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

inline void sleep_ms(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

inline void set_realtime_sched(int prio) {
    sched_param param{};
    param.sched_priority = prio;
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
        std::perror("pthread_setschedparam");
    }
}

#endif
