#ifndef VSOMEIP_MANAGER_H_
#define VSOMEIP_MANAGER_H_

#include <vsomeip/vsomeip.hpp>
#include <memory>
#include <mutex>
#include <vector>
#include <thread>
#include <cstdint>
#include <set>

// -------------------- 서비스 / 메서드 정의 --------------------
#define SERVICE_ID_SENSOR   0x0100
#define SERVICE_ID_CONTROL  0x0200
#define SERVICE_ID_SYSTEM   0x0300

#define METHOD_ID_PR        0x0101
#define METHOD_ID_TOF       0x0102
#define METHOD_ID_ULT       0x0103
#define METHOD_ID_BUZZER    0x0201
#define METHOD_ID_LED       0x0202
#define METHOD_ID_ALERT     0x0301
#define METHOD_ID_MOTOR     0x0302

#define INSTANCE_ID         0x0001
#define CLIENT_ID           0x5678


// -------------------- 데이터 구조체 정의 --------------------
struct PRData_t {
    uint32_t val;
    uint64_t received_time_us;
};

struct ToFData_t {
    uint8_t id;
    uint32_t system_time_ms;
    float distance_m;
    uint8_t distance_status;
    uint16_t signal_strength;
    uint64_t received_time_us;
};

struct UltrasonicData_t {
    int32_t dist_raw_mm;
    int32_t dist_filt_mm;
    uint64_t received_time_us;
};

// 제어 요청의 응답(Response) 데이터
struct ControlResponse_t {
    uint16_t method_id;
    uint8_t result_code;
    bool updated;
    uint64_t received_time_us;
};


// -------------------- VSomeIPManager 클래스 --------------------
class VSomeIPManager {
public:
    static VSomeIPManager& getInstance();

    bool init();

    // ---------- 요청 함수 ----------
    void requestPRData();
    void requestToFData();
    void requestUltrasonicData();
    void requestBuzzerControl(uint8_t cmd, int32_t freq);
    void requestLedControl(uint8_t side, uint8_t cmd);
    void requestAlertControl(int64_t cycle_ms);
    void requestMotorControl(int32_t x, int32_t y);

    // ---------- Getter ----------
    PRData_t getLatestPR();
    ToFData_t getLatestToF();
    std::vector<UltrasonicData_t> getLatestUltrasonic();
    ControlResponse_t getLatestControlResponse(uint16_t method_id);

    // ---------- 서비스 가용성 확인 ----------
    bool isServiceAvailable(uint16_t service_id);
    bool waitForService(uint16_t service_id, int timeout_ms);  //  추가


private:
    VSomeIPManager();
    ~VSomeIPManager();

    void onAvailability(vsomeip::service_t service, vsomeip::instance_t instance, bool available);
    void onMessage(const std::shared_ptr<vsomeip::message>& msg);

    template <typename T>
    T get_value(const vsomeip::byte_t* data, size_t& offset);

    template <typename T>
    void append_value(std::vector<vsomeip::byte_t>& buf, T val);

private:
    std::shared_ptr<vsomeip::application> app_;
    std::thread app_thread_;
    std::mutex mtx_data_;

    // 최신 수신 데이터 저장
    PRData_t latest_pr_;
    ToFData_t latest_tof_;
    std::vector<UltrasonicData_t> latest_ult_;
    std::vector<ControlResponse_t> latest_ctrl_resps_;

    std::mutex mtx_avail_;                // 가용성 정보 보호용 mutex
    std::set<uint16_t> available_services_; // 현재 AVAILABLE 상태인 서비스 목록

};

#endif
