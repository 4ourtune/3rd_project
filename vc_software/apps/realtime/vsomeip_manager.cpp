#include "vsomeip_manager.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <chrono>

using namespace std;

// -------------------- Singleton --------------------
VSomeIPManager::VSomeIPManager() {}
VSomeIPManager::~VSomeIPManager() {}

VSomeIPManager& VSomeIPManager::getInstance() {
    static VSomeIPManager instance;
    return instance;
}


// -------------------- Template Helpers --------------------
template <typename T>
T VSomeIPManager::get_value(const vsomeip::byte_t* data, size_t& offset) {
    T value;
    memcpy(&value, data + offset, sizeof(T));
    if (sizeof(T) > 1)
        reverse(reinterpret_cast<vsomeip::byte_t*>(&value),
                reinterpret_cast<vsomeip::byte_t*>(&value) + sizeof(T));
    offset += sizeof(T);
    return value;
}

template <typename T>
void VSomeIPManager::append_value(vector<vsomeip::byte_t>& buf, T val) {
    if (sizeof(T) > 1)
        reverse(reinterpret_cast<vsomeip::byte_t*>(&val),
                reinterpret_cast<vsomeip::byte_t*>(&val) + sizeof(T));
    const vsomeip::byte_t* ptr = reinterpret_cast<const vsomeip::byte_t*>(&val);
    buf.insert(buf.end(), ptr, ptr + sizeof(T));
}


// -------------------- Init --------------------
bool VSomeIPManager::init() {
    app_ = vsomeip::runtime::get()->create_application("rpi_client_app");
    if (!app_->init()){
      cout << "vsomeip init failed!\n";
      return false;
    }
    cout << "vsomeip init success!\n";

    // 서비스 가용성 콜백 등록
    auto handler = std::bind(&VSomeIPManager::onAvailability, this,
                             std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

    app_->register_availability_handler(SERVICE_ID_SENSOR, INSTANCE_ID, handler);
    app_->register_availability_handler(SERVICE_ID_CONTROL, INSTANCE_ID, handler);
    app_->register_availability_handler(SERVICE_ID_SYSTEM, INSTANCE_ID, handler);

    // 메시지 수신 핸들러
    app_->register_message_handler(vsomeip::ANY_SERVICE, INSTANCE_ID, vsomeip::ANY_METHOD,
                                   [this](std::shared_ptr<vsomeip::message> msg){ this->onMessage(msg); });

    // 서비스 요청
    app_->request_service(SERVICE_ID_SENSOR, INSTANCE_ID);
    app_->request_service(SERVICE_ID_CONTROL, INSTANCE_ID);
    app_->request_service(SERVICE_ID_SYSTEM, INSTANCE_ID);

    // vsomeip 내부 스레드 시작
    app_thread_ = std::thread([this] { app_->start(); });

    cout << "[VSomeIPManager] initialized successfully" << endl;
    return true;
}


// // -------------------- Availability --------------------
// void VSomeIPManager::onAvailability(vsomeip::service_t s, vsomeip::instance_t i, bool avail) {
//     cout << "[SOME/IP] Service 0x" << hex << s << " instance 0x" << i
//          << (avail ? " AVAILABLE" : " UNAVAILABLE") << dec << endl;
// }
// 1. onAvailability 수정
void VSomeIPManager::onAvailability(vsomeip::service_t s, vsomeip::instance_t i, bool avail) {
    cout << "[SOME/IP] Service 0x" << hex << s << " instance 0x" << i
         << (avail ? " AVAILABLE" : " UNAVAILABLE") << dec << endl;

    std::lock_guard<std::mutex> lock(mtx_avail_);
    if (avail)
        available_services_.insert(s);
    else
        available_services_.erase(s);
}

// 2. isServiceAvailable() 함수 추가
bool VSomeIPManager::isServiceAvailable(uint16_t service_id) {
    std::lock_guard<std::mutex> lock(mtx_avail_);
    return available_services_.count(service_id) > 0;
}

// 추가: 서비스 실제 연결 대기 함수
bool VSomeIPManager::waitForService(uint16_t service_id, int timeout_ms) {
    const int step = 100;
    int waited = 0;
    while (waited < timeout_ms) {
        if (isServiceAvailable(service_id))
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(step));
        waited += step;
    }
    return false;
}


// -------------------- Message Handler --------------------
void VSomeIPManager::onMessage(const shared_ptr<vsomeip::message>& msg) {
    auto sid = msg->get_service();
    auto mid = msg->get_method();
    auto payload = msg->get_payload();
    auto data = payload->get_data();
    auto len = payload->get_length();

    lock_guard<mutex> lock(mtx_data_);

    // ---------- 센서 응답 ----------
    if (sid == SERVICE_ID_SENSOR) {
        if (mid == METHOD_ID_PR && len >= 12) {
            size_t o = 0;
            latest_pr_.val = get_value<uint32_t>(data, o);
            latest_pr_.received_time_us = get_value<uint64_t>(data, o);
        }
        else if (mid == METHOD_ID_TOF && len >= 20) {
            size_t o = 0;
            latest_tof_.id = get_value<uint8_t>(data, o);
            latest_tof_.system_time_ms = get_value<uint32_t>(data, o);
            latest_tof_.distance_m = get_value<float>(data, o);
            latest_tof_.distance_status = get_value<uint8_t>(data, o);
            latest_tof_.signal_strength = get_value<uint16_t>(data, o);
            latest_tof_.received_time_us = get_value<uint64_t>(data, o);
        }
        else if (mid == METHOD_ID_ULT && len > 0) {
            latest_ult_.clear();
            size_t o = 0;
            uint8_t count = get_value<uint8_t>(data, o);
            for (int i = 0; i < count && o + 16 <= len; ++i) {
                UltrasonicData_t u;
                u.dist_raw_mm = get_value<int32_t>(data, o);
                u.dist_filt_mm = get_value<int32_t>(data, o);
                u.received_time_us = get_value<uint64_t>(data, o);
                latest_ult_.push_back(u);
            }
        }
    }

    // ---------- 제어 서비스 응답 ----------
    else if (sid == SERVICE_ID_CONTROL || sid == SERVICE_ID_SYSTEM) {
        ControlResponse_t resp;
        resp.method_id = mid;
        resp.updated = true;
        resp.received_time_us = chrono::duration_cast<chrono::microseconds>(
                                    chrono::steady_clock::now().time_since_epoch()).count();
        resp.result_code = (len >= 1) ? data[0] : 0xFF; // result code 첫 byte 저장
        latest_ctrl_resps_.push_back(resp);
    }
}


// -------------------- Request Functions --------------------
void VSomeIPManager::requestPRData() {
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE_ID_SENSOR);
    req->set_instance(INSTANCE_ID);
    req->set_method(METHOD_ID_PR);
    req->set_client(CLIENT_ID);
    req->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    req->set_interface_version(1);
    app_->send(req);
}

void VSomeIPManager::requestToFData() {
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE_ID_SENSOR);
    req->set_instance(INSTANCE_ID);
    req->set_method(METHOD_ID_TOF);
    req->set_client(CLIENT_ID);
    req->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    req->set_interface_version(1);
    app_->send(req);
}

void VSomeIPManager::requestUltrasonicData() {
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE_ID_SENSOR);
    req->set_instance(INSTANCE_ID);
    req->set_method(METHOD_ID_ULT);
    req->set_client(CLIENT_ID);
    req->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    req->set_interface_version(1);
    app_->send(req);
}

void VSomeIPManager::requestBuzzerControl(uint8_t cmd, int32_t freq) {
    vector<vsomeip::byte_t> buf; buf.push_back(cmd);
    append_value(buf, freq);
    auto p = vsomeip::runtime::get()->create_payload();
    p->set_data(buf);
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE_ID_CONTROL);
    req->set_instance(INSTANCE_ID);
    req->set_method(METHOD_ID_BUZZER);
    req->set_client(CLIENT_ID);
    req->set_interface_version(1);
    req->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    req->set_payload(p);
    app_->send(req);
}

void VSomeIPManager::requestLedControl(uint8_t side, uint8_t cmd) {
    vector<vsomeip::byte_t> buf = {side, cmd};
    auto p = vsomeip::runtime::get()->create_payload();
    p->set_data(buf);
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE_ID_CONTROL);
    req->set_instance(INSTANCE_ID);
    req->set_method(METHOD_ID_LED);
    req->set_client(CLIENT_ID);
    req->set_interface_version(1);
    req->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    req->set_payload(p);
    app_->send(req);
}

void VSomeIPManager::requestAlertControl(int64_t cycle_ms) {
    vector<vsomeip::byte_t> buf;
    append_value(buf, cycle_ms);
    auto p = vsomeip::runtime::get()->create_payload();
    p->set_data(buf);
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE_ID_SYSTEM);
    req->set_instance(INSTANCE_ID);
    req->set_method(METHOD_ID_ALERT);
    req->set_client(CLIENT_ID);
    req->set_interface_version(1);
    req->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    req->set_payload(p);
    app_->send(req);
}

void VSomeIPManager::requestMotorControl(int32_t x, int32_t y) {
    vector<vsomeip::byte_t> buf;
    append_value(buf, x);
    append_value(buf, y);
    auto p = vsomeip::runtime::get()->create_payload();
    p->set_data(buf);
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE_ID_SYSTEM);
    req->set_instance(INSTANCE_ID);
    req->set_method(METHOD_ID_MOTOR);
    req->set_client(CLIENT_ID);
    req->set_interface_version(1);
    req->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    req->set_payload(p);
    app_->send(req);
}


// -------------------- Getter --------------------
PRData_t VSomeIPManager::getLatestPR() {
    lock_guard<mutex> lock(mtx_data_);
    return latest_pr_;
}

ToFData_t VSomeIPManager::getLatestToF() {
    lock_guard<mutex> lock(mtx_data_);
    return latest_tof_;
}

vector<UltrasonicData_t> VSomeIPManager::getLatestUltrasonic() {
    lock_guard<mutex> lock(mtx_data_);
    return latest_ult_;
}

ControlResponse_t VSomeIPManager::getLatestControlResponse(uint16_t method_id) {
    lock_guard<mutex> lock(mtx_data_);
    for (auto it = latest_ctrl_resps_.rbegin(); it != latest_ctrl_resps_.rend(); ++it) {
        if (it->method_id == method_id) return *it;
    }
    return ControlResponse_t{method_id, 0xFF, false, 0};
}
