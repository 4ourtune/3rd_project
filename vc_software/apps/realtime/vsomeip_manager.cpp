#include "vsomeip_manager.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <chrono>

using namespace std;

// -------------------- Singleton --------------------
VSomeIPManager::VSomeIPManager() : subscribed_(false) {}
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

    // 메시지 수신 핸들러 (Request/Response 및 Event 모두 처리)
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


// -------------------- Availability --------------------
void VSomeIPManager::onAvailability(vsomeip::service_t s, vsomeip::instance_t i, bool avail) {
    cout << "[SOME/IP] Service 0x" << hex << s << " instance 0x" << i
         << (avail ? " AVAILABLE" : " UNAVAILABLE") << dec << endl;

    std::lock_guard<std::mutex> lock(mtx_avail_);
    if (avail) {
        available_services_.insert(s);
        cv_avail_.notify_all();
    } else {
        available_services_.erase(s);
    }
}

bool VSomeIPManager::isServiceAvailable(uint16_t service_id) {
    std::lock_guard<std::mutex> lock(mtx_avail_);
    return available_services_.count(service_id) > 0;
}

bool VSomeIPManager::waitForService(uint16_t service_id, int timeout_ms) {
    std::unique_lock<std::mutex> lock(mtx_avail_);
    return cv_avail_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                               [this, service_id]() { 
                                   return available_services_.count(service_id) > 0; 
                               });
}


// -------------------- Event Subscription --------------------
void VSomeIPManager::subscribeToSensorEvents() {
    if (subscribed_) {
        cout << "[VSomeIPManager] Already subscribed to sensor events" << endl;
        return;
    }

    // 센서 서비스가 available 될 때까지 대기
    if (!waitForService(SERVICE_ID_SENSOR, 5000)) {
        cout << "[VSomeIPManager] Warning: Sensor service not available, subscribing anyway..." << endl;
    }

    // PR Event 구독
    std::set<vsomeip::eventgroup_t> pr_groups;
    pr_groups.insert(EVENTGROUP_ID_PR);
    app_->request_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_PR_DATA, pr_groups);
    app_->subscribe(SERVICE_ID_SENSOR, INSTANCE_ID, EVENTGROUP_ID_PR);
    cout << "[VSomeIPManager] Subscribed to PR event (0x" << hex << EVENT_ID_PR_DATA << ")" << dec << endl;

    // ToF Event 구독
    std::set<vsomeip::eventgroup_t> tof_groups;
    tof_groups.insert(EVENTGROUP_ID_TOF);
    app_->request_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_TOF_DATA, tof_groups);
    app_->subscribe(SERVICE_ID_SENSOR, INSTANCE_ID, EVENTGROUP_ID_TOF);
    cout << "[VSomeIPManager] Subscribed to ToF event (0x" << hex << EVENT_ID_TOF_DATA << ")" << dec << endl;

    // Ultrasonic Events 구독
    std::set<vsomeip::eventgroup_t> ult_groups;
    ult_groups.insert(EVENTGROUP_ID_ULT);
    app_->request_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_ULT_1, ult_groups);
    app_->request_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_ULT_2, ult_groups);
    app_->request_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_ULT_3, ult_groups);
    app_->subscribe(SERVICE_ID_SENSOR, INSTANCE_ID, EVENTGROUP_ID_ULT);
    cout << "[VSomeIPManager] Subscribed to Ultrasonic events (0x" << hex 
         << EVENT_ID_ULT_1 << ", 0x" << EVENT_ID_ULT_2 << ", 0x" << EVENT_ID_ULT_3 << ")" << dec << endl;

    subscribed_ = true;
}

void VSomeIPManager::unsubscribeFromSensorEvents() {
    if (!subscribed_) {
        return;
    }

    app_->unsubscribe(SERVICE_ID_SENSOR, INSTANCE_ID, EVENTGROUP_ID_PR);
    app_->unsubscribe(SERVICE_ID_SENSOR, INSTANCE_ID, EVENTGROUP_ID_TOF);
    app_->unsubscribe(SERVICE_ID_SENSOR, INSTANCE_ID, EVENTGROUP_ID_ULT);
    
    app_->release_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_PR_DATA);
    app_->release_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_TOF_DATA);
    app_->release_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_ULT_1);
    app_->release_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_ULT_2);
    app_->release_event(SERVICE_ID_SENSOR, INSTANCE_ID, EVENT_ID_ULT_3);

    cout << "[VSomeIPManager] Unsubscribed from all sensor events" << endl;
    subscribed_ = false;
}


// -------------------- Message Handler --------------------
void VSomeIPManager::onMessage(const shared_ptr<vsomeip::message>& msg) {
    auto sid = msg->get_service();
    auto mid = msg->get_method();
    auto msg_type = msg->get_message_type();
    auto payload = msg->get_payload();
    auto data = payload->get_data();
    auto len = payload->get_length();

    // Event notification인지 확인
    bool is_event = (msg_type == vsomeip::message_type_e::MT_NOTIFICATION);

    if (is_event) {
        cout << "[VSomeIPManager] Received EVENT notification: Service=0x" << hex << sid 
             << " Event=0x" << mid << " Length=" << dec << len << endl;
    }

    lock_guard<mutex> lock(mtx_data_);

    // ---------- 센서 응답 및 이벤트 ----------
    if (sid == SERVICE_ID_SENSOR) {
        // PR 데이터 (Method ID 또는 Event ID)
        if ((mid == METHOD_ID_PR || mid == EVENT_ID_PR_DATA) && len >= 12) {
            size_t o = 0;
            latest_pr_.val = get_value<uint32_t>(data, o);
            latest_pr_.received_time_us = get_value<uint64_t>(data, o);
        }
        // ToF 데이터 (Method ID 또는 Event ID)
        else if ((mid == METHOD_ID_TOF || mid == EVENT_ID_TOF_DATA) && len >= 20) {
            size_t o = 0;
            latest_tof_.id = get_value<uint8_t>(data, o);
            latest_tof_.system_time_ms = get_value<uint32_t>(data, o);
            latest_tof_.distance_m = get_value<float>(data, o);
            latest_tof_.distance_status = get_value<uint8_t>(data, o);
            latest_tof_.signal_strength = get_value<uint16_t>(data, o);
            latest_tof_.received_time_us = get_value<uint64_t>(data, o);
        }
        // Ultrasonic 데이터 (Method ID 또는 Event IDs)
        else if ((mid == METHOD_ID_ULT || mid == EVENT_ID_ULT_1 || 
                  mid == EVENT_ID_ULT_2 || mid == EVENT_ID_ULT_3) && len > 0) {
            // 단일 Event의 경우 하나의 센서 데이터만 포함
            if (is_event && (mid == EVENT_ID_ULT_1 || mid == EVENT_ID_ULT_2 || mid == EVENT_ID_ULT_3)) {
                if (len >= 16) {
                    size_t o = 0;
                    UltrasonicData_t u;
                    u.dist_raw_mm = get_value<int32_t>(data, o);
                    u.dist_filt_mm = get_value<int32_t>(data, o);
                    u.received_time_us = get_value<uint64_t>(data, o);
                    
                    // Event ID에 따라 인덱스 결정
                    int idx = (mid == EVENT_ID_ULT_1) ? 0 : (mid == EVENT_ID_ULT_2) ? 1 : 2;
                    
                    // 벡터 크기 확보
                    if (latest_ult_.size() < 3) {
                        latest_ult_.resize(3);
                    }
                    latest_ult_[idx] = u;
                }
            }
            // Request/Response의 경우 모든 센서 데이터 포함
            else if (mid == METHOD_ID_ULT) {
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
    }

    // ---------- 제어 서비스 응답 ----------
    else if (sid == SERVICE_ID_CONTROL || sid == SERVICE_ID_SYSTEM) {
        ControlResponse_t resp;
        resp.method_id = mid;
        resp.updated = true;
        resp.received_time_us = chrono::duration_cast<chrono::microseconds>(
                                    chrono::steady_clock::now().time_since_epoch()).count();
        resp.result_code = (len >= 1) ? data[0] : 0xFF;
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