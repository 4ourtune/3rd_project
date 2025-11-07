#include <vsomeip/vsomeip.hpp>
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <algorithm>

// Service IDs
#define SERVICE_ID_SENSOR   0x0100
#define SERVICE_ID_CONTROL  0x0200
#define SERVICE_ID_SYSTEM   0x0300

// Service1 (Sensor) Method IDs
#define METHOD_ID_PR        0x0101
#define METHOD_ID_TOF       0x0102
#define METHOD_ID_ULT       0x0103

// Service2 (Control) Method IDs
#define METHOD_ID_BUZZER    0x0201
#define METHOD_ID_LED       0x0202

// Service3 (System) Method IDs
#define METHOD_ID_ALERT     0x0301
#define METHOD_ID_MOTOR     0x0302

#define INSTANCE_ID         0x0001
#define CLIENT_ID           0x5678

typedef struct
{
	uint32_t val;
	uint64_t received_time_us;
} PRData_t;

typedef struct
{
	uint8_t id;
	uint32_t system_time_ms;
	float distance_m;
	uint8_t distance_status;
	uint16_t signal_strength;
	uint64_t received_time_us;
} ToFData_t;

typedef struct
{
	int32_t dist_raw_mm;
	int32_t dist_filt_mm;
	uint64_t received_time_us;
} UltrasonicData_t;

typedef struct
{
	bool isOn;
	int32_t frequency;
} BuzzerData_t;

typedef enum
{
	LED_BACK = 0, LED_FRONT_DOWN, LED_FRONT_UP, LED_SIDE_COUNT
} LedSide;

typedef struct
{
	LedSide side;
	bool isOn;
} LedData_t;

typedef struct
{
	int64_t interval_ms;
} EmerAlertData_t;

typedef struct
{
	int32_t x;
	int32_t y;
	int32_t motorChA_speed;
	int32_t motorChB_speed;
} MotorControllerData_t;

std::shared_ptr<vsomeip::application> app;

template <typename T>
T get_value_from_payload(const vsomeip::byte_t* data, size_t offset) {
	T value;
	std::memcpy(&value, data + offset, sizeof(T));
	if (sizeof(T) > 1) {
		vsomeip::byte_t* byte_ptr = reinterpret_cast<vsomeip::byte_t*>(&value);
		std::reverse(byte_ptr, byte_ptr + sizeof(T));
	}
	return value;
}

template <typename T>
void append_to_payload(std::vector<vsomeip::byte_t>& payload_data, T value) {
	if (sizeof(T) > 1) {
		vsomeip::byte_t* byte_ptr = reinterpret_cast<vsomeip::byte_t*>(&value);
		std::reverse(byte_ptr, byte_ptr + sizeof(T));
	}
	const vsomeip::byte_t* data_ptr = reinterpret_cast<const vsomeip::byte_t*>(&value);
	for (size_t i = 0; i < sizeof(T); ++i) {
		payload_data.push_back(data_ptr[i]);
	}
}

void on_availability(vsomeip::service_t service,
	vsomeip::instance_t instance,
	bool is_available) {
	std::cout << "Service [0x"
		<< std::setw(4) << std::setfill('0') << std::hex << service
		<< ".0x" << std::setw(4) << instance
		<< "] is " << (is_available ? "AVAILABLE" : "NOT available")
		<< std::endl;

	if (is_available) {
		std::cout << "Requesting service 0x" << std::hex << service
			<< " instance 0x" << instance << "..." << std::endl;
		app->request_service(service, instance);
	}
}

void on_message(const std::shared_ptr<vsomeip::message>& response_msg) {
	vsomeip::service_t service_id = response_msg->get_service();
	vsomeip::method_t method_id = response_msg->get_method();
	std::shared_ptr<vsomeip::payload> payload = response_msg->get_payload();
	const vsomeip::byte_t* data = payload->get_data();
	size_t length = payload->get_length();

	std::cout << "\n--- Received Response for Service 0x" << std::hex << service_id
		<< ", Method 0x" << method_id << std::dec << " (Length: " << length << " bytes) ---" << std::endl;

	if (service_id == SERVICE_ID_SENSOR) {
		if (method_id == METHOD_ID_PR) {
			// PR Data: val (4 bytes) + received_time_us (8 bytes)
			if (length >= 12) {
				size_t offset = 0;
				uint32_t val = get_value_from_payload<uint32_t>(data, offset); offset += 4;
				uint64_t received_time = get_value_from_payload<uint64_t>(data, offset); offset += 8;
				std::cout << "  [PR Data] Val: " << val << ", Time: " << received_time << " us" << std::endl;
			}
		}
		else if (method_id == METHOD_ID_TOF) {
			// ToF Data: id (1) + system_time_ms (4) + distance_m (4) + distance_status (1) + signal_strength (2) + received_time_us (8)
			if (length >= 20) {
				size_t offset = 0;
				uint8_t id = get_value_from_payload<uint8_t>(data, offset); offset += 1;
				uint32_t system_time = get_value_from_payload<uint32_t>(data, offset); offset += 4;
				float distance = get_value_from_payload<float>(data, offset); offset += 4;
				uint8_t status = get_value_from_payload<uint8_t>(data, offset); offset += 1;
				uint16_t strength = get_value_from_payload<uint16_t>(data, offset); offset += 2;
				uint64_t received_time = get_value_from_payload<uint64_t>(data, offset); offset += 8;
				std::cout << "  [ToF Data] ID: " << (int)id << ", Distance: " << distance << " m, Time: " << received_time << " us" << std::endl;
			}
		}
		else if (method_id == METHOD_ID_ULT) {
			// Ultrasonic Data: count (1 byte) + N * (dist_raw_mm (4) + dist_filt_mm (4) + received_time_us (8))
			if (length > 0) {
				uint8_t count = get_value_from_payload<uint8_t>(data, 0);
				std::cout << "  [Ultrasonic] Sensor Count: " << (int)count << std::endl;

				size_t offset = 1;
				for (int i = 0; i < count; ++i) {
					if (offset + 16 <= length) {
						int32_t raw = get_value_from_payload<int32_t>(data, offset); offset += 4;
						int32_t filt = get_value_from_payload<int32_t>(data, offset); offset += 4;
						uint64_t received_time = get_value_from_payload<uint64_t>(data, offset); offset += 8;
						std::cout << "    Sensor " << i << " Raw/Filt: " << raw << " / " << filt << " mm" << std::endl;
					}
				}
			}
		}
	}
	else if (service_id == SERVICE_ID_CONTROL) {
		if (method_id == METHOD_ID_BUZZER) {
			// Buzzer Data: isOn (1 byte) + frequency (4 bytes)
			if (length >= 5) {
				size_t offset = 0;
				bool isOn = get_value_from_payload<uint8_t>(data, offset) != 0; offset += 1;
				int32_t frequency = get_value_from_payload<int32_t>(data, offset); offset += 4;
				std::cout << "  [Buzzer Status] IsOn: " << (isOn ? "true" : "false")
					<< ", Frequency: " << frequency << " Hz" << std::endl;
			}
		}
		else if (method_id == METHOD_ID_LED) {
			// LED Data: side (1 byte) + isOn (1 byte)
			if (length >= 2) {
				size_t offset = 0;
				uint8_t side = get_value_from_payload<uint8_t>(data, offset); offset += 1;
				bool isOn = get_value_from_payload<uint8_t>(data, offset) != 0; offset += 1;
				std::cout << "  [LED Status] Side: " << (int)side
					<< ", IsOn: " << (isOn ? "true" : "false") << std::endl;
			}
		}
	}
	else if (service_id == SERVICE_ID_SYSTEM) {
		if (method_id == METHOD_ID_ALERT) {
			// Emergency Alert Data: interval_ms (8 bytes)
			if (length >= 8) {
				size_t offset = 0;
				int64_t interval = get_value_from_payload<int64_t>(data, offset); offset += 8;
				std::cout << "  [Alert Status] Interval: " << interval << " ms" << std::endl;
			}
		}
		else if (method_id == METHOD_ID_MOTOR) {
			// Motor Data: x (4 bytes) + y (4 bytes) + motorChA_speed (4 bytes) + motorChB_speed (4 bytes)
			if (length >= 16) {
				size_t offset = 0;
				int32_t x = get_value_from_payload<int32_t>(data, offset); offset += 4;
				int32_t y = get_value_from_payload<int32_t>(data, offset); offset += 4;
				int32_t speed_A = get_value_from_payload<int32_t>(data, offset); offset += 4;
				int32_t speed_B = get_value_from_payload<int32_t>(data, offset); offset += 4;
				std::cout << "  [Motor Status] Pos(x,y): " << x << ", " << y << " | Speed A/B: " << speed_A << " / " << speed_B << std::endl;
			}
		}
	}
}

void request_pr_data() {
	std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request();
	request->set_service(SERVICE_ID_SENSOR);
	request->set_instance(INSTANCE_ID);
	request->set_method(METHOD_ID_PR);
	request->set_client(CLIENT_ID);
	request->set_interface_version(0x01);
	request->set_message_type(vsomeip::message_type_e::MT_REQUEST);

	std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
	request->set_payload(its_payload);

	std::cout << "\nSending PR Data Request" << std::endl;
	app->send(request);
}

void request_tof_data() {
	std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request();
	request->set_service(SERVICE_ID_SENSOR);
	request->set_instance(INSTANCE_ID);
	request->set_method(METHOD_ID_TOF);
	request->set_client(CLIENT_ID);
	request->set_interface_version(0x01);
	request->set_message_type(vsomeip::message_type_e::MT_REQUEST);

	std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
	request->set_payload(its_payload);

	std::cout << "\nSending ToF Data Request" << std::endl;
	app->send(request);
}

void request_ultrasonic_data() {
	std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request();
	request->set_service(SERVICE_ID_SENSOR);
	request->set_instance(INSTANCE_ID);
	request->set_method(METHOD_ID_ULT);
	request->set_client(CLIENT_ID);
	request->set_interface_version(0x01);
	request->set_message_type(vsomeip::message_type_e::MT_REQUEST);

	std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
	request->set_payload(its_payload);

	std::cout << "\nSending Ultrasonic Data Request" << std::endl;
	app->send(request);
}

void request_buzzer_control(uint8_t command, int32_t frequency) {
	std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request();
	request->set_service(SERVICE_ID_CONTROL);
	request->set_instance(INSTANCE_ID);
	request->set_method(METHOD_ID_BUZZER);
	request->set_client(CLIENT_ID);
	request->set_interface_version(0x01);
	request->set_message_type(vsomeip::message_type_e::MT_REQUEST);

	std::vector<vsomeip::byte_t> payload_data;
	payload_data.push_back(command);
	append_to_payload(payload_data, frequency);

	std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
	its_payload->set_data(payload_data);
	request->set_payload(its_payload);

	std::cout << "\nSending Buzzer Control Request (Command: " << (int)command
		<< ", Frequency: " << frequency << " Hz)" << std::endl;
	app->send(request);
}

void request_led_control(uint8_t side, uint8_t command) {
	std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request();
	request->set_service(SERVICE_ID_CONTROL);
	request->set_instance(INSTANCE_ID);
	request->set_method(METHOD_ID_LED);
	request->set_client(CLIENT_ID);
	request->set_interface_version(0x01);
	request->set_message_type(vsomeip::message_type_e::MT_REQUEST);

	std::vector<vsomeip::byte_t> payload_data;
	payload_data.push_back(side);
	payload_data.push_back(command);

	std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
	its_payload->set_data(payload_data);
	request->set_payload(its_payload);

	std::cout << "\nSending LED Control Request (Side: " << (int)side << ", Command: " << (int)command << ")" << std::endl;
	app->send(request);
}

void request_alert_control(int64_t cycle_ms) {
	std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request();
	request->set_service(SERVICE_ID_SYSTEM);
	request->set_instance(INSTANCE_ID);
	request->set_method(METHOD_ID_ALERT);
	request->set_client(CLIENT_ID);
	request->set_interface_version(0x01);
	request->set_message_type(vsomeip::message_type_e::MT_REQUEST);

	std::vector<vsomeip::byte_t> payload_data;
	append_to_payload(payload_data, cycle_ms);

	std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
	its_payload->set_data(payload_data);
	request->set_payload(its_payload);

	std::cout << "\nSending Emergency Alert Control Request (Cycle: " << cycle_ms << " ms)" << std::endl;
	app->send(request);
}

void request_motor_control(int32_t motor_x, int32_t motor_y) {
	std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request();
	request->set_service(SERVICE_ID_SYSTEM);
	request->set_instance(INSTANCE_ID);
	request->set_method(METHOD_ID_MOTOR);
	request->set_client(CLIENT_ID);
	request->set_interface_version(0x01);
	request->set_message_type(vsomeip::message_type_e::MT_REQUEST);

	std::vector<vsomeip::byte_t> payload_data;
	append_to_payload(payload_data, motor_x);
	append_to_payload(payload_data, motor_y);

	std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
	its_payload->set_data(payload_data);
	request->set_payload(its_payload);

	std::cout << "\nSending Motor Control Request (X=" << motor_x << ", Y=" << motor_y << ")" << std::endl;
	app->send(request);
}

void client_routine() {
	using namespace std::chrono;

	std::cout << "Waiting 4 second for vsomeip stack to stabilize..." << std::endl;
	std::this_thread::sleep_for(seconds(4));

	// --- 1. Service1 (Sensor) 요청 ---
	request_pr_data();
	std::this_thread::sleep_for(seconds(2));

	request_tof_data();
	std::this_thread::sleep_for(seconds(2));

	request_ultrasonic_data();
	std::this_thread::sleep_for(seconds(2));

	// --- 2. Service2 (Control) 요청 ---
	request_buzzer_control(0x01, 1000);  // Buzzer On, 1000 Hz
	std::this_thread::sleep_for(seconds(2));

	request_led_control(0x00, 0x01);     // LED_BACK On
	std::this_thread::sleep_for(seconds(2));

	// --- 3. Service3 (System) 요청 ---
	request_alert_control(300);          // Emergency Alert Cycle 300 ms
	std::this_thread::sleep_for(seconds(2));

	request_motor_control(50, 80);       // Motor X=50, Y=80
	std::this_thread::sleep_for(seconds(2));

	std::cout << "\nClient routine finished. Stopping app in 1 second..." << std::endl;
	std::this_thread::sleep_for(seconds(1));
	app->stop();
}

int main() {
	app = vsomeip::runtime::get()->create_application("rpi_client_app");
	app->init();

	app->register_availability_handler(SERVICE_ID_SENSOR, INSTANCE_ID, on_availability);
	app->register_availability_handler(SERVICE_ID_CONTROL, INSTANCE_ID, on_availability);
	app->register_availability_handler(SERVICE_ID_SYSTEM, INSTANCE_ID, on_availability);
	app->register_message_handler(vsomeip::ANY_SERVICE, INSTANCE_ID, vsomeip::ANY_METHOD, on_message);

	app->request_service(SERVICE_ID_SENSOR, INSTANCE_ID);
	app->request_service(SERVICE_ID_CONTROL, INSTANCE_ID);
	app->request_service(SERVICE_ID_SYSTEM, INSTANCE_ID);

	std::thread worker(client_routine);

	app->start();

	worker.join();

	return 0;
}