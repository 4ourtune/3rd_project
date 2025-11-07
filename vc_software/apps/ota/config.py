# apps/ota/config.py
BROKER_HOST = "192.168.137.1"
BROKER_PORT = 1883
TOPIC = "ota/vehicle_control/update"

REQUIRE_CONFIRM_DEFAULT = True  # 기본적으로 OTA 적용 전에 사용자 확인을 요구

# OTA 디렉터리 설정
import os
BASE_DIR = os.path.dirname(__file__)
INBOX_DIR = os.path.join(BASE_DIR, "inbox")
LOG_DIR = os.path.join(BASE_DIR, "logs")

os.makedirs(INBOX_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
