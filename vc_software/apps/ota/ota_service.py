# apps/ota/ota_service.py
import os
import stat
import time
import subprocess
import json
import paho.mqtt.client as mqtt
from config import BROKER_HOST, BROKER_PORT, TOPIC, INBOX_DIR, REQUIRE_CONFIRM_DEFAULT
from utils import log, download_file, verify_checksum

def load_versions():
    path = os.path.join(os.path.dirname(__file__), "versions.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_versions(data):
    path = os.path.join(os.path.dirname(__file__), "versions.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def apply_ota(target, version, checksum):
    target_path = target["target_path"]
    src_url = target["source_path"]
    backup_dir = target["backup_path"]
    process_name = target.get("process_check") or os.path.basename(target_path)
    file_name = os.path.basename(target_path)

    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(INBOX_DIR, exist_ok=True)

    temp_file = os.path.join(INBOX_DIR, file_name)

    # 1. 다운로드
    download_file(src_url, temp_file)
    log(f"다운로드 완료: {src_url} → {temp_file}")

    # 2. 체크섬 검증
    if not verify_checksum(temp_file, checksum):
        log("체크섬 불일치 — OTA 중단")
        return False

    # 3. 기존 파일 백업
    if os.path.exists(target_path):
        backup_file = os.path.join(backup_dir, f"{file_name}_{int(time.time())}")
        os.rename(target_path, backup_file)
        log(f"기존 파일 백업 완료: {backup_file}")

    # 4. 새 파일로 교체
    os.rename(temp_file, target_path)
    log(f"파일 교체 완료: {target_path}")
    try:
        current_mode = os.stat(target_path).st_mode
    except OSError as exc:
        log(f"신규 파일 정보 확인 실패: {exc}")
        return False

    required_exec = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if not current_mode & required_exec:
        new_mode = current_mode | required_exec
        try:
            os.chmod(target_path, new_mode)
            log(f"실행 권한을 추가했습니다: {target_path} (mode={oct(new_mode & 0o777)})")
        except PermissionError as exc:
            log(f"실행 권한 설정 실패: {exc}")
            return False
    else:
        log(f"실행 권한이 이미 설정되어 있습니다: {target_path}")

    # 5. 서비스 재시작
    try:
        subprocess.run(["sudo", "systemctl", "restart", f"vc-{process_name}.service"], check=True)
        log(f"{process_name} 서비스 재시작 완료")
    except Exception as e:
        log(f"서비스 재시작 실패: {e}")

    # 6. 버전 갱신
    versions = load_versions()
    versions[file_name] = version
    save_versions(versions)
    log(f"버전 업데이트: {file_name} → {version}")

    return True

# --- MQTT 구독 루프 ---
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        log(f"[MQTT] 연결 성공 ({BROKER_HOST}:{BROKER_PORT}) → 토픽: {TOPIC}")
        client.subscribe(TOPIC)
    else:
        log(f"[MQTT] 연결 실패 (code={rc})")

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode("utf-8")
        log(f"[MQTT] 메시지 수신 → {msg.topic}: {payload}")
        data = json.loads(payload)

        target = data["target"]
        version = data.get("version", "unknown")
        checksum = data.get("checksum", "")

        require_confirm = data.get("require_confirm")
        if require_confirm is None:
            require_confirm = REQUIRE_CONFIRM_DEFAULT
        else:
            require_confirm = bool(require_confirm)

        # require_confirm이 True면 사용자 확인 절차
        if require_confirm:
            print("\n=======================================")
            print(f"새 버전({version}) 업데이트 요청이 있습니다.")
            desc = data.get("description", "")
            if desc:
                print(f"설명: {desc}")
            print("적용하시겠습니까? (y/n): ", end="", flush=True)
            try:
                user_input = input().strip().lower()
            except EOFError:
                log("[OTA] 입력 스트림이 없어 업데이트를 진행하지 않습니다.")
                return

            if user_input not in ("y", "yes"):
                log("[OTA] 업데이트가 취소되었습니다.")
                return

            log("[OTA] 사용자가 업데이트를 승인했습니다.")

        # 확인이 필요 없거나, 승인되었으므로 적용
        apply_ota(target, version, checksum)

    except Exception as e:
        log(f"[MQTT] 메시지 처리 오류: {e}")



if __name__ == "__main__":
    log("[OTA] OTA 서비스 시작됨 (MQTT 구독 중...)")
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    backoff = 5
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, 60)
            client.loop_forever()
        except Exception as e:
            log(f"[OTA] MQTT 연결 실패: {e} — {backoff}초 후 재시도")
            time.sleep(backoff)
