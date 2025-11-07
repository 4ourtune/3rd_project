#!/usr/bin/env python3
# 사용법: pip3 install paho-mqtt → 환경변수(MQTT_HOST=PC 브로커 IP 등) 설정 → python3 ota_bridge.py 실행
# 옵션: --send-notify <json 파일> 로 테스트 알림 발행, --debug-print 로 수신/전달 로그 상세 출력
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import string
import threading
import time
from pathlib import Path
from typing import Any, Optional

import paho.mqtt.client as mqtt


DEFAULT_MQTT_HOST = os.environ.get("MQTT_HOST", "192.168.137.1")  # PC 브로커 IP
DEFAULT_MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
DEFAULT_VIN = os.environ.get("VEHICLE_VIN", "TESTVIN0000000000")


def _default_client_id_suffix() -> str:
    hostname = socket.gethostname()
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{hostname}-{rand}"


CLIENT_ID_SUFFIX = os.environ.get("CLIENT_ID_SUFFIX", _default_client_id_suffix())
CLIENT_ID = f"vc-ota-bridge-{CLIENT_ID_SUFFIX}"

TOPIC_NOTIFY = "ota/vehicle_control/notify"
TOPIC_DECISION = "ui/ota/decision"
OTA_UPDATE_TOPIC = "ota/vehicle_control/update"


def prefixed(topic_tail: str, vin: Optional[str] = None) -> str:
    vin_value = vin or DEFAULT_VIN
    return f"vc/{vin_value}/{topic_tail}"


class ExponentialBackoff:
    def __init__(self, base: int = 1, factor: int = 2, maximum: int = 30) -> None:
        self._base = base
        self._factor = factor
        self._maximum = maximum
        self._current = base
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._current = self._base

    def wait(self) -> None:
        with self._lock:
            delay = self._current
            self._current = min(self._current * self._factor, self._maximum)
        print(f"[MQTT] 재연결 대기 {delay}초...", flush=True)
        time.sleep(delay)


class OtaBridge:
    def __init__(self, debug: bool = False, send_notify: Optional[dict[str, Any]] = None) -> None:
        self._debug = debug
        self._client = mqtt.Client(client_id=CLIENT_ID, clean_session=True)
        self._client.enable_logger(None)
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message
        self._backoff = ExponentialBackoff()
        self._disconnect_lock = threading.Lock()
        self._reconnecting = False
        self._stop_event = threading.Event()
        self._latest_notify: Optional[dict[str, Any]] = None
        self._latest_version: Optional[str] = None
        self._processed_versions: set[str] = set()
        self._pending_send_notify = send_notify

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: dict[str, Any], rc: int) -> None:
        if rc == 0:
            print(f"[MQTT] 연결 성공 → {DEFAULT_MQTT_HOST}:{DEFAULT_MQTT_PORT}", flush=True)
            self._backoff.reset()
            notify_topic = prefixed(TOPIC_NOTIFY)
            decision_topic = prefixed(TOPIC_DECISION)
            client.subscribe([(notify_topic, 1), (decision_topic, 1)])
            print(f"[MQTT] 구독: {notify_topic}, {decision_topic}", flush=True)
            if self._pending_send_notify is not None:
                self._publish_notify_payload(self._pending_send_notify)
                self._pending_send_notify = None
        else:
            print(f"[MQTT] 연결 실패 rc={rc}", flush=True)

    def _on_disconnect(self, client: mqtt.Client, userdata: Any, rc: int) -> None:
        if self._stop_event.is_set():
            return
        if rc != 0:
            print(f"[MQTT] 예기치 않은 연결 종료 rc={rc}", flush=True)
        self._schedule_reconnect()

    def _schedule_reconnect(self) -> None:
        with self._disconnect_lock:
            if self._reconnecting or self._stop_event.is_set():
                return
            self._reconnecting = True

        def _worker() -> None:
            while not self._stop_event.is_set():
                try:
                    print("[MQTT] 재연결 시도...", flush=True)
                    self._client.reconnect()
                    print("[MQTT] 재연결 성공", flush=True)
                    self._backoff.reset()
                    break
                except Exception as exc:  # pylint: disable=broad-except
                    print(f"[MQTT] 재연결 실패: {exc}", flush=True)
                    self._backoff.wait()
            with self._disconnect_lock:
                self._reconnecting = False

        threading.Thread(target=_worker, daemon=True).start()

    def _debug_log(self, message: str) -> None:
        if self._debug:
            print(f"[DEBUG] {message}", flush=True)

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
        try:
            payload = msg.payload.decode("utf-8")
        except UnicodeDecodeError:
            print(f"[MQTT] 디코딩 실패: {msg.topic}", flush=True)
            return

        print(f"[MQTT] 수신 {msg.topic}: {payload}", flush=True)
        try:
            data = json.loads(payload)
            if not isinstance(data, dict):
                raise ValueError("payload is not a JSON object")
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[브릿지] JSON 파싱 실패: {exc}", flush=True)
            return

        notify_topic = prefixed(TOPIC_NOTIFY)
        decision_topic = prefixed(TOPIC_DECISION)

        if msg.topic == notify_topic:
            self._handle_notify(data)
        elif msg.topic == decision_topic:
            self._handle_decision(data)

    def _handle_notify(self, data: dict[str, Any]) -> None:
        version = str(data.get("version", "unknown"))
        update = data.get("update")
        if not isinstance(update, dict):
            print("[브릿지] update 필드가 없어 버퍼하지 않습니다.", flush=True)
            return
        self._latest_notify = data
        self._latest_version = version
        self._debug_log(f"최근 OTA 알림 저장 version={version}")
        if version in self._processed_versions:
            print(f"[브릿지] version {version} 은 이미 처리된 업데이트입니다.", flush=True)

    def _handle_decision(self, data: dict[str, Any]) -> None:
        decision = data.get("decision")
        version = str(data.get("version", ""))
        if decision not in {"yes", "no"}:
            print(f"[브릿지] 알 수 없는 결정 {decision}", flush=True)
            return

        if decision == "no":
            print(f"[브릿지] OTA version {version} 거절됨", flush=True)
            return

        if not self._latest_notify or not self._latest_version:
            print("[브릿지] 대기 중인 OTA 알림이 없어 yes를 무시합니다.", flush=True)
            return

        if version != self._latest_version:
            print(
                f"[브릿지] 결정 버전({version})과 최신 알림 버전({self._latest_version})이 다릅니다.",
                flush=True,
            )
            return

        if version in self._processed_versions:
            print(f"[브릿지] version {version} 이미 처리되어 무시합니다.", flush=True)
            return

        update = self._latest_notify.get("update")
        if not isinstance(update, dict):
            print("[브릿지] 최신 알림에 update 데이터가 없어 전송 불가", flush=True)
            return

        self._debug_log(f"OTA yes 처리 진행 version={version}")
        try:
            self._publish_update(update)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[브릿지] OTA 업데이트 전달 중 예외: {exc}", flush=True)
            return
        self._processed_versions.add(version)
        self._debug_log(f"version {version} 처리 완료, processed set={self._processed_versions}")

    def _publish_update(self, update: dict[str, Any]) -> None:
        payload = json.dumps(update, ensure_ascii=False)
        result = self._client.publish(OTA_UPDATE_TOPIC, payload=payload, qos=1, retain=False)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            print(f"[브릿지] OTA 업데이트 전달 → {OTA_UPDATE_TOPIC}: {payload}", flush=True)
        else:
            print(f"[브릿지] OTA 업데이트 전달 실패 rc={result.rc}", flush=True)

    def _publish_notify_payload(self, notify: dict[str, Any]) -> None:
        topic = prefixed(TOPIC_NOTIFY)
        payload = json.dumps(notify, ensure_ascii=False)
        result = self._client.publish(topic, payload=payload, qos=1, retain=False)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            print(f"[브릿지] 테스트 notify 발행 → {topic}", flush=True)
        else:
            print(f"[브릿지] 테스트 notify 발행 실패 rc={result.rc}", flush=True)

    def connect(self) -> None:
        delay = 1
        while not self._stop_event.is_set():
            try:
                print(f"[MQTT] 연결 시도 → {DEFAULT_MQTT_HOST}:{DEFAULT_MQTT_PORT}", flush=True)
                self._client.connect(DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, keepalive=60)
                print("[MQTT] 연결 완료, 브릿지 가동", flush=True)
                self._backoff.reset()
                break
            except Exception as exc:  # pylint: disable=broad-except
                print(f"[MQTT] 연결 실패: {exc}", flush=True)
                print(f"[MQTT] {delay}초 후 재시도", flush=True)
                time.sleep(delay)
                delay = min(delay * 2, 30)

        self._client.loop_start()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._client.disconnect()
        except Exception:  # pylint: disable=broad-except
            pass
        self._client.loop_stop()


def load_notify_file(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    if "update" not in data:
        raise ValueError("notify JSON must include update field")
    return data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Vehicle Control OTA MQTT bridge")
    parser.add_argument(
        "--send-notify",
        type=str,
        default=None,
        help="연결 완료 후 지정된 JSON 파일을 notify 토픽으로 발행합니다.",
    )
    parser.add_argument(
        "--debug-print",
        action="store_true",
        help="수신/중계 이벤트를 상세 출력합니다.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    send_notify_payload: Optional[dict[str, Any]] = None
    if args.send_notify:
        file_path = Path(args.send_notify).expanduser()
        try:
            send_notify_payload = load_notify_file(file_path)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[브릿지] notify 파일 로드 실패: {exc}", flush=True)
            return

    bridge = OtaBridge(debug=args.debug_print, send_notify=send_notify_payload)

    try:
        bridge.connect()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[시스템] 사용자 종료 요청(Ctrl+C)", flush=True)
    finally:
        bridge.stop()
        print("[시스템] OTA 브릿지 종료", flush=True)


if __name__ == "__main__":
    main()
