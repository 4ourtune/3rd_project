import threading
import serial


class BluetoothHandler:
    def __init__(self, port="/dev/rfcomm0", baudrate=9600):
        self.port = port
        self.baudrate = baudrate
        self.serial = None
        self.callback = None
        self.running = False
        self.thread = None

    def start(self):
        try:
            self.serial = serial.Serial(self.port, self.baudrate, timeout=1)
            self.running = True
            self.thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.thread.start()
            print("[BT 시작] BluetoothHandler 시작됨.")
        except Exception as e:
            print(f"[BT 시작 에러] {e}")

    def stop(self):
        self.running = False
        if self.serial:
            try:
                if self.serial.is_open:
                    self.serial.close()
                    print("[BT 종료] 시리얼 포트 닫힘.")
            except Exception as e:
                print(f"[BT 종료 에러] {e}")
        else:
            print("[BT 종료] 시리얼 포트가 None임.")

    def wait_until_stopped(self):
        if self.thread:
            self.thread.join()
            print("[BT 종료 대기] 쓰레드 종료 완료.")

    def send(self, message: str):
        if self.serial and self.serial.is_open:
            try:
                self.serial.write((message + '\n').encode())
            except Exception as e:
                print(f"[BT 송신 에러] {e}")
        else:
            print("[BT 송신 실패] 시리얼 포트가 열려있지 않음.")

    def register_callback(self, callback):
        self.callback = callback

    def _receive_loop(self):
        print("[BT 수신 루프] 시작됨.")
        while self.running:
            try:
                # 시리얼 객체 유효성 검사
                if self.serial is None or not self.serial.is_open:
                    print("[BT 수신 루프] 시리얼이 None이거나 닫힘. 종료.")
                    break

                # readline() 호출
                raw = self.serial.readline()

                if not raw:
                    continue

                data = raw.decode(errors='ignore').strip()

                if data and self.callback:
                    self.callback(data)

            except Exception as e:
                print(f"[BT 에러] {e}")
                break

        print("[BT 수신 루프] 종료됨.")