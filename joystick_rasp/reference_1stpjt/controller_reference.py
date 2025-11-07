import time
from joystick import Joystick
from bluetooth import BluetoothHandler


class Controller:
    def __init__(self):
        self.js = Joystick()
        self.bt = BluetoothHandler()
        self.bt.register_callback(self.on_bt_message)
        self.running = True
        self.callback = None  # signal 대신 사용할 콜백 함수

    def set_callback(self, callback_func):
        """
        콜백 함수를 설정합니다.
        callback_func: 함수 (int, str) -> None
        """
        self.callback = callback_func

    def emit(self, kind: int, message: str):
        if self.callback:
            self.callback(kind, message)

    def on_bt_message(self, message: str):
        self.emit(2, message)

    def run(self):
        self.bt.start()

        prev_swt = self.js.get_converted_swt()
        prev_vrx = self.js.get_converted_vrx()
        prev_vry = self.js.get_converted_vry()
        last_vr_send_time = time.time()

        while self.running:
            # 스위치 값이 바뀌었을 때만 전송
            cur_swt = self.js.get_converted_swt()
            if cur_swt != prev_swt:
                msg = f"P{cur_swt:02}" + '\0'
                self.bt.send(msg)
                self.emit(1, msg)
                prev_swt = cur_swt

            # 조이스틱이 일정 이상 움직였을 때 + 시간 간격도 만족할 때만 전송
            cur_vrx = self.js.get_converted_vrx()
            cur_vry = self.js.get_converted_vry()
            delta_vrx = abs(cur_vrx - prev_vrx)
            delta_vry = abs(cur_vry - prev_vry)
            now = time.time()

            if (delta_vrx >= 2 or delta_vry >= 2) and (now - last_vr_send_time >= 0.1):
                msg = f"M{cur_vrx:02}{cur_vry:02}" + '\0'
                self.bt.send(msg)
                self.emit(1, msg)
                prev_vrx = cur_vrx
                prev_vry = cur_vry
                last_vr_send_time = now

            time.sleep(0.01)

    def stop(self):
        self.running = False
        self.bt.stop()
        self.bt.wait_until_stopped()