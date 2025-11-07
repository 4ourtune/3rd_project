import time
from joystick import Joystick
from bluetooth import BluetoothHandler


class Controller:
    def __init__(self):
        self.js = Joystick()
        self.bt = BluetoothHandler()
        self.bt.register_callback(self.on_bt_message)
        self.running = True
        self.callback = None  # 외부 콜백 (UI 표시용 등)

    def set_callback(self, callback_func):
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
            # 🔹 스위치 변화 감지
            cur_swt = self.js.get_converted_swt()
            if cur_swt != prev_swt:
                msg = f"P{cur_swt:02}\0"
                self.bt.send(msg)
                self.emit(1, msg)
                print(f"{time.time():.3f} [DEBUG] Send SWT={cur_swt}")
                prev_swt = cur_swt

            # 🔹 조이스틱 변화 감지 (노이즈 필터 반영됨)
            cur_vrx = self.js.get_converted_vrx()
            cur_vry = self.js.get_converted_vry()
            delta_vrx = abs(cur_vrx - prev_vrx)
            delta_vry = abs(cur_vry - prev_vry)
            now = time.time()

            # 5단위 이상 움직임 & 0.1초 간격 이상만 전송
            if (delta_vrx >= 5 or delta_vry >= 5) and (now - last_vr_send_time >= 0.1):
                msg = f"M{cur_vrx:02}{cur_vry:02}\0"
                self.bt.send(msg)
                self.emit(1, msg)
                print(f"{time.time():.3f} [DEBUG] Send VRX={cur_vrx}, VRY={cur_vry}, Δ({delta_vrx},{delta_vry})")
                prev_vrx = cur_vrx
                prev_vry = cur_vry
                last_vr_send_time = now

            time.sleep(0.01)

    def stop(self):
        self.running = False
        self.bt.stop()
        self.bt.wait_until_stopped()
