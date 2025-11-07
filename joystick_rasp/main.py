from controller import Controller  # Controller 클래스가 있는 파일명이 controller.py라고 가정

def my_callback(kind: int, message: str):
    if kind == 1:
        print(f"[SEND] {message.strip()}")
    elif kind == 2:
        print(f"[RECV] {message.strip()}")

controller = Controller()
controller.set_callback(my_callback)

try:
    print("Controller started. Press Ctrl+C to stop.")
    controller.run()  # 블로킹 실행 (메인 루프에서 작동)
except KeyboardInterrupt:
    print("Stopping controller...")
    controller.stop()