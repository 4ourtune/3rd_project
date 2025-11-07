import socket
import threading
import time


class BluetoothHandler:
    """
    UDP 기반 송수신 핸들러.
    기존 BluetoothHandler와 동일한 인터페이스를 유지하지만
    내부는 블루투스(UART)가 아닌 UDP 소켓 통신으로 구현됨.

    - 포트 5001을 사용 (VC가 이 포트를 수신)
    - recvfrom() 스레드를 별도로 구동하여 실시간 수신
    """

    def __init__(self, udp_ip="192.168.137.35", udp_port=5001, listen_port=5002):
        # ✅ 목적지 (VC 라즈베리파이)
        self.udp_ip = udp_ip
        self.udp_port = udp_port

        # ✅ 조이스틱 자신이 수신할 포트
        self.listen_port = listen_port

        # ✅ UDP 소켓 초기화
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.listen_port))

        self.callback = None
        self.running = False
        self.thread = None

    def start(self):
        """UDP 수신 스레드 시작"""
        self.running = True
        self.thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.thread.start()
        print(f"[UDP 시작] Handler started (dst={self.udp_ip}:{self.udp_port}, listen={self.listen_port})")

    def stop(self):
        """UDP 소켓 및 스레드 종료"""
        self.running = False
        try:
            self.sock.close()
            print("[UDP 종료] 소켓 닫힘.")
        except Exception as e:
            print(f"[UDP 종료 에러] {e}")

    def wait_until_stopped(self):
        """수신 스레드 종료 대기"""
        if self.thread:
            self.thread.join()
            print("[UDP 종료 대기] 쓰레드 종료 완료.")

    def send(self, message: str):
        """
        UDP 전송.
        기존 BluetoothHandler와 동일한 함수명 유지 (controller.py 호환)
        """
        try:
            data = (message + '\n').encode()
            self.sock.sendto(data, (self.udp_ip, self.udp_port))
            # print(f"[UDP 송신] {message.strip()}")
        except Exception as e:
            print(f"[UDP 송신 에러] {e}")

    def register_callback(self, callback):
        """수신 메시지용 콜백 등록"""
        self.callback = callback

    def _receive_loop(self):
        """UDP 수신 스레드"""
        print(f"[UDP 수신 루프] 시작됨 (listen={self.listen_port})")
        while self.running:
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(1024)
                if not data:
                    continue

                message = data.decode(errors="ignore").strip()
                if message and self.callback:
                    self.callback(message)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                print(f"[UDP 수신 에러] {e}")
                break
        print("[UDP 수신 루프] 종료됨.")
