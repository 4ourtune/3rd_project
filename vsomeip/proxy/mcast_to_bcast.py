#!/usr/bin/env python3
import socket
import struct

# === CONFIG ===
IFACE = "eth0"
LOCAL_IP = "192.168.2.31"         # 라즈베리파이 eth0 IP
MCAST_GRP = "224.224.224.245"
PORT = 30490
BCAST_ADDR = "192.168.2.255"

# === 수신 소켓 (Multicast) ===
recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
recv.bind(('', PORT))

# 멀티캐스트 그룹 가입
mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton("0.0.0.0"))
recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# === 송신 소켓 (Broadcast) ===
send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# eth0로 강제 전송 (Linux only, root 권한 필요)
try:
    send.setsockopt(socket.SOL_SOCKET, 25, IFACE.encode() + b'\0')
except OSError as e:
    print(f"[WARN] Could not bind to {IFACE}: {e}")

print(f"[INFO] Multicast→Broadcast relay active")
print(f"       {MCAST_GRP}:{PORT}  ==>  {BCAST_ADDR}:{PORT} on {IFACE}")
print(f"       Local IP = {LOCAL_IP}")
print()

try:
    while True:
        data, addr = recv.recvfrom(4096)
        src_ip, src_port = addr

        # === 루프 방지 ===
        # 1. 자기 자신이 보낸 것
        if src_ip == LOCAL_IP:
            continue

        # 2. 이미 broadcast 주소에서 온 것
        if src_ip == BCAST_ADDR:
            continue

        # === 브로드캐스트로 송신 ===
        send.sendto(data, (BCAST_ADDR, PORT))
        # print(f"[RELAY] {src_ip} → {BCAST_ADDR}, {len(data)} bytes")

except KeyboardInterrupt:
    print("\n[INFO] Relay stopped.")
finally:
    recv.close()
    send.close()

