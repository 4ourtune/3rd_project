### vc_라파4 ID, PW
```
ID: cyh
PW: 1111
```

### 라파4 네트워크 설정

sudo nmtui

eth0의 ipv4 설정을 manual로 변경 후, address를 192.168.2.30/24 로 설정
→ TC375 ip: 192.168.2.20, 서브넷 마스크: 255.255.255.0 이라서

### 클라이언트 코드 빌드 명령어

cyh@cyh:~/Pjt2/vsomeip/build $ 에서

```
rm -rf *
cmake ..
make
```

### SOMEIP-SD 사용 전에
❗ Make sure that your device has been configured for receiving multicast messages
e.g.
```
sudo route add -nv  224.224.224.245 dev eth0
```
or similar; that depends on teh name of your ethernet device.

### 클라이언트 코드 실행 명령어

```
export VSOMEIP_CONFIGURATION=../vsomeip.json
export VSOMEIP_APPLICATION_NAME=rpi_client_app
export LD_LIBRARY_PATH=/usr/local/lib
sudo -E ./sensor_comm_test
```

### 현재 프로세스 강제 종료

- **`Ctrl + Z`** → 프로세스를 일시 중지 (background로 보냄)
- **`kill` 명령어로 종료**
    
    ```bash
    jobs       # 현재 백그라운드 잡 번호 확인
    kill -9 %1 # 1번 job 강제 종료
    ```
    
    또는
    
    ```bash
    ps -ef | grep 프로그램이름
    kill -9 <PID>
    ```
