#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-resolution capture script for Raspberry Pi Camera Module 3 (IMX708)
- Picamera2-based
- Autofocus enabled
- ROI adjusted for lower road view (LKAS / AEB data capture)
Author: Hyunje
"""

import time
import cv2
from picamera2 import Picamera2

# -------------------------------
# 사용자 설정
# -------------------------------
FRAME_SIZE = (4608, 2592)   # IMX708 full resolution
CAPTURE_INTERVAL = 1        # 초 단위 (1초마다 촬영)
CAPTURE_DURATION = 60       # 총 촬영 시간 (초 단위)
ROI_OFFSET_Y = 400          # 하단 영역 강조 (0~500 정도에서 조정)
OUTPUT_DIR = "./images"   # 저장 경로

# -------------------------------
# 카메라 초기화
# -------------------------------
picam2 = Picamera2()

config = picam2.create_still_configuration(main={"size": FRAME_SIZE})
picam2.configure(config)
picam2.start()
time.sleep(2)  # 워밍업

# ✅ 자동 초점 활성화 (모듈 3만 가능)
try:
    picam2.set_controls({"AfMode": 2, "AfTrigger": 0})
    print("🔍 Autofocus enabled.")
except Exception as e:
    print(f"⚠️ Autofocus not supported or already active: {e}")

# ✅ ROI 하단 이동 (도로/차선 강조)
try:
    picam2.set_controls({
        "ScalerCrop": (0, ROI_OFFSET_Y, FRAME_SIZE[0], FRAME_SIZE[1] - ROI_OFFSET_Y)
    })
    print(f"📷 ROI set to bottom region (offset_y={ROI_OFFSET_Y})")
except Exception as e:
    print(f"⚠️ ROI control failed: {e}")

print(f"✅ Camera ready. Capturing every {CAPTURE_INTERVAL}s for {CAPTURE_DURATION}s...")
print(f"💾 Output path: {OUTPUT_DIR}")

# -------------------------------
# 캡처 루프
# -------------------------------
start_time = time.time()
count = 0

try:
    while True:
        elapsed = time.time() - start_time
        if elapsed > CAPTURE_DURATION:
            print("🕒 Capture duration finished.")
            break

        frame = picam2.capture_array()
        filename = f"{OUTPUT_DIR}/capture_{count:04d}.jpg"
        cv2.imwrite(filename, frame)
        print(f"📸 Saved {filename} ({int(elapsed)}s elapsed)")
        count += 1
        time.sleep(CAPTURE_INTERVAL)

except KeyboardInterrupt:
    print("\n🛑 User interrupted capture.")

finally:
    picam2.stop()
    print("📷 Camera stopped and released.")
