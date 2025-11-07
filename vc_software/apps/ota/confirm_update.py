import json
import os
from ota_service import apply_ota, log

PENDING_PATH = "/home/hj/vc_software/apps/ota/pending_update.json"

def main():
    if not os.path.exists(PENDING_PATH):
        print("대기 중인 업데이트가 없습니다.")
        return

    with open(PENDING_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    target = data["target"]
    version = data.get("version", "unknown")
    checksum = data.get("checksum", "")

    print(f"버전 {version} 업데이트를 적용하시겠습니까? (y/n)")
    if input().lower() == "y":
        apply_ota(target, version, checksum)
        os.remove(PENDING_PATH)
        print("✅ 업데이트 완료되었습니다.")
    else:
        print("❌ 업데이트 취소됨.")

if __name__ == "__main__":
    main()
