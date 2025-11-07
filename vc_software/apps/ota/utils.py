# apps/ota/utils.py
import hashlib
import urllib.request
import os
from config import INBOX_DIR, LOG_DIR

def log(msg: str):
    """공용 로그 함수"""
    log_path = os.path.join(LOG_DIR, "ota.log")
    with open(log_path, "a") as f:
        f.write(msg + "\n")
    print(msg)

def download_file(url: str, dest_path: str):
    """지정한 URL에서 파일을 다운로드하여 dest_path에 저장"""
    try:
        urllib.request.urlretrieve(url, dest_path)
    except Exception as e:
        log(f"다운로드 실패: {e}")
        raise

def verify_checksum(file_path: str, expected_checksum: str) -> bool:
    """파일의 SHA256 해시를 계산하고 expected_checksum과 비교"""
    if not expected_checksum:
        log("체크섬 값이 비어있음 — 검증 건너뜀")
        return True

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    calculated = sha256.hexdigest()
    log(f"체크섬 계산 결과: {calculated}")

    if calculated == expected_checksum:
        return True
    else:
        log(f"체크섬 불일치 (expected={expected_checksum[:10]}..., got={calculated[:10]}...)")
        return False
