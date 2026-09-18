"""
auth.log 를 분석하여 브루트포스 의심 IP를 추출하고 JSON으로 덤프하는 스크립트.

핵심 로직:
1. syslog 라인에서 타임스탬프 + 유저명 + IP를 동시에 파싱
2. 사설/루프백 IP는 제외 (내부 장비 노이즈 제거)
3. IP별로 deque에 타임스탬프를 쌓아 슬라이딩 윈도우(기본 5분) 유지
4. 윈도우 내 시도 횟수가 임계치 이상이면 "malicious"로 판정
5. count, first_seen, last_seen, usernames 를 함께 기록
"""

import re
import json
import ipaddress
from datetime import datetime
from collections import defaultdict, deque

# ---------------------------------------------------------
# 설정값 (필요에 따라 조정)
# ---------------------------------------------------------
LOG_FILE = "auth.log"
OUTPUT_FILE = "malicious_ip.json"   
WINDOW_SECONDS = 300                # 슬라이딩 윈도우 크기: 5분
THRESHOLD = 10                      # 윈도우 내 임계 시도 횟수
EXCLUDE_PRIVATE = True              # 사설/링크로컬 IP 제외 여부

# syslog 형식 예시:
# Jan 12 03:14:15 myhost sshd[1234]: Failed password for invalid user admin from 85.245.107.41 port 51234 ssh2
LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r".*Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)

MONTH_INDEX = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def is_excluded_ip(ip_str):
    """루프백/사설/링크로컬 IP 여부 확인 (내부 장비 노이즈 제거용)."""
    try:
        address = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # 파싱 안되면 일단 제외

    if address.is_loopback:
        return True
    if EXCLUDE_PRIVATE and (address.is_private or address.is_link_local):
        return True
    return False


def parse_timestamp(month_str, day_str, time_str, reference_year, reference_month):
    """
    syslog 라인엔 연도가 없으므로, 기준 연도를 받아 보정한다.
    로그의 월(month)이 기준 시점보다 미래(예: 12월 로그를 1월에 분석)면
    작년으로 간주해서 연도를 하나 낮춘다 (연말/연초 경계 처리).
    """
    month_num = MONTH_INDEX[month_str]
    year = reference_year
    if month_num > reference_month:
        year -= 1

    dt_str = f"{year} {month_str} {day_str} {time_str}"
    return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")


def analyze_log(file_path):
    now = datetime.now()

    # 윈도우 내 최근 타임스탬프 추적용 (브루트포스 판정)
    recent_attempts = defaultdict(deque)

    # 전체 통계 누적용 (count, first/last seen, usernames)
    stats = defaultdict(lambda: {
        "count": 0,
        "first_seen": None,
        "last_seen": None,
        "usernames": set(),
    })

    malicious_ips = set()

    with open(file_path, encoding="utf-8") as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if not match:
                continue

            ip = match.group("ip")
            if is_excluded_ip(ip):
                continue

            user = match.group("user")
            ts = parse_timestamp(
                match.group("month"), match.group("day"), match.group("time"),
                reference_year=now.year, reference_month=now.month,
            )

            # --- 슬라이딩 윈도우 갱신 ---
            dq = recent_attempts[ip]
            dq.append(ts)
            while dq and (ts - dq[0]).total_seconds() > WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= THRESHOLD:
                malicious_ips.add(ip)

            # --- 통계 갱신 ---
            entry = stats[ip]
            entry["count"] += 1
            entry["usernames"].add(user)
            if entry["first_seen"] is None or ts < entry["first_seen"]:
                entry["first_seen"] = ts
            if entry["last_seen"] is None or ts > entry["last_seen"]:
                entry["last_seen"] = ts

    # --- 결과 조립 (malicious로 판정된 IP만 최종 포함) ---
    result = {}
    for ip in malicious_ips:
        entry = stats[ip]
        result[ip] = {
            "count": entry["count"],
            "first_seen": entry["first_seen"].isoformat(),
            "last_seen": entry["last_seen"].isoformat(),
            "usernames": sorted(entry["usernames"]),
        }

    return result


def main():
    result = analyze_log(LOG_FILE)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"{len(result)}개의 의심 IP를 {OUTPUT_FILE} 에 저장했습니다.")


if __name__ == "__main__":
    main()