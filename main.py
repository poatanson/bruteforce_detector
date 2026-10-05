"""
auth.log 를 분석하여 브루트포스 의심 IP를 추출하고 JSON으로 덤프하는 스크립트.

핵심 로직:
1. sshd 로그 라인에서 타임스탬프 + 유저명 + IP + 포트를 파싱
   - 전통 syslog(Jan 12 03:14:15)와 ISO-8601(2024-01-12T03:14:15+09:00) 형식을 모두 지원
   - 유저명은 공격자가 통제하므로, 라인에서 "마지막" `from <ip> port <n>` 을 실제 접속 정보로 사용
     (유저명에 가짜 "from 8.8.8.8 port 22" 를 심어도 속지 않음)
2. 집계 대상 이벤트
   - Failed password / publickey / keyboard-interactive (유효한 계정)
   - Invalid user (존재하지 않는 계정). sshd는 "Invalid user" 뒤에 같은 (ip, port) 로
     "Failed ... for invalid user" 를 또 남기므로, 그 첫 번째 한 건만 중복으로 보고 건너뜀
     (같은 연결의 2번째 이후 실패나, Invalid user 라인이 없는 로그는 그대로 집계)
3. IPv4/IPv6 모두 지원, IPv4-mapped IPv6 는 IPv4로 정규화, 사설/루프백 IP는 제외
4. IP별 deque 로 슬라이딩 윈도우(기본 5분) 유지, 윈도우 내 "최대 시도 횟수(peak)"가
   임계치 이상이면 "malicious"로 판정
5. count / first_seen / last_seen / usernames 는 파일 전체 기준,
   peak_window 는 판정 근거가 된 버스트 구간 기준으로 함께 기록
6. 매칭/제외/실패 라인 수를 요약 출력하고, 매칭이 0건이면 경고(종료코드 2)
"""

import argparse
import gzip
import ipaddress
import json
import os
import re
import sys
from collections import Counter, OrderedDict, defaultdict, deque
from datetime import datetime, timedelta

# ---------------------------------------------------------
# 기본 설정값 (CLI 옵션으로 덮어쓸 수 있음)
# ---------------------------------------------------------
DEFAULT_LOG_FILE = "auth.log"
DEFAULT_OUTPUT_FILE = "malicious_ip.json"
DEFAULT_WINDOW_SECONDS = 300        # 슬라이딩 윈도우 크기: 5분
DEFAULT_THRESHOLD = 10              # 윈도우 내 임계 시도 횟수
MAX_USERNAMES_PER_IP = 200          # IP당 유저명 저장 상한 (메모리 보호)
MAX_PENDING_INVALID = 10000         # 중복 제거용 (ip, port) 기억 상한 (메모리 보호)

MONTH_INDEX = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# 로그 앞부분: 타임스탬프 + 호스트명 + sshd 프로세스명
# - 전통 syslog:  Jan 12 03:14:15 myhost sshd[1234]: ...
# - ISO-8601:     2024-01-12T03:14:15.123456+09:00 myhost sshd[1234]: ...
# - OpenSSH 9.8+ 는 프로세스명이 sshd-session 으로 바뀌므로 함께 허용
_HEADER = (
    r"^(?:(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?))"
    r"\s+\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+"
)
# user 를 탐욕적(.+)으로 잡는 이유: 라인의 "마지막" from/port 쌍을 실제 접속 정보로 쓰기 위함
_TAIL = r" from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"

FAILED_PATTERN = re.compile(
    _HEADER
    + r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    + r"(?P<invalid>invalid user )?(?P<user>.+)"
    + _TAIL
)
INVALID_PATTERN = re.compile(_HEADER + r"Invalid user (?P<user>.*)" + _TAIL)


def normalize_ip(ip_str):
    """문자열을 ip_address 로 변환. IPv4-mapped IPv6 는 IPv4로 정규화. 실패 시 None."""
    try:
        address = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address


def is_excluded_ip(address, exclude_private):
    """루프백/미지정/멀티캐스트는 항상, 사설/링크로컬은 옵션에 따라 제외."""
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return True
    if exclude_private and (address.is_private or address.is_link_local):
        return True
    return False


def build_datetime(year, month, day, hour, minute, second):
    """
    datetime 생성. strptime(%b) 은 로케일에 의존하므로 숫자로 직접 만든다.
    2월 29일이 평년에 걸리면 ValueError 가 나므로, 가장 가까운 과거 윤년으로 내린다.
    """
    while True:
        try:
            return datetime(year, month, day, hour, minute, second)
        except ValueError:
            if (month, day) != (2, 29):
                raise
            year -= 1


def parse_timestamp(match, reference):
    """
    매치 객체에서 naive datetime 을 만든다. 실패하면 ValueError.

    - ISO-8601: 연도/오프셋이 있으므로 그대로 사용 (오프셋은 버리고 로그에 적힌 시각 유지)
    - syslog: 연도가 없으므로 reference(보통 파일 mtime) 기준으로 추정한다.
      올해로 가정한 시각이 reference 보다 하루 넘게 미래면 작년 로그로 본다.
    """
    iso = match.group("iso")
    if iso:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).replace(tzinfo=None)

    month = MONTH_INDEX.get(match.group("month"))
    if month is None:
        raise ValueError(f"알 수 없는 월: {match.group('month')}")
    day = int(match.group("day"))
    hour, minute, second = (int(x) for x in match.group("time").split(":"))

    ts = build_datetime(reference.year, month, day, hour, minute, second)
    if ts > reference + timedelta(days=1):
        ts = build_datetime(reference.year - 1, month, day, hour, minute, second)
    return ts


def open_log(path):
    """일반 파일과 .gz(로테이션) 파일 모두 지원. 깨진 바이트는 대체 문자로 치환."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def analyze_log(file_path, window_seconds, threshold, exclude_private, reference=None):
    """로그를 분석해 (의심 IP 결과 dict, 카운터) 를 반환한다."""
    if reference is None:
        reference = datetime.fromtimestamp(os.path.getmtime(file_path))

    counters = Counter()
    recent_attempts = defaultdict(deque)   # 윈도우 내 타임스탬프
    stats = {}                             # IP별 누적 통계
    pending_invalid = OrderedDict()        # 중복 제거용 (ip, port)

    with open_log(file_path) as file:
        for line in file:
            counters["total_lines"] += 1

            match = FAILED_PATTERN.match(line)
            is_failed = match is not None
            if match is None:
                match = INVALID_PATTERN.match(line)
            if match is None:
                continue
            counters["matched_lines"] += 1

            address = normalize_ip(match.group("ip"))
            if address is None:
                counters["invalid_ip"] += 1
                continue
            if is_excluded_ip(address, exclude_private):
                counters["excluded_ip"] += 1
                continue

            ip = str(address)
            conn_key = (ip, match.group("port"))

            # "Invalid user" 직후 같은 연결에서 나오는 첫 "Failed ... for invalid user" 는 중복
            if is_failed and match.group("invalid") and conn_key in pending_invalid:
                del pending_invalid[conn_key]
                counters["skipped_duplicate"] += 1
                continue

            try:
                ts = parse_timestamp(match, reference)
            except ValueError:
                counters["bad_timestamp"] += 1
                continue

            if not is_failed:
                pending_invalid[conn_key] = True
                if len(pending_invalid) > MAX_PENDING_INVALID:
                    pending_invalid.popitem(last=False)

            user = match.group("user")

            # --- 슬라이딩 윈도우 갱신 ---
            # DST 전환 등으로 시간이 거꾸로 가면 직전 시각으로 고정해 윈도우가 늘어나는 것을 막는다.
            dq = recent_attempts[ip]
            effective_ts = ts if not dq or ts >= dq[-1] else dq[-1]
            dq.append(effective_ts)
            while (effective_ts - dq[0]).total_seconds() > window_seconds:
                dq.popleft()

            # --- 통계 갱신 ---
            entry = stats.get(ip)
            if entry is None:
                entry = stats[ip] = {
                    "count": 0,
                    "first_seen": ts,
                    "last_seen": ts,
                    "usernames": set(),
                    "usernames_truncated": False,
                    "peak_count": 0,
                    "peak_start": None,
                    "peak_end": None,
                }
            entry["count"] += 1
            if ts < entry["first_seen"]:
                entry["first_seen"] = ts
            if ts > entry["last_seen"]:
                entry["last_seen"] = ts

            if user in entry["usernames"] or len(entry["usernames"]) < MAX_USERNAMES_PER_IP:
                entry["usernames"].add(user)
            else:
                entry["usernames_truncated"] = True

            if len(dq) > entry["peak_count"]:
                entry["peak_count"] = len(dq)
                entry["peak_start"] = dq[0]
                entry["peak_end"] = effective_ts

    # --- 결과 조립: peak 가 임계치 이상인 IP만, peak 큰 순으로 ---
    flagged = [ip for ip, e in stats.items() if e["peak_count"] >= threshold]
    flagged.sort(key=lambda ip: (-stats[ip]["peak_count"], ip))

    result = {}
    for ip in flagged:
        e = stats[ip]
        item = {
            "count": e["count"],
            "first_seen": e["first_seen"].isoformat(),
            "last_seen": e["last_seen"].isoformat(),
            "usernames": sorted(e["usernames"]),
            "peak_window": {
                "attempts": e["peak_count"],
                "start": e["peak_start"].isoformat(),
                "end": e["peak_end"].isoformat(),
            },
        }
        if e["usernames_truncated"]:
            item["usernames_truncated"] = True
        result[ip] = item

    return result, counters


def write_json_atomic(path, data):
    """임시 파일에 쓴 뒤 교체하여, 중간에 실패해도 기존 결과가 깨지지 않게 한다."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="auth.log 브루트포스 의심 IP 탐지")
    parser.add_argument("log_file", nargs="?", default=DEFAULT_LOG_FILE,
                        help=f"분석할 로그 (.gz 가능, 기본: {DEFAULT_LOG_FILE})")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_FILE,
                        help=f"결과 JSON 경로 (기본: {DEFAULT_OUTPUT_FILE})")
    parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_SECONDS,
                        help=f"슬라이딩 윈도우(초) (기본: {DEFAULT_WINDOW_SECONDS})")
    parser.add_argument("-t", "--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"윈도우 내 임계 시도 횟수 (기본: {DEFAULT_THRESHOLD})")
    parser.add_argument("--include-private", action="store_true",
                        help="사설/링크로컬 IP도 분석 대상에 포함")
    parser.add_argument("--reference-date", type=datetime.fromisoformat, default=None,
                        help="syslog 연도 추정 기준 시각 (ISO 형식, 기본: 로그 파일 mtime)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    try:
        result, counters = analyze_log(
            args.log_file,
            window_seconds=args.window,
            threshold=args.threshold,
            exclude_private=not args.include_private,
            reference=args.reference_date,
        )
    except OSError as exc:
        print(f"[오류] 로그 파일을 읽을 수 없습니다: {exc}", file=sys.stderr)
        return 1

    write_json_atomic(args.output, result)

    print(
        f"총 {counters['total_lines']}줄 중 {counters['matched_lines']}줄 매칭 "
        f"(제외 IP {counters['excluded_ip']}, 중복 건너뜀 {counters['skipped_duplicate']}, "
        f"IP 오류 {counters['invalid_ip']}, 시간 파싱 실패 {counters['bad_timestamp']})"
    )
    print(f"{len(result)}개의 의심 IP를 {args.output} 에 저장했습니다.")

    if counters["bad_timestamp"]:
        print("[경고] 일부 라인의 타임스탬프를 해석하지 못했습니다.", file=sys.stderr)
    if counters["total_lines"] > 0 and counters["matched_lines"] == 0:
        print("[경고] 매칭된 라인이 0건입니다. 로그 형식(타임스탬프/프로세스명)을 확인하세요.",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())