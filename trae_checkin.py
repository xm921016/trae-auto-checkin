# -*- coding: utf-8 -*-
"""
Trae CN / TRAE SOLO CN 每日自动签到脚本
========================================
调用 Trae 官方接口领取每日签到积分（基础 100 + 额外 100 = 每日 200）。

接口:
    POST {host}/trae/api/v2/ug/checkin_credits/status   查询签到状态
    POST {host}/trae/api/v2/ug/checkin_credits/claim    领取每日签到

Token 来源（按优先级）:
    1. 环境变量 TRAE_ACCESS_TOKEN / TRAE_REFRESH_TOKEN（GitHub Actions Secrets）
    2. 本地 Trae CN / TRAE SOLO CN 客户端登录态文件（AES 解密）

运行:
    python trae_checkin.py
    python trae_checkin.py --check-only   # 只查询不领取
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import random
import smtplib
import ssl
import string
import sys
import time
import uuid
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path

try:
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("缺少依赖，请先: pip install requests pycryptodome")
    sys.exit(1)

# ===== 常量 =====
# iCube 登录态解密常量（与 Trae 客户端加密格式对应）
HDR_LEN = 6
KEY_LEN = 32
HMAC_LEN = 64
URE = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
             124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
             84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
             8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37])
DRE = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
             96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
             160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
             23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])

APP_DIRS = ["Trae CN", "TRAE SOLO CN", "Trae", "TRAE SOLO"]

DEFAULT_HOST = "https://api.trae.cn"
DEFAULT_APP_ID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
REFRESH_CLIENT_ID = "ono9krqynydwx5"

BASE_DIR = Path(__file__).parent.resolve()
LOG_FILE = BASE_DIR / "checkin_log.jsonl"
LOG_TEXT_FILE = BASE_DIR / "checkin.log"


# ===== 日志 =====
def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_TEXT_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def append_log(record, account=None):
    try:
        record["ts"] = datetime.datetime.now().isoformat()
        if account:
            record["account"] = account
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        log(f"WARN 写日志失败: {e}")


# ===== 解密 =====
def decrypt_auth(b64_text):
    """解密 iCubeAuthInfo 加密串"""
    t = base64.b64decode(b64_text)
    key = t[HDR_LEN:HDR_LEN + KEY_LEN]
    sha = hashlib.sha512(key).digest()
    xor = bytes(a ^ b for a, b in zip(URE, DRE))
    h = hashlib.sha512(sha + xor).digest()
    aes_key, iv = h[:16], h[16:32]
    ct = t[HDR_LEN + KEY_LEN:]
    plain = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
    # plain = stored_hash(64) + payload
    return json.loads(plain[HMAC_LEN:].decode("utf-8"))


# ===== 设备指纹 =====
def detect_os():
    import platform
    system = platform.system().lower()
    release = platform.release()
    if system == "darwin":
        return "mac", f"Darwin {release}"
    elif system == "windows":
        return "windows", f"Windows {release}"
    elif system == "linux":
        return "linux", f"Linux {release}"
    return "unknown", system


def read_device_fingerprint(storage):
    """从 storage.json 读取 machineId / deviceId / ideVersion"""
    fp = {}
    machine_id = storage.get("telemetry.machineId", "")
    if machine_id:
        fp["machineId"] = machine_id
    for k in storage.keys():
        import re
        m = re.match(r"^iCubeAuthInfo:\/\/icube-dc:(\d+)$", k)
        if m:
            fp["deviceId"] = m.group(1)
            break
    ver = storage.get("iCubeLastVersion", "")
    if isinstance(ver, str) and ver.strip():
        fp["ideVersion"] = ver.strip()
        fp["ideVersionCode"] = ver.strip().replace(".", "")
    return fp


# ===== 账号加载 =====
def scan_targets():
    appdata = os.environ.get("APPDATA", "")
    targets = []
    for n in APP_DIRS:
        sf = Path(appdata) / n / "User" / "globalStorage" / "storage.json"
        targets.append((n, sf))
    return targets


def load_accounts_from_local():
    accounts, seen = [], set()
    for name, path in scan_targets():
        try:
            if not path.exists():
                continue
            storage = json.loads(path.read_text(encoding="utf-8"))
            enc = storage.get("iCubeAuthInfo://icube.cloudide")
            if not enc:
                continue
            auth = decrypt_auth(enc)
            token = auth.get("token")
            if not token:
                continue
            if token in seen:
                continue
            seen.add(token)
            # 附加设备指纹
            fp = read_device_fingerprint(storage)
            auth["_fingerprint"] = fp
            auth["_host"] = auth.get("host") or DEFAULT_HOST
            accounts.append((name, auth))
            log(f"从本地加载账号: [{name}] (userId={auth.get('userId', '?')})")
        except Exception as e:
            log(f"WARN 解析 [{name}] 失败: {e}")
    return accounts


def load_accounts_from_env():
    accounts = []
    i = 1
    while True:
        suffix = "" if i == 1 else f"_{i}"
        tok = os.environ.get(f"TRAE_ACCESS_TOKEN{suffix}", "").strip()
        if not tok and i > 1:
            break
        if not tok:
            if i == 1:
                i += 1
                continue
            break
        auth = {
            "token": tok,
            "refreshToken": os.environ.get(f"TRAE_REFRESH_TOKEN{suffix}", "").strip(),
            "userId": os.environ.get(f"TRAE_USER_ID{suffix}", "").strip(),
            "userRegion": {"region": os.environ.get(f"TRAE_USER_REGION{suffix}", "").strip() or "CN"},
            "_host": os.environ.get(f"TRAE_API_HOST{suffix}", "").strip() or DEFAULT_HOST,
            "_fingerprint": {
                "deviceId": os.environ.get(f"TRAE_DEVICE_ID{suffix}", "").strip() or None,
                "machineId": os.environ.get(f"TRAE_MACHINE_ID{suffix}", "").strip() or None,
                "ideVersion": os.environ.get(f"TRAE_IDE_VERSION{suffix}", "").strip() or None,
                "ideVersionCode": os.environ.get(f"TRAE_IDE_VERSION_CODE{suffix}", "").strip() or None,
            },
        }
        label = f"账号{suffix.lstrip('_')}"
        accounts.append((label, auth))
        log(f"从环境变量加载账号: [{label}]")
        i += 1
    return accounts


def load_all_accounts():
    all_accounts, seen = [], set()
    for label, auth in load_accounts_from_env() + load_accounts_from_local():
        tok = auth.get("token", "")
        if not tok or tok in seen:
            continue
        seen.add(tok)
        all_accounts.append((label, auth))
    return all_accounts


# ===== Token 自动刷新 =====
def refresh_token(auth):
    """用 refreshToken 换新 accessToken。成功则更新 auth dict 并返回 True"""
    refresh_tok = auth.get("refreshToken")
    uid = auth.get("userId")
    if not refresh_tok or not uid:
        return False
    host = auth.get("_host", DEFAULT_HOST)
    try:
        r = requests.post(
            f"{host}/cloudide/api/v3/trae/oauth/ExchangeToken",
            headers={"Content-Type": "application/json"},
            json={
                "ClientID": REFRESH_CLIENT_ID,
                "RefreshToken": refresh_tok,
                "ClientSecret": "-",
                "UserID": str(uid),
            },
            timeout=15,
        )
        j = r.json()
        result = (j.get("Result") or {})
        new_tok = result.get("Token")
        if new_tok:
            auth["token"] = new_tok
            return True
    except Exception as e:
        log(f"WARN token 刷新失败: {e}")
    return False


# ===== Headers & API =====
def build_headers(auth):
    """构造完整请求 headers（与 Trae 客户端一致）"""
    token = auth["token"]
    uid = str(auth.get("userId", ""))
    fp = auth.get("_fingerprint") or {}
    device_type, os_version = detect_os()

    # 生成稳定的 device-id（无则随机）
    dev_id = fp.get("deviceId") or hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32]
    machine_id = fp.get("machineId") or hashlib.sha256(uuid.uuid4().bytes).hexdigest()

    headers = {
        "Authorization": f"Cloud-IDE-JWT {token}",
        "X-Cloudide-Token": token,
        "x-uid": uid,
        "x-app-id": DEFAULT_APP_ID,
        "x-device-id": dev_id,
        "x-machine-id": machine_id,
        "x-request-id": str(uuid.uuid4()),
        "x-ide-version": fp.get("ideVersion") or "3.5.0",
        "x-ide-version-code": fp.get("ideVersionCode") or "20260101",
        "x-device-type": device_type,
        "x-os-version": os_version,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "TraeCheckin/1.0",
    }
    return headers


def checkin_api(auth, path):
    """发请求到 checkin_credits 接口。成功返回 (status_code, json_body)"""
    host = auth.get("_host", DEFAULT_HOST)
    url = f"{host}/trae/api/v2/ug/checkin_credits/{path}"
    headers = build_headers(auth)
    # status: 空 body {} 即可; claim 也是空 body！（和 Trae 客户端一致）
    body = {}
    resp = requests.post(url, headers=headers, json=body, timeout=30)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"message": resp.text[:300]}


# ===== 邮件 =====
def send_email(subject, body, account_label=None):
    if account_label:
        subject = f"[{account_label}] {subject}"
    host = os.environ.get("SMTP_HOST", "")
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASS", "")
    to = os.environ.get("MAIL_TO", "")
    if not (host and user and password and to):
        log("WARN 邮件配置不完整，跳过发送")
        return False
    port_str = os.environ.get("SMTP_PORT", "")
    try:
        port = int(port_str) if port_str else 465
    except ValueError:
        port = 465
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = formataddr((str(Header("Trae签到", "utf-8")), user))
        msg["To"] = to
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, timeout=30, context=context) as s:
            s.login(user, password)
            s.sendmail(user, [to], msg.as_string())
        log(f"OK 已发送邮件到 {to}")
        return True
    except Exception as e:
        log(f"ERROR 邮件发送失败: {e}")
        return False


# ===== 签到主流程 =====
def process_account(args, label, auth):
    log(f"===== [{label}] 开始签到 =====")

    # Token 临期自动刷新
    try:
        expired_at = int(auth.get("expiredAt") or 0)
    except (ValueError, TypeError):
        expired_at = 0
    if expired_at and expired_at / 1000 < time.time() + 30 * 60:
        log(f"[{label}] token 即将过期，尝试刷新...")
        if refresh_token(auth):
            log(f"  token 刷新成功 ✅")

    # 1. 查询状态
    try:
        code, body = checkin_api(auth, "status")
        log(f"[{label}] status -> HTTP {code}")
        log(f"  {json.dumps(body, ensure_ascii=False)[:200]}")
        if code == 401:
            # token 过期，尝试刷新后重试
            log(f"[{label}] 收到 401，刷新 token 后重试...")
            if refresh_token(auth):
                code, body = checkin_api(auth, "status")
                log(f"  重试后 HTTP {code}")
        if code != 200 or body.get("code") not in (0, None):
            log(f"ERROR [{label}] 查询状态失败")
            append_log({"event": "status_fail", "ok": False, "http": code, "resp": body}, account=label)
            send_email("⚠️ Trae 签到：查询状态异常",
                       f"[{label}]\nHTTP {code}\n响应: {json.dumps(body, ensure_ascii=False)[:500]}\n时间: {datetime.datetime.now()}",
                       account_label=label)
            return 1
    except Exception as e:
        log(f"ERROR [{label}] 查询状态异常: {e}")
        append_log({"event": "status_error", "ok": False, "msg": str(e)}, account=label)
        return 1

    summary = {
        "checked_in": body.get("checked_in", False),
        "enable": body.get("enable", False),
        "credits": body.get("credits", 0),
        "extra_credits": body.get("extra_credits", 0),
        "did_checked_in": body.get("did_checked_in", False),
    }
    log(f"[{label}] 状态摘要: {json.dumps(summary, ensure_ascii=False)}")

    if args.check_only:
        append_log({"event": "check_only", "ok": True, "summary": summary}, account=label)
        return 0

    if body.get("checked_in"):
        credits = body.get("credits", 0)
        extra = body.get("extra_credits", 0)
        log(f"✅ [{label}] 今日已签到（基础 {credits} + 额外 {extra} = {credits + extra} 积分）")
        append_log({"event": "already", "ok": True, "summary": summary}, account=label)
        return 0

    if not body.get("enable"):
        log(f"INFO [{label}] 签到活动未启用，跳过")
        append_log({"event": "disabled", "ok": True, "summary": summary}, account=label)
        return 0

    # 2. 领取
    log(f"[{label}] 正在领取每日签到...")
    try:
        code, claim = checkin_api(auth, "claim")
        log(f"[{label}] claim -> HTTP {code}")
        log(f"  {json.dumps(claim, ensure_ascii=False)[:200]}")
        if code == 200 and claim.get("code") in (0, None):
            # 再查一次确认
            _, after = checkin_api(auth, "status")
            c = after.get("credits", 0)
            e = after.get("extra_credits", 0)
            log(f"✅ [{label}] 签到成功！基础 {c} + 额外 {e} = {c + e}")
            append_log({"event": "success", "ok": True, "credits": c + e}, account=label)
            return 0
        else:
            msg = claim.get("message") or json.dumps(claim, ensure_ascii=False)[:200]
            log(f"WARN [{label}] 领取未成功: code={claim.get('code')}, msg={msg}")
            append_log({"event": "claim_fail", "ok": False, "resp": claim}, account=label)
            send_email("⚠️ Trae 签到：领取失败",
                       f"[{label}]\ncode={claim.get('code')}\nmessage={msg}\n\n时间: {datetime.datetime.now()}",
                       account_label=label)
            return 1
    except Exception as e:
        log(f"ERROR [{label}] 领取异常: {e}")
        append_log({"event": "claim_error", "ok": False, "msg": str(e)}, account=label)
        return 1


def main():
    parser = argparse.ArgumentParser(description="Trae CN / TRAE SOLO CN 每日自动签到")
    parser.add_argument("--check-only", action="store_true", help="只查询不领取")
    args = parser.parse_args()

    log("=" * 50)
    log("Trae CN / TRAE SOLO CN 每日自动签到")
    log("=" * 50)

    accounts = load_all_accounts()
    if not accounts:
        log("ERROR 没有可用登录态")
        log("请先在 Trae CN 客户端登录，或设置环境变量 TRAE_ACCESS_TOKEN")
        sys.exit(1)

    log(f"共 {len(accounts)} 个账号: " + ", ".join(l for l, _ in accounts))

    fail = 0
    for label, auth in accounts:
        rc = process_account(args, label, auth)
        log(f"===== [{label}] 结束 (rc={rc}) =====")
        fail += 1 if rc != 0 else 0

    if fail:
        log(f"ERROR {fail} 个账号签到失败")
        sys.exit(1)
    log("全部完成 ✅")
    sys.exit(0)


if __name__ == "__main__":
    main()
