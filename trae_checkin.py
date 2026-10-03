# -*- coding: utf-8 -*-
"""
Trae CN / TRAE SOLO CN 每日自动签到脚本
========================================
调用 Trae 官方接口领取每日签到积分（基础 100 + 额外 100 = 每日 200）。

接口（已实测调通）:
    POST https://api.trae.cn/trae/api/v2/ug/checkin_credits/status   查询签到状态
    POST https://api.trae.cn/trae/api/v2/ug/checkin_credits/claim    领取每日签到
鉴权:
    Authorization: Cloud-IDE-JWT <accessToken>
    X-User-Region: CN（可选）
    x-device-id: <device_id>（可选）

Token 来源（按优先级）:
    1. 环境变量 TRAE_ACCESS_TOKEN / TRAE_REFRESH_TOKEN（GitHub Actions 注入 Secrets）
    2. 本地 Trae CN / TRAE SOLO CN 客户端登录态文件（AES 解密）:
       %APPDATA%/Trae CN/User/globalStorage/storage.json
       %APPDATA%/TRAE SOLO CN/User/globalStorage/storage.json
       （token 不进代码仓库）

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
import smtplib
import ssl
import sys
import time
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

# ===== 配置 =====
API_BASE = "https://api.trae.cn/trae/api/v2/ug/checkin_credits"
REQ_SOURCE = 1  # 1=Trae CN IDE

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

# %APPDATA% 下的应用数据目录名（支持多客户端）
APP_DIRS = ["Trae CN", "TRAE SOLO CN", "Trae", "TRAE SOLO"]

BASE_DIR = Path(__file__).parent.resolve()
LOG_FILE = BASE_DIR / "checkin_log.jsonl"
LOG_TEXT_FILE = BASE_DIR / "checkin.log"
# refresh token 缓存文件（云端工作区临时文件，已 gitignore）
REFRESH_TOKEN_FILE = BASE_DIR / ".refresh_token"


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
    """追加一条 JSONL 日志"""
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
    """解密 iCubeAuthInfo 加密串，返回含 token / userRegion / refreshToken 的 dict"""
    t = base64.b64decode(b64_text)
    key = t[HDR_LEN:HDR_LEN + KEY_LEN]
    sha = hashlib.sha512(key).digest()
    xor = bytes(a ^ b for a, b in zip(URE, DRE))
    h = hashlib.sha512(sha + xor).digest()
    aes_key, iv = h[:16], h[16:32]
    ct = t[HDR_LEN + KEY_LEN:]
    plain = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
    return json.loads(plain[HMAC_LEN:].decode("utf-8"))


# ===== 账号加载 =====
def scan_targets():
    """扫描目标 [(名称, storage.json 路径, 应用数据目录)]，按路径去重"""
    appdata = os.environ.get("APPDATA", "")
    targets = []
    for n in APP_DIRS:
        sf = Path(appdata) / n / "User" / "globalStorage" / "storage.json"
        ad = Path(appdata) / n
        targets.append((n, sf, ad))
    seen, uniq = set(), []
    for name, sf, d in targets:
        key = str(sf).lower()
        if key not in seen:
            seen.add(key)
            uniq.append((name, sf, d))
    return uniq


def load_accounts_from_local():
    """从本地客户端 storage.json 读取账号列表"""
    accounts, seen = [], set()
    for name, path, _ in scan_targets():
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
                log(f"跳过 [{name}]：token 为空")
                continue
            if token in seen:
                continue
            seen.add(token)
            accounts.append((name, auth))
            log(f"从本地加载账号: [{name}] (userId={auth.get('userId', '?')})")
        except Exception as e:
            log(f"WARN 解析 [{name}] 失败: {e}")
    return accounts


def load_accounts_from_env():
    """从环境变量加载账号（支持 TRAE_ACCESS_TOKEN / TRAE_REFRESH_TOKEN / TRAE_USER_REGION）"""
    accounts = []
    i = 1
    while True:
        suffix = "" if i == 1 else f"_{i}"
        tok = os.environ.get(f"TRAE_ACCESS_TOKEN{suffix}", "").strip()
        if not tok and i > 1:
            break  # 连续缺失则停止
        if not tok:
            # 账号1 没有 env token，继续检查账号2+
            if i == 1:
                i += 1
                continue
            break
        region = os.environ.get(f"TRAE_USER_REGION{suffix}", "").strip() or "CN"
        auth = {
            "token": tok,
            "refreshToken": os.environ.get(f"TRAE_REFRESH_TOKEN{suffix}", "").strip(),
            "userRegion": {"region": region},
            "userId": os.environ.get(f"TRAE_USER_ID{suffix}", "").strip(),
        }
        label = f"账号{suffix.lstrip('_')}"
        accounts.append((label, auth))
        log(f"从环境变量加载账号: [{label}]")
        i += 1
    return accounts


def load_all_accounts():
    """合并本地 + 环境变量账号，按 token 去重"""
    all_accounts, seen = [], set()
    for label, auth in load_accounts_from_env() + load_accounts_from_local():
        tok = auth.get("token", "")
        if not tok or tok in seen:
            continue
        seen.add(tok)
        all_accounts.append((label, auth))
    return all_accounts


# ===== API 调用 =====
def api_call(url, token, region="", device_id=""):
    """调用 Trae API"""
    headers = {
        "Authorization": f"Cloud-IDE-JWT {token}",
        "Content-Type": "application/json",
        "x-device-id": device_id,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TraeCheckin/1.0",
    }
    if region:
        headers["X-User-Region"] = region
    resp = requests.post(url, headers=headers, json={"req_source": REQ_SOURCE}, timeout=30)
    try:
        body = resp.json()
    except Exception:
        body = {"code": resp.status_code, "message": resp.text[:300]}
    return resp.status_code, body


def unwrap_resp(body):
    """兼容 {checked_in:...} 与 {code:0, data:{checked_in:...}} 两种返回格式"""
    if ("checked_in" not in body and isinstance(body.get("data"), dict)
            and "checked_in" in body["data"]):
        return body["data"]
    return body


# ===== 邮件通知 =====
def send_email(subject, body, account_label=None):
    """通过 SMTP 发送邮件（失败不抛异常）"""
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
        with smtplib.SMTP_SSL(host, port, timeout=30, context=context) as server:
            server.login(user, password)
            server.sendmail(user, [to], msg.as_string())
        log(f"OK 已发送邮件到 {to}: {subject}")
        return True
    except Exception as e:
        log(f"ERROR 邮件发送失败: {e}")
        return False


# ===== 签到主流程 =====
def process_account(args, label, auth):
    """对单个账号执行签到主流程。返回 0=成功/正常，非0=失败。"""
    token = auth["token"]
    region = (auth.get("userRegion") or {}).get("region", "")
    log(f"===== [{label}] 开始签到 =====")

    # 1. 查询签到状态
    try:
        code, body = api_call(f"{API_BASE}/status", token, region)
        log(f"[{label}] status -> HTTP {code}, body={json.dumps(body, ensure_ascii=False)[:200]}")
        if code != 200 or (body.get("code") != 0 and body.get("message") != "success"):
            log(f"ERROR [{label}] 查询状态失败")
            append_log({"event": "status_fail", "ok": False, "http": code, "resp": body}, account=label)
            send_email("⚠️ Trae 签到：查询状态异常",
                       f"[{label}]\n查询签到状态失败\nHTTP {code}\n响应: {json.dumps(body, ensure_ascii=False)[:500]}\n时间: {datetime.datetime.now()}",
                       account_label=label)
            return 1
        data = unwrap_resp(body)
    except Exception as e:
        log(f"ERROR [{label}] 查询状态异常: {e}")
        append_log({"event": "status_error", "ok": False, "msg": str(e)}, account=label)
        return 1

    summary = {
        "checked_in": data.get("checked_in", False),
        "enable": data.get("enable", False),
        "credits": data.get("credits", 0),
        "extra_credits": data.get("extra_credits", 0),
        "did_checked_in": data.get("did_checked_in", False),
        "message": data.get("message", ""),
    }
    log(f"[{label}] 状态摘要: {json.dumps(summary, ensure_ascii=False)}")

    if args.check_only:
        log(f"[{label}] --check-only 模式，不领取")
        append_log({"event": "check_only", "ok": True, "summary": summary}, account=label)
        return 0

    if data.get("checked_in"):
        credits = data.get("credits", 0)
        extra = data.get("extra_credits", 0)
        log(f"✅ [{label}] 今日已签到（基础 {credits} + 额外 {extra} = {credits + extra} 积分）")
        append_log({"event": "already", "ok": True, "summary": summary}, account=label)
        return 0

    if not data.get("enable"):
        log(f"INFO [{label}] 签到活动未启用，跳过")
        append_log({"event": "disabled", "ok": True, "summary": summary}, account=label)
        send_email("ℹ️ Trae 签到：今日不可用",
                   f"[{label}]\n签到活动未启用。\n\n状态:\n{json.dumps(summary, ensure_ascii=False, indent=2)}\n\n时间: {datetime.datetime.now()}",
                   account_label=label)
        return 0

    # 2. 执行签到
    log(f"[{label}] 正在领取每日签到...")
    try:
        code, claim = api_call(f"{API_BASE}/claim", token, region)
        log(f"[{label}] claim -> HTTP {code}, body={json.dumps(claim, ensure_ascii=False)[:200]}")
        if code == 200 and (claim.get("code") == 0 or claim.get("message") == "success"):
            # 再查一次状态确认
            try:
                _, after = api_call(f"{API_BASE}/status", token, region)
                after_data = unwrap_resp(after)
                credits = after_data.get("credits", 0)
                extra = after_data.get("extra_credits", 0)
                log(f"✅ [{label}] 签到成功！获得积分：基础 {credits} + 额外 {extra} = {credits + extra}")
            except Exception:
                log(f"✅ [{label}] 签到成功！")
            append_log({"event": "success", "ok": True, "claim": claim}, account=label)
            return 0
        else:
            msg = claim.get("message") or json.dumps(claim, ensure_ascii=False)[:200]
            log(f"INFO [{label}] 领取未成功: {msg}")
            append_log({"event": "claim_skip", "ok": True, "claim": claim}, account=label)
            send_email("⚠️ Trae 签到：领取未成功",
                       f"[{label}]\n领取每日签到未成功：{msg}\n\n时间: {datetime.datetime.now()}",
                       account_label=label)
            return 0
    except Exception as e:
        log(f"ERROR [{label}] 领取异常: {e}")
        append_log({"event": "claim_error", "ok": False, "msg": str(e)}, account=label)
        send_email("⚠️ Trae 签到失败",
                   f"[{label}]\n领取每日签到时发生异常：{e}\n时间: {datetime.datetime.now()}",
                   account_label=label)
        return 1


def main():
    parser = argparse.ArgumentParser(description="Trae CN / TRAE SOLO CN 每日自动签到")
    parser.add_argument("--check-only", action="store_true", help="只查询签到状态，不领取")
    args = parser.parse_args()

    log("=" * 50)
    log("Trae CN / TRAE SOLO CN 每日自动签到")
    log("=" * 50)

    accounts = load_all_accounts()
    if not accounts:
        log("ERROR 没有可用登录态")
        log("请先在 Trae CN 客户端登录，或设置环境变量 TRAE_ACCESS_TOKEN")
        append_log({"event": "no_token", "ok": False})
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
