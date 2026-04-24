import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re
import time
import json
import base64
import requests
import urllib3
import ddddocr
from io import BytesIO
from urllib.parse import urlparse
from collections import Counter
from PIL import Image, ImageFilter, ImageEnhance
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CF_DNS_NAME = os.getenv("CLOUDFLARE_DNS_NAME", "us")
CF_DOMAIN = os.getenv("CLOUDFLARE_DOMAIN")

FOFA_EMAIL = os.getenv("FOFA_EMAIL")
FOFA_PASSWORD = os.getenv("FOFA_PASSWORD")

FOFA_QUERY = 'server=="cloudflare" && header="Forbidden" && asn=="31898" && country=="US"'
PROXY_CHECK_URL = "https://check.proxyip.cmliussss.net"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
ABUSE_THRESHOLD = 20

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0"
LOGIN_PAGE = "https://i.nosec.org/login?locale=zh-CN&service=https://fofa.info/f_login"


# ========== 验证码识别 ==========
def preprocess_captcha(image_bytes):
    img = Image.open(BytesIO(image_bytes))
    candidates = []

    buf = BytesIO()
    img.save(buf, format="PNG")
    candidates.append(buf.getvalue())

    gray = img.convert("L")
    enhanced = ImageEnhance.Contrast(gray).enhance(2.0)
    bw = enhanced.point(lambda x: 255 if x > 128 else 0, "1")
    buf = BytesIO()
    bw.save(buf, format="PNG")
    candidates.append(buf.getvalue())

    sharp = gray.filter(ImageFilter.SHARPEN)
    bw2 = sharp.point(lambda x: 255 if x > 100 else 0, "1")
    buf = BytesIO()
    bw2.save(buf, format="PNG")
    candidates.append(buf.getvalue())

    big = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)
    big_gray = big.convert("L")
    big_enhanced = ImageEnhance.Contrast(big_gray).enhance(2.5)
    big_bw = big_enhanced.point(lambda x: 255 if x > 120 else 0, "1")
    buf = BytesIO()
    big_bw.save(buf, format="PNG")
    candidates.append(buf.getvalue())

    median = gray.filter(ImageFilter.MedianFilter(3))
    med_bw = median.point(lambda x: 255 if x > 130 else 0, "1")
    buf = BytesIO()
    med_bw.save(buf, format="PNG")
    candidates.append(buf.getvalue())

    return candidates


def ocr_captcha(image_bytes):
    ocr = ddddocr.DdddOcr(show_ad=False)
    candidates = preprocess_captcha(image_bytes)

    results = []
    for img_data in candidates:
        try:
            text = ocr.classification(img_data)
            clean = re.sub(r'[^a-zA-Z]', '', text).lower()
            if 4 <= len(clean) <= 6:
                results.append(clean[:5])
        except:
            continue

    if not results:
        return ""

    counter = Counter(results)
    best = counter.most_common(1)[0][0]
    print(f"    OCR 候选: {results} -> 选择: {best}")
    return best


# ========== FOFA 自动登录 ==========
def fofa_login():
    session = requests.Session()
    session.headers.update({
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "DNT": "1",
    })

    for attempt in range(10):
        print(f"登录尝试 {attempt + 1}/10 ...")

        cookies_dict = {c.name: c.value for c in session.cookies}
        if "tgt" in cookies_dict or "fofa_token" in cookies_dict:
            try:
                test = session.get("https://fofa.info/", timeout=15)
                if test.status_code == 200:
                    print("  ✅ 已登录（session 有效）")
                    return session
            except:
                pass

        try:
            login_page = session.get(LOGIN_PAGE, timeout=30, allow_redirects=True)
            login_page.raise_for_status()
            final_url = login_page.url
            print(f"  登录页: {final_url} ({login_page.status_code})")
        except Exception as e:
            print(f"  访问登录页失败: {e}")
            time.sleep(3)
            continue

        if "fofa.info" in final_url and "ticket=" in final_url:
            print("  ✅ SSO 已登录，回调完成")
            return session

        if "fofa.info" in final_url and "i.nosec.org" not in final_url:
            print("  ✅ 已登录（跳转到 FOFA）")
            return session

        soup = BeautifulSoup(login_page.text, "html.parser")

        form = soup.find("form", {"id": "login-form"})
        if not form:
            form = soup.find("form")
        if not form:
            print("  没有登录表单，尝试直接访问 FOFA...")
            try:
                test = session.get("https://fofa.info/", timeout=15)
                if test.status_code == 200:
                    print("  ✅ 已登录")
                    return session
            except:
                pass
            time.sleep(3)
            continue

        hidden_fields = {}
        for inp in form.find_all("input", {"type": "hidden"}):
            name = inp.get("name")
            value = inp.get("value", "")
            if name:
                hidden_fields[name] = value

        parsed = urlparse(login_page.url)
        action = form.get("action", "/login")
        if action.startswith("/"):
            action_url = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif action.startswith("http"):
            action_url = action
        else:
            action_url = f"{parsed.scheme}://{parsed.netloc}/login"

        captcha_base = f"{parsed.scheme}://{parsed.netloc}"
        try:
            captcha_resp = session.get(
                f"{captcha_base}/rucaptcha/?t={int(time.time() * 1000)}",
                timeout=15
            )
            captcha_resp.raise_for_status()
        except Exception as e:
            print(f"  下载验证码失败: {e}")
            time.sleep(2)
            continue

        captcha_text = ocr_captcha(captcha_resp.content)
        print(f"  验证码: {captcha_text}")

        if len(captcha_text) < 4:
            time.sleep(1)
            continue

        login_data = {}
        login_data.update(hidden_fields)
        login_data.update({
            "username": FOFA_EMAIL,
            "password": FOFA_PASSWORD,
            "_rucaptcha": captcha_text,
            "rememberMe": "1",
            "fofa_service": "1",
        })

        session.headers.update({
            "Referer": login_page.url,
            "Origin": f"{parsed.scheme}://{parsed.netloc}",
        })

        try:
            resp = session.post(action_url, data=login_data, timeout=30, allow_redirects=True)
        except Exception as e:
            print(f"  提交失败: {e}")
            time.sleep(3)
            continue

        cookies_dict = {c.name: c.value for c in session.cookies}
        print(f"  状态: {resp.status_code}, URL: {resp.url}")
        print(f"  Cookies: {list(cookies_dict.keys())}")

        if "fofa_token" in cookies_dict:
            print("  ✅ 登录成功")
            return session

        if "tgt" in cookies_dict:
            print("  ✅ 登录成功（SSO tgt）")
            return session

        if "fofa.info" in resp.url and "ticket=" in resp.url:
            print("  ✅ 登录成功（SSO 回调）")
            return session

        if "fofa.info" in resp.url and "/login" not in resp.url.split("?")[0].replace("f_login", ""):
            print("  ✅ 登录成功（跳转 FOFA）")
            return session

        if "退出" in resp.text or "个人中心" in resp.text:
            print("  ✅ 登录成功")
            return session

        if "验证码" in resp.text:
            print("  ❌ 验证码错误")
        elif resp.status_code == 403:
            print("  ❌ 403")
        else:
            print("  ❌ 登录失败")

        time.sleep(1)

    print("10 次登录均失败")
    return None


# ========== 获取 FOFA JWT ==========
def get_fofa_jwt(session):
    """登录成功后，从 fofa.info 获取 JWT token"""
    print("获取 FOFA JWT...")

    # 方法1: 从 cookie 中获取
    for cookie in session.cookies:
        if cookie.name == "fofa_token":
            print(f"  从 cookie 获取 JWT")
            return cookie.value

    # 方法2: 访问用户信息页面提取
    try:
        resp = session.get("https://fofa.info/userInfo", timeout=15)
        # 尝试从页面中提取 token
        match = re.search(r'"token"\s*:\s*"(eyJ[^"]+)"', resp.text)
        if match:
            print(f"  从 userInfo 页面提取 JWT")
            return match.group(1)
    except:
        pass

    # 方法3: 尝试 API 登录接口
    try:
        resp = session.get("https://fofa.info/api/users/info", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token") or data.get("fofa_token")
            if token:
                print(f"  从 API 获取 JWT")
                return token
    except:
        pass

    # 方法4: 访问首页，从 JS 变量或 meta 中提取
    try:
        resp = session.get("https://fofa.info/", timeout=15)
        # 找 window.__INITIAL_STATE__ 或类似的
        for pattern in [
            r'fofa_token["\s:=]+["\']?(eyJ[^"\';\s]+)',
            r'authorization["\s:=]+["\']?(eyJ[^"\';\s]+)',
            r'token["\s:=]+["\']?(eyJ[^"\';\s]+)',
        ]:
            match = re.search(pattern, resp.text)
            if match:
                print(f"  从首页提取 JWT")
                return match.group(1)
    except:
        pass

    print("  ⚠️ 无法获取 JWT")
    return None


# ========== FOFA 搜索 ==========
def fofa_search():
    session = fofa_login()
    if session is None:
        return []

    # 获取 JWT
    jwt = get_fofa_jwt(session)

    # 先打印调试信息
    print(f"JWT: {'有' if jwt else '无'}")
    all_cookies = {c.name: c.value[:30] + "..." if len(c.value) > 30 else c.value
                   for c in session.cookies}
    print(f"所有 Cookies: {all_cookies}")

    # 尝试访问 result 页面看返回什么
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    url = f"https://fofa.info/result?qbase64={qbase64}"
    print(f"请求 FOFA: {url}")

    try:
        resp = session.get(url, timeout=60)
        resp.raise_for_status()
        print(f"  页面长度: {len(resp.text)}")
        print(f"  前500字符: {resp.text[:500]}")
    except Exception as e:
        print(f"请求失败: {e}")
        return []

    # 尝试从页面解析 IP（SSR 情况）
    soup = BeautifulSoup(resp.text, "html.parser")
    ips = []
    ip_divs = soup.find_all("div", class_="hsxa-ip")
    for div in ip_divs:
        a_tags = div.find_all("a", class_="hsxa-jump-a")
        for a in a_tags:
            if a.get("style") and "display:none" in a.get("style", ""):
                continue
            ip_text = a.get_text(strip=True)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_text):
                ips.append(ip_text)
                break

    if ips:
        ips = list(dict.fromkeys(ips))
        print(f"从页面提取到 {len(ips)} 个IP")
        return ips

    # 页面是 SPA，需要调 API
    print("页面无数据（SPA），尝试调用内部 API...")

    if not jwt:
        print("⚠️ 没有 JWT，无法调用 API")
        return []

    # 调用 api.fofa.info 搜索
    api_headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "authorization": jwt,
        "Origin": "https://fofa.info",
        "Referer": "https://fofa.info/",
    }

    ts = str(int(time.time() * 1000))
    api_url = "https://api.fofa.info/v1/search/all"
    params = {
        "qbase64": qbase64,
        "page": "1",
        "size": "100",
        "fields": "ip",
        "ts": ts,
        "lang": "zh-CN",
    }

    try:
        resp = session.get(api_url, headers=api_headers, params=params, timeout=30)
        print(f"  API 状态: {resp.status_code}")
        print(f"  API 响应: {resp.text[:500]}")

        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            for row in results:
                ip = row[0] if isinstance(row, list) else row
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
                    ips.append(ip)
    except Exception as e:
        print(f"  API 调用失败: {e}")

    ips = list(dict.fromkeys(ips))
    print(f"提取到 {len(ips)} 个去重IP")
    return ips


# ========== CF 反代指纹探测 ==========
def check_cf_proxy(ip):
    try:
        resp = requests.get(f"https://{ip}/cdn-cgi/trace", verify=False, timeout=5)
        if "cloudflare" in resp.text.lower():
            return True
    except:
        pass
    for scheme in ["http", "https"]:
        try:
            resp = requests.head(f"{scheme}://{ip}", verify=False, timeout=5)
            if "cloudflare" in resp.headers.get("Server", "").lower():
                return True
        except:
            continue
    return False


# ========== AbuseIPDB 检测 ==========
def abuseipdb_check(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()["data"]["abuseConfidenceScore"]


# ========== Cloudflare DNS ==========
def get_dns_records():
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    resp = requests.get(CF_DNS_RECORDS_URL, headers=headers, params={"type": "A", "name": fqdn}, timeout=15)
    resp.raise_for_status()
    return resp.json().get("result", [])


def create_dns_record(ip):
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    for r in get_dns_records():
        if r["content"] == ip:
            print(f"IP {ip} 已存在，跳过")
            return
    data = {"type": "A", "name": fqdn, "content": ip, "ttl": 1, "proxied": False}
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data, timeout=15)
    resp.raise_for_status()
    print(f"已添加 DNS: {fqdn} -> {ip}")


def delete_dns_record(record_id, ip):
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    resp = requests.delete(f"{CF_DNS_RECORDS_URL}/{record_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    print(f"已删除 DNS 记录: {ip}")


# ========== ProxyIP 检测 ==========
def check_proxy_ips():
    print(f"\n===== 第五步：检测 ProxyIP =====")
    print("等待 30 秒让 DNS 生效...")
    time.sleep(30)
    records = get_dns_records()
    if not records:
        print("没有 DNS 记录需要检测")
        return {}
    all_ips = [r["content"] for r in records]
    print(f"当前 DNS 中的 IP: {all_ips}")
    ip_status = {}
    for ip in all_ips:
        try:
            resp = requests.get(f"{PROXY_CHECK_URL}/check?proxyip={ip}:443", timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data.get("success", False):
                ip_status[ip] = "valid"
                print(f"  ✅ {ip} 有效")
            else:
                ip_status[ip] = "invalid"
                print(f"  ❌ {ip} 无效")
        except Exception as e:
            ip_status[ip] = "invalid"
            print(f"  ❌ {ip} 出错: {e}")
        time.sleep(1)
    return ip_status


# ========== 清理失败 IP ==========
def cleanup_failed_ips(ip_status):
    print(f"\n===== 第六步：清理失败 IP =====")
    failed_ips = [ip for ip, s in ip_status.items() if s == "invalid"]
    if not failed_ips:
        print("所有 IP 正常")
        return
    records = get_dns_records()
    for r in records:
        if r["content"] in failed_ips:
            try:
                delete_dns_record(r["id"], r["content"])
            except Exception as e:
                print(f"❌ 删除失败 {r['content']}: {e}")


# ========== 主流程 ==========
def main():
    print("===== 第一步：从 FOFA 搜索 IP =====")
    ips = fofa_search()
    print(f"找到 {len(ips)} 个IP: {ips}")
    if not ips:
        return

    print("\n===== 第二步：探测 CF 反代特征 =====")
    cf
