import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re
import time
import json
import base64
import requests
import urllib3
import urllib.parse
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


# ========== FOFA Session 补全 ==========
def _ensure_fofa_session(session):
    cookies_dict = {c.name: c.value for c in session.cookies}
    if "fofa_token" in cookies_dict:
        return

    print("  补全 FOFA session...")

    try:
        resp = session.get("https://fofa.info/", timeout=15, allow_redirects=True)
        cookies_dict = {c.name: c.value for c in session.cookies}
        print(f"  首页 Cookies: {list(cookies_dict.keys())}")

        if "fofa_token" in cookies_dict:
            print("  fofa_token 已获取")
            return

        # 从 user cookie 提取 API key
        if "user" in cookies_dict:
            user_data = urllib.parse.unquote(cookies_dict["user"])
            try:
                user_json = json.loads(user_data)
                if "key" in user_json:
                    session._fofa_email = user_json.get("email", FOFA_EMAIL)
                    session._fofa_key = user_json["key"]
                    print(f"  从 user cookie 提取 API key")
                    return
            except:
                pass

        # 从页面提取
        for pattern in [
            r'fofa_token["\s:=]+["\']?(eyJ[^"\';\s,]+)',
            r'"token"\s*:\s*"(eyJ[^"]+)"',
            r'"key"\s*:\s*"([a-f0-9]{32})"',
        ]:
            match = re.search(pattern, resp.text)
            if match:
                val = match.group(1)
                if val.startswith("eyJ"):
                    session.cookies.set("fofa_token", val, domain=".fofa.info")
                    print("  从页面提取 fofa_token")
                else:
                    session._fofa_key = val
                    session._fofa_email = FOFA_EMAIL
                    print("  从页面提取 API key")
                return

    except Exception as e:
        print(f"  补全失败: {e}")

    # 尝试 API 获取用户信息
    try:
        for ep in ["https://fofa.info/api/v1/info/my", "https://api.fofa.info/v1/m/users/info"]:
            try:
                r = session.get(ep, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict):
                        key = data.get("key") or (data.get("data") or {}).get("key")
                        email = data.get("email") or (data.get("data") or {}).get("email")
                        if key:
                            session._fofa_key = key
                            session._fofa_email = email or FOFA_EMAIL
                            print(f"  从 API 获取 key")
                            return
            except:
                continue
    except:
        pass

    print("  ⚠️ 未能获取 fofa_token 或 API key")


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
            _ensure_fofa_session(session)
            return session

        if "fofa.info" in final_url and "i.nosec.org" not in final_url:
            print("  ✅ 已登录（跳转到 FOFA）")
            _ensure_fofa_session(session)
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
                    _ensure_fofa_session(session)
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

        logged_in = False
        if "fofa_token" in cookies_dict:
            logged_in = True
        elif "tgt" in cookies_dict:
            logged_in = True
        elif "fofa.info" in resp.url and "ticket=" in resp.url:
            logged_in = True
        elif "fofa.info" in resp.url and "/login" not in resp.url.split("?")[0].replace("f_login", ""):
            logged_in = True
        elif "退出" in resp.text or "个人中心" in resp.text:
            logged_in = True

        if logged_in:
            _ensure_fofa_session(session)
            cookies_dict = {c.name: c.value for c in session.cookies}
            print(f"  ✅ 登录成功, Cookies: {list(cookies_dict.keys())}")
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


# ========== FOFA 搜索 ==========
def fofa_search():
    session = fofa_login()
    if session is None:
        return []

    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()

    print(f"Cookies: {[c.name for c in session.cookies]}")

    # 方式1: API key（web 额度）
    fofa_key = getattr(session, '_fofa_key', None)
    fofa_email = getattr(session, '_fofa_email', FOFA_EMAIL)

    if fofa_key:
        print(f"使用 API key 查询（web 额度）")
        params = {
            "email": fofa_email,
            "key": fofa_key,
            "qbase64": qbase64,
            "size": "100",
            "page": "1",
            "fields": "ip",
        }
        try:
            resp = requests.get("https://fofa.info/api/v1/search/all", params=params, timeout=60)
            print(f"  API 状态: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("error"):
                    print(f"  API 错误: {data.get('errmsg', data)}")
                else:
                    results = data.get("results", [])
                    ips = []
                    for row in results:
                        ip = row[0] if isinstance(row, list) else row
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
                            ips.append(str(ip))
                    ips = list(dict.fromkeys(ips))
                    print(f"提取到 {len(ips)} 个去重IP")
                    return ips
            else:
                print(f"  响应: {resp.text[:300]}")
        except Exception as e:
            print(f"  API 调用失败: {e}")

    # 方式2: JWT 内部 API
    fofa_token = None
    for c in session.cookies:
        if c.name == "fofa_token":
            fofa_token = c.value
            break

    if fofa_token:
        print(f"使用 JWT 查询内部 API")
        api_headers = {
            "User-Agent": UA,
            "Accept": "application/json",
            "authorization": fofa_token,
            "Origin": "https://fofa.info",
            "Referer": "https://fofa.info/",
        }
        params = {
            "qbase64": qbase64,
            "page": "1",
            "size": "100",
            "fields": "ip",
            "ts": str(int(time.time() * 1000)),
            "lang": "zh-CN",
        }
        try:
            resp = requests.get("https://api.fofa.info/v1/search/all",
                                headers=api_headers, params=params, timeout=30)
            print(f"  内部 API 状态: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                ips = []
                for row in results:
                    ip = row[0] if isinstance(row, list) else row
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
                        ips.append(str(ip))
                ips = list(dict.fromkeys(ips))
                print(f"提取到 {len(ips)} 个去重IP")
                return ips
            else:
                print(f"  响应: {resp.text[:300]}")
        except Exception as e:
            print(f"  内部 API 失败: {e}")

    # 方式3: HTML 兜底
    print("尝试 HTML 页面解析...")
    url = f"https://fofa.info/result?qbase64={qbase64}"
    try:
        resp = session.get(url, timeout=60)
        if "hsxa-ip" in resp.text:
            soup = BeautifulSoup(resp.text, "html.parser")
            ips = []
            for div in soup.find_all("div", class_="hsxa-ip"):
                for a in div.find_all("a", class_="hsxa-jump-a"):
                    if a.get("style") and "display:none" in a.get("style", ""):
                        continue
                    ip_text = a.get_text(strip=True)
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_text):
                        ips.append(ip_text)
                        break
            ips = list(dict.fromkeys(ips))
            print(f"提取到 {len(ips)} 个去重IP")
            return ips
        else:
            print("页面无数据")
    except Exception as e:
        print(f"页面请求失败: {e}")

    return []


# ========== CF 反代探测 ==========
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


# ========== AbuseIPDB ==========
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


# ========== 清理 ==========
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
    cf_ips = []
    for idx, ip in enumerate(ips, 1):
        print(f"[{idx}/{len(ips)}] {ip} ...", end=" ")
        if check_cf_proxy(ip):
            print("✅")
            cf_ips.append(ip)
        else:
            print("❌")
    print(f"CF 节点: {len(cf_ips)} 个")
    if not cf_ips:
        return

    print("\n===== 第三步：AbuseIPDB 检测 =====")
    clean_ips = []
    for ip in cf_ips:
        try:
            score = abuseipdb_check(ip)
            print(f"  {ip} 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean_ips.append(ip)
            time.sleep(0.5)
        except Exception as e:
            print(f"  {ip} 失败: {e}")
    if not clean_ips:
        return

    print("\n===== 第四步：添加 DNS =====")
    for ip in clean_ips:
        try:
            create_dns_record(ip)
            time.sleep(0.5)
        except Exception as e:
            print(f"添加失败 {ip}: {e}")

    cleanup_failed_ips(check_proxy_ips())
    print("\n===== 全部完毕 =====")


if __name__ == "__main__":
    main()
