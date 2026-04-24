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
from collections import Counter
from PIL import Image, ImageFilter, ImageEnhance
from playwright.sync_api import sync_playwright

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


# ========== Playwright 登录 + 搜索 ==========
def fofa_search():
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    search_url = f"https://fofa.info/result?qbase64={qbase64}"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=UA)
        page = context.new_page()

        # 登录
        fofa_key = None
        fofa_email_found = None

        for attempt in range(10):
            print(f"登录尝试 {attempt + 1}/10 ...")

            page.goto(LOGIN_PAGE, timeout=30000)
            page.wait_for_load_state("networkidle", timeout=15000)

            # 检查是否已经跳转到 fofa（已登录）
            if "fofa.info" in page.url and "login" not in page.url.lower():
                print("  ✅ 已登录")
                break

            # 填写表单
            try:
                page.fill('input[name="username"]', FOFA_EMAIL, timeout=5000)
                page.fill('input[name="password"]', FOFA_PASSWORD, timeout=5000)
            except:
                print("  找不到登录表单")
                time.sleep(2)
                continue

            # 下载验证码
            try:
                captcha_img = page.query_selector('#captcha_image')
                if captcha_img:
                    captcha_bytes = captcha_img.screenshot()
                    captcha_text = ocr_captcha(captcha_bytes)
                    print(f"  验证码: {captcha_text}")

                    if len(captcha_text) < 4:
                        print("  识别失败，刷新验证码...")
                        captcha_img.click()
                        time.sleep(1)
                        continue

                    page.fill('input[name="_rucaptcha"]', captcha_text, timeout=5000)
                else:
                    print("  找不到验证码图片")
                    continue
            except Exception as e:
                print(f"  验证码处理失败: {e}")
                continue

            # 勾选协议
            try:
                fofa_service = page.query_selector('#fofa_service')
                if fofa_service and not fofa_service.is_checked():
                    fofa_service.check()
            except:
                pass

            # 提交
            try:
                page.click('button[type="submit"]', timeout=5000)
                page.wait_for_load_state("networkidle", timeout=15000)
            except:
                pass

            print(f"  提交后 URL: {page.url}")

            # 检查是否登录成功
            if "fofa.info" in page.url and "login" not in page.url.replace("f_login", "").lower():
                print("  ✅ 登录成功")
                break

            if "i.nosec.org" in page.url:
                # 检查是否验证码错误
                content = page.content()
                if "验证码" in content:
                    print("  ❌ 验证码错误")
                else:
                    print("  ❌ 登录失败")
                time.sleep(1)
                continue

        # 从 cookie 提取 API key
        cookies = context.cookies()
        print(f"  所有 cookies: {[c['name'] for c in cookies]}")

        for c in cookies:
            if c["name"] == "user":
                try:
                    import urllib.parse
                    user_data = urllib.parse.unquote(c["value"])
                    user_json = json.loads(user_data)
                    fofa_key = user_json.get("key")
                    fofa_email_found = user_json.get("email", FOFA_EMAIL)
                    print(f"  API key: {fofa_key[:8]}..." if fofa_key else "  无 key")
                except:
                    pass

        fofa_token = None
        for c in cookies:
            if c["name"] == "fofa_token":
                fofa_token = c["value"]
                print(f"  fofa_token: {fofa_token[:30]}...")

        # 如果没拿到 key，尝试访问 userInfo 页面
        if not fofa_key and not fofa_token:
            print("  尝试访问 userInfo...")
            try:
                page.goto("https://fofa.info/userInfo", timeout=15000)
                page.wait_for_load_state("networkidle", timeout=10000)
                time.sleep(2)

                cookies = context.cookies()
                for c in cookies:
                    if c["name"] == "user":
                        try:
                            import urllib.parse
                            user_data = urllib.parse.unquote(c["value"])
                            user_json = json.loads(user_data)
                            fofa_key = user_json.get("key")
                            fofa_email_found = user_json.get("email", FOFA_EMAIL)
                        except:
                            pass
                    if c["name"] == "fofa_token":
                        fofa_token = c["value"]
            except:
                pass

        browser.close()

    # 用 API key 查询
    if fofa_key:
        print(f"使用 API key 查询")
        params = {
            "email": fofa_email_found or FOFA_EMAIL,
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
            print(f"  API 失败: {e}")

    # 用 JWT 查询
    if fofa_token:
        print(f"使用 JWT 查询")
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
            print(f"  API 状态: {resp.status_code}")
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
            print(f"  API 失败: {e}")

    print("无法获取数据")
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
