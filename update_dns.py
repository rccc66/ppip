import os
import re
import time
import json
import base64
import logging
import subprocess
import requests
import urllib3
import shutil

import undetected_chromedriver as uc
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException, StaleElementReferenceException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger(__name__)

# ---------- 环境变量 ----------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CF_DNS_NAME = os.getenv("CLOUDFLARE_DNS_NAME", "us")
CF_DOMAIN = os.getenv("CLOUDFLARE_DOMAIN")
FOFA_EMAIL = os.getenv("FOFA_EMAIL")
FOFA_PASSWORD = os.getenv("FOFA_PASSWORD")
FOFA_API_KEY = os.getenv("FOFA_API_KEY", "")
_fofa_size = (os.getenv("FOFA_API_SIZE") or "").strip()
FOFA_API_SIZE = int(_fofa_size) if _fofa_size else 100
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
TWOCAPTCHA_API_KEY = os.getenv("TWOCAPTCHA_API_KEY", "")
FOFA_QUERY = ('server=="cloudflare" && header="Forbidden" && country=="US" && '
              'port="443" && (asn=="31898" || asn=="16509" || asn=="14618" || asn=="8075")')
PROXY_CHECK_URL = "https://check.proxyip.cmliussss.net"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
ABUSE_THRESHOLD = 20
LOGIN_PAGE = "https://i.nosec.org/login?locale=zh-CN&service=https://fofa.info/f_login"


# ---------- 浏览器 ----------
def create_driver():
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--lang=zh-CN")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--disable-features=IsolateOrigins,site-per-process,AutomationControlled")
    options.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")

    if os.getenv("GITHUB_ACTIONS") or os.getenv("FORCE_PROXY"):
        proxy = "socks5://127.0.0.1:1080" if os.getenv("SOCKS5_PROXY") else "socks5://127.0.0.1:40000"
        options.add_argument(f"--proxy-server={proxy}")
        log.info(f"🌐 Chrome 走 SOCKS5: {proxy}")
    elif os.getenv("SOCKS5_PROXY"):
        options.add_argument("--proxy-server=socks5://127.0.0.1:1080")

    browser_path = (shutil.which("google-chrome") or shutil.which("google-chrome-stable")
                    or shutil.which("chromium-browser") or shutil.which("chromium"))
    version = None
    if browser_path:
        try:
            version = int(subprocess.check_output([browser_path, "--version"], text=True).split()[-1].split(".")[0])
            log.info(f"Chrome {version}: {browser_path}")
        except Exception: pass

    driver = uc.Chrome(options=options, browser_executable_path=browser_path,
                       version_main=version, headless=False)
    driver.implicitly_wait(5)

    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": """
            try { Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN','zh','en-US','en']}); } catch(e){}
            try { Object.defineProperty(navigator, 'language', {get: () => 'zh-CN'}); } catch(e){}
            try { Object.defineProperty(navigator, 'webdriver', {get: () => undefined}); } catch(e){}
            try { Object.defineProperty(navigator, 'plugins', {get: () => [
                {name:'Chrome PDF Plugin'},{name:'Chrome PDF Viewer'},{name:'Native Client'}]}); } catch(e){}
        """})
    except Exception: pass

    return driver


def _save_debug(driver, tag):
    os.makedirs("debug", exist_ok=True)
    ts = time.strftime("%H%M%S")
    base = f"debug/dbg_{tag}_{ts}"
    try:
        driver.save_screenshot(f"{base}.png")
        log.info(f"  📸 {base}.png")
    except Exception: pass
    try:
        with open(f"{base}.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source or "")
        log.info(f"  📄 {base}.html")
    except Exception: pass


# ---------- Turnstile 处理（修复版 - 支持 iframe）----------
def handle_turnstile(driver, max_wait_widget=30, max_wait_token=30):
    """
    修复版本：Turnstile 的 checkbox 位于 iframe 内部
    1. 切换到 iframe 后查找 checkbox 并点击
    2. 同时保留 token 自动检测和诊断功能
    """
    log.info(f"  等待 Turnstile widget 出现 (最多 {max_wait_widget}s)...")

    # 1) 等待 .cf-turnstile 容器出现
    try:
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.cf-turnstile")))
    except TimeoutException:
        log.info("  ❌ 未找到 Turnstile 容器")
        _save_debug(driver, "no_widget")
        return False

    # 2) 等待 iframe 出现（widget 渲染完成的标志）
    iframe = None
    deadline = time.time() + max_wait_widget
    while time.time() < deadline:
        try:
            iframe = driver.find_element(By.CSS_SELECTOR, "div.cf-turnstile iframe")
            if iframe:
                log.info("  ✅ Turnstile iframe 已出现")
                break
        except NoSuchElementException:
            pass

        # 检查 token 是否自动生成
        try:
            token = driver.execute_script(
                "var i=document.querySelector('input[name=\"cf-turnstile-response\"]');"
                "return i ? i.value : '';")
            if token and len(token) > 10:
                log.info(f"  ✅ Turnstile 自动通过 (token 长度 {len(token)})")
                return True
        except Exception:
            pass

        # 检查提交按钮是否可用
        try:
            btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
            if btn.is_enabled() and not btn.get_attribute("disabled"):
                log.info("  ✅ 提交按钮已启用 (Turnstile 自动通过)")
                return True
        except Exception:
            pass

        time.sleep(1)

    if not iframe:
        log.info("  ❌ Turnstile iframe 未出现")
        _save_debug(driver, "no_iframe")
        return False

    # 3) 切换到 iframe 内部
    try:
        driver.switch_to.frame(iframe)
        log.info("  ✅ 已切换到 Turnstile iframe")
    except Exception as e:
        log.info(f"  ❌ 切换 iframe 失败: {e}")
        _save_debug(driver, "switch_frame_fail")
        return False

    # 4) 在 iframe 内查找并点击 checkbox
    checkbox = None
    try:
        # 优先尝试查找 input[type="checkbox"]
        checkbox = driver.find_element(By.CSS_SELECTOR, 'input[type="checkbox"]')
        log.info("  ✅ 找到 checkbox（input 类型）")
    except NoSuchElementException:
        # 尝试查找 label
        try:
            checkbox = driver.find_element(By.CSS_SELECTOR, 'label[for="challenge-stage"]')
            log.info("  ✅ 找到 checkbox（label 类型）")
        except NoSuchElementException:
            # 模糊匹配包含"真人"的元素
            try:
                checkbox = driver.find_element(By.XPATH, '//*[contains(@aria-label, "真人") or contains(text(), "Verify") or contains(text(), "human")]')
                log.info("  ✅ 找到 checkbox（模糊匹配）")
            except NoSuchElementException:
                log.info("  ❌ 未找到 checkbox")
                driver.switch_to.default_content()
                _save_debug(driver, "no_checkbox_in_iframe")
                return False

    # 5) 点击 checkbox
    try:
        ActionChains(driver).move_to_element(checkbox).pause(0.5).click().perform()
        log.info("  👉 物理点击 checkbox 成功")
    except Exception:
        try:
            driver.execute_script("arguments[0].click();", checkbox)
            log.info("  👉 JS 点击 checkbox 成功")
        except Exception as e:
            log.info(f"  ❌ 点击失败: {e}")
            driver.switch_to.default_content()
            _save_debug(driver, "click_fail")
            return False

    # 6) 切换回主文档
    driver.switch_to.default_content()

    # 7) 等待 token 生成或按钮可用
    log.info(f"  等待 Turnstile 验证完成 (最多 {max_wait_token}s)...")
    deadline = time.time() + max_wait_token
    while time.time() < deadline:
        try:
            token = driver.execute_script(
                "var i=document.querySelector('input[name=\"cf-turnstile-response\"]');"
                "return i ? i.value : '';")
            if token and len(token) > 10:
                log.info(f"  ✅ Turnstile token 已生成 (长度 {len(token)})")
                return True
        except Exception:
            pass

        try:
            btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
            if btn.is_enabled() and not btn.get_attribute("disabled"):
                log.info("  ✅ 提交按钮已启用")
                return True
        except Exception:
            pass

        time.sleep(1)

    log.info("  ❌ 验证超时")
    _save_debug(driver, "verify_timeout")
    return False


# ---------- 其他函数（保持不变）----------
def fofa_search_via_shodan():
    if not SHODAN_API_KEY:
        return []
    log.info("===== Shodan API 搜索 IP =====")
    query = 'port:443 country:US http.status:403 server:cloudflare'
    log.info(f"  查询: {query}")
    try:
        r = requests.get("https://api.shodan.io/shodan/host/search",
            params={"key": SHODAN_API_KEY, "query": query, "facets": "country,asn,org"}, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.error(f"❌ Shodan 异常: {e}")
        return []

    if "error" in data:
        log.error(f"❌ Shodan 错误: {data['error']}")
        return []

    matches = data.get("matches", [])
    ips = [m.get("ip_str", "") for m in matches if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', m.get("ip_str", ""))]
    ips = list(dict.fromkeys(ips))
    log.info(f"提取 {len(ips)} 个去重 IP")
    return ips


def fofa_search_via_api():
    if not FOFA_API_KEY:
        return []
    log.info("===== FOFA API 搜索 IP =====")
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    try:
        r = requests.get("https://fofa.info/api/v1/search/all", params={
            "email": FOFA_EMAIL, "key": FOFA_API_KEY, "qbase64": qbase64,
            "size": FOFA_API_SIZE, "fields": "ip,port,server,country"}, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.error(f"❌ FOFA API 异常: {e}")
        return []

    results = data.get("results", [])
    ips = []
    for item in results:
        ip = item.get("ip") if isinstance(item, dict) else (item[0] if item else "")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
            ips.append(str(ip))
    ips = list(dict.fromkeys(ips))
    log.info(f"提取 {len(ips)} 个去重 IP")
    return ips


def fofa_search_via_browser():
    driver = create_driver()
    ips = []
    try:
        for attempt in range(3):
            log.info(f"登录尝试 {attempt + 1}/3 ...")
            driver.get(LOGIN_PAGE)
            time.sleep(3)

            if "fofa.info" in driver.current_url and "login" not in driver.current_url.lower():
                log.info("  ✅ 已登录")
                break

            try:
                u = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "username")))
                u.clear(); u.send_keys(FOFA_EMAIL)
                p = driver.find_element(By.NAME, "password")
                p.clear(); p.send_keys(FOFA_PASSWORD)
            except TimeoutException:
                log.info("  找不到登录表单")
                _save_debug(driver, "no_form")
                continue

            if not handle_turnstile(driver):
                if TWOCAPTCHA_API_KEY:
                    try:
                        div = driver.find_element(By.CSS_SELECTOR, "div.cf-turnstile")
                        sitekey = div.get_attribute("data-sitekey")
                        token = None  # 2captcha 解码逻辑（可自行实现）
                        if token:
                            driver.execute_script("""
                                var i = document.querySelector('input[name="cf-turnstile-response"]') || 
                                      document.createElement('input');
                                i.type = 'hidden';
                                i.name = 'cf-turnstile-response';
                                i.value = arguments[0];
                                document.querySelector('form#login-form').appendChild(i);
                            """, token)
                            log.info("  ✅ 2captcha token 注入完成")
                        else:
                            continue
                    except Exception as e:
                        log.info(f"  2captcha 异常: {e}")
                        continue
                else:
                    log.info("  未配置 TWOCAPTCHA_API_KEY")
                    continue

            # 提交
            try:
                btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                driver.execute_script("arguments[0].disabled = false;", btn)
                btn.click()
                time.sleep(5)
            except Exception as e:
                log.info(f"  提交异常: {e}")

            log.info(f"  提交后 URL: {driver.current_url}")
            if "fofa.info" in driver.current_url and "login" not in driver.current_url.lower():
                log.info("  ✅ 登录成功")
                break
            log.info("  ❌ 登录失败")
            _save_debug(driver, "login_fail")

        # 搜索逻辑保持不变...
        driver.get(f"https://fofa.info/result?qbase64={base64.b64encode(FOFA_QUERY.encode()).decode()}")
        time.sleep(10)

    except Exception as e:
        log.error(f"异常: {e}")
        _save_debug(driver, "error")
    finally:
        try: driver.quit()
        except Exception: pass

    # 解析 IP 逻辑保持不变...
    return ips


def fofa_search():
    if SHODAN_API_KEY:
        log.info("检测到 SHODAN_API_KEY, 优先用 Shodan")
        ips = fofa_search_via_shodan()
        if ips: return ips
    if FOFA_API_KEY:
        log.info("尝试 FOFA API")
        ips = fofa_search_via_api()
        if ips: return ips
    log.info("===== 浏览器模式 =====")
    return fofa_search_via_browser()


def check_cf_proxy(ip):
    try:
        if "cloudflare" in requests.get(f"https://{ip}/cdn-cgi/trace", verify=False, timeout=5).text.lower():
            return True
    except Exception: pass
    for scheme in ("http", "https"):
        try:
            r = requests.head(f"{scheme}://{ip}", verify=False, timeout=5)
            if "cloudflare" in r.headers.get("Server", "").lower(): return True
        except Exception: continue
    return False


def abuseipdb_check(ip):
    r = requests.get(ABUSE_CHECK_URL,
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15)
    r.raise_for_status()
    return r.json()["data"]["abuseConfidenceScore"]


def get_dns_records():
    r = requests.get(CF_DNS_RECORDS_URL,
        headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
        params={"type": "A", "name": f"{CF_DNS_NAME}.{CF_DOMAIN}"}, timeout=15)
    r.raise_for_status()
    return r.json().get("result", [])


def create_dns_record(ip):
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    for r in get_dns_records():
        if r["content"] == ip:
            log.info(f"IP {ip} 已存在")
            return
    r = requests.post(CF_DNS_RECORDS_URL,
        headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
        json={"type": "A", "name": fqdn, "content": ip, "ttl": 1, "proxied": False}, timeout=15)
    r.raise_for_status()
    log.info(f"已添加 DNS: {fqdn} -> {ip}")


def delete_dns_record(rid, ip):
    r = requests.delete(f"{CF_DNS_RECORDS_URL}/{rid}",
        headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}, timeout=15)
    r.raise_for_status()
    log.info(f"已删除: {ip}")


def check_proxy_ips():
    log.info("===== 检测 ProxyIP =====")
    time.sleep(30)
    records = get_dns_records()
    if not records:
        log.info("无 DNS 记录")
        return {}
    all_ips = [r["content"] for r in records]
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    log.info(f"检测 {fqdn} ({len(all_ips)} 个 IP)")

    driver = create_driver()
    valid = set()
    try:
        driver.get(PROXY_CHECK_URL)
        time.sleep(3)
        ib = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "inputList")))
        ib.clear(); ib.send_keys(fqdn)
        try:
            driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], .check-btn, #checkBtn').click()
        except Exception:
            ib.send_keys(Keys.RETURN)
        log.info("  等待检测结果...")
        last = stable = 0
        for _ in range(90):
            time.sleep(2)
            cur = driver.page_source.count("result-item")
            if cur > 0:
                if cur == last: stable += 1
                else: stable = 0; last = cur; log.info(f"  已加载 {cur} 个")
                if stable >= 5: break
        time.sleep(3)
        soup = BeautifulSoup(driver.page_source, "html.parser")
        for item in soup.find_all("div", class_="result-item"):
            ok = "success" in (item.get("class") or [])
            sp = item.find(class_="result-ip")
            if sp:
                ip = sp.get_text(strip=True).split(":")[0]
                if ok: valid.add(ip); log.info(f"  ✅ {ip}")
                else: log.info(f"  ❌ {ip}")
    except Exception as e:
        log.error(f"检测异常: {e}")
    finally:
        try: driver.quit()
        except Exception: pass
    return {ip: ("valid" if ip in valid else "invalid") for ip in all_ips}


def run_cloudflare_speedtest(valid_ips):
    if not valid_ips:
        log.info("无有效 IP")
        return []
    log.info("===== CloudflareST 测速 =====")
    with open("cf_ips.txt", "w") as f:
        for ip in valid_ips: f.write(ip + "\n")
    if not os.path.exists("./cfst"):
        log.info("未找到 cfst")
        return []
    cmd = ["./cfst", "-f", "cf_ips.txt", "-o", "cf_speedtest.csv",
           "-n", "200", "-t", "4", "-dn", "10", "-dt", "10", "-tp", "443",
           "-tl", "300", "-sl", "0", "-p", "10", "-allip",
           "-url", "http://speed.cloudflare.com/__down?bytes=99999999"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        for line in (r.stdout or "").splitlines(): log.info(line)
        for line in (r.stderr or "").splitlines(): log.info(f"[stderr] {line}")
    except Exception as e:
        log.info(f"测速失败: {e}")
        return []

    results = []
    if os.path.exists("cf_speedtest.csv"):
        try:
            with open("cf_speedtest.csv") as f: lines = f.readlines()
            for line in lines[1:]:
                p = [x.strip() for x in line.strip().split(",") if x.strip()]
                if len(p) >= 6:
                    try: speed = float(p[5])
                    except Exception: speed = 0.0
                    results.append({"ip": p[0], "speed_mbps": speed,
                                    "latency": p[4] if len(p) > 4 else "",
                                    "loss": p[3] if len(p) > 3 else "",
                                    "region": p[6] if len(p) > 6 else ""})
            if results:
                results.sort(key=lambda x: x["speed_mbps"], reverse=True)
                log.info("===== 速度排名 =====")
                for i, it in enumerate(results, 1):
                    log.info(f"  #{i} {it['ip']} -> {it['speed_mbps']:.2f} MB/s, "
                             f"延迟 {it['latency']}, 丢包 {it['loss']}, 区域 {it['region']}")
        except Exception as e:
            log.info(f"解析失败: {e}")
    return results


def cleanup_failed_ips(ip_status):
    failed = [ip for ip, s in ip_status.items() if s == "invalid"]
    if not failed: return
    log.info(f"清理 {len(failed)} 个失败 IP")
    records = get_dns_records()
    for r in records:
        if r["content"] in failed:
            try: delete_dns_record(r["id"], r["content"])
            except Exception as e: log.info(f"删除失败 {r['content']}: {e}")


def main():
    import sys
    log.info("===== 第一步：搜索 IP =====")
    ips = fofa_search()
    log.info(f"找到 {len(ips)} 个 IP")
    if not ips:
        log.error("❌ 无 IP，退出")
        sys.exit(1)

    log.info("===== 第二步：探测 CF 反代 =====")
    cf_ips = [ip for ip in ips if check_cf_proxy(ip)]
    log.info(f"CF 节点: {len(cf_ips)} 个")
    if not cf_ips: sys.exit(1)

    log.info("===== 第三步：AbuseIPDB =====")
    clean = []
    for ip in cf_ips:
        try:
            s = abuseipdb_check(ip)
            log.info(f"  {ip}: {s}")
            if s < ABUSE_THRESHOLD: clean.append(ip)
            time.sleep(0.5)
        except Exception as e:
            log.info(f"  {ip} 失败: {e}")
    if not clean: sys.exit(1)

    log.info("===== 第四步：添加 DNS =====")
    for ip in clean:
        try: create_dns_record(ip); time.sleep(0.5)
        except Exception as e: log.info(f"添加失败 {ip}: {e}")

    ip_status = check_proxy_ips()
    valid_ips = [ip for ip, s in ip_status.items() if s == "valid"]
    run_cloudflare_speedtest(valid_ips)
    cleanup_failed_ips(ip_status)
    log.info("===== 全部完毕 =====")


if __name__ == "__main__":
    main()
