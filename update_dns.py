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


# ---------- Turnstile 处理（修复版） ----------
def handle_turnstile(driver, max_wait_checkbox=30, max_wait_token=30):
    """
    修复后的 Turnstile 处理：
    - 使用更稳定的 checkbox 定位方式（aria-label + label 文字）
    - 优先使用 ActionChains 点击
    - 增加完整诊断信息输出
    - 检测到 token 直接通过
    """
    log.info(f"  等待 Turnstile checkbox 出现 (最多 {max_wait_checkbox}s)...")

    checkbox = None
    deadline = time.time() + max_wait_checkbox

    while time.time() < deadline:
        # 诊断信息（每5秒输出一次）
        if int(time.time()) % 5 == 0:
            try:
                info = driver.execute_script("""
                    var cbs = document.querySelectorAll('input[type="checkbox"]');
                    var labels = document.querySelectorAll('label');
                    var cfWidget = document.querySelector('div.cf-turnstile');
                    var cfInnerHTML = cfWidget ? cfWidget.innerHTML.substring(0, 400) : 'no_widget';
                    var cfChildrenCount = cfWidget ? cfWidget.children.length : 0;
                    var cfIframes = cfWidget ? cfWidget.querySelectorAll('iframe') : [];
                    var cfIframeCount = cfIframes.length;
                    var cfTokenInput = document.querySelector('input[name="cf-turnstile-response"]');
                    var wrapper = document.querySelector('.turnstile-wrapper');
                    return {
                        checkboxCount: cbs.length,
                        labelCount: labels.length,
                        cfChildrenCount: cfChildrenCount,
                        cfInnerHTML: cfInnerHTML,
                        cfIframeCount: cfIframeCount,
                        hasCfTokenInput: !!cfTokenInput,
                        cfTokenLen: cfTokenInput ? cfTokenInput.value.length : 0,
                        wrapperHTML: wrapper ? wrapper.innerHTML.substring(0, 300) : 'no_wrapper'
                    };
                """)
                log.info(f"  [{int(time.time())}s] 诊断:")
                for k, v in info.items():
                    log.info(f"     {k}: {v}")
            except Exception:
                pass

        # 尝试找到 checkbox（优先 aria-label）
        for el in driver.find_elements(By.CSS_SELECTOR, 'input[type="checkbox"]'):
            try:
                aria = el.get_attribute("aria-label") or ""
                if "真人" in aria or "verify" in aria.lower() or "human" in aria.lower():
                    checkbox = el
                    log.info(f"  ✅ 找到 checkbox (aria-label='{aria}')")
                    break
            except StaleElementReferenceException:
                continue
            except Exception:
                continue

        if checkbox:
            break

        time.sleep(1)

    if not checkbox:
        log.info("  ❌ checkbox 未出现")
        _save_debug(driver, "no_checkbox")
        return False

    # 点击 checkbox
    try:
        ActionChains(driver).move_to_element(checkbox).pause(0.5).click().perform()
        log.info("  👉 ActionChains 点击 checkbox 成功")
    except Exception as e:
        log.info(f"  ActionChains 点击失败: {e}")
        try:
            driver.execute_script("arguments[0].click();", checkbox)
            log.info("  👉 JS 点击 checkbox 成功")
        except Exception as e2:
            log.info(f"  JS 点击也失败: {e2}")
            _save_debug(driver, "click_fail")
            return False

    # 等待 token 生成或按钮可用
    log.info(f"  等待 Turnstile 验证完成 (最多 {max_wait_token}s)...")
    deadline = time.time() + max_wait_token
    while time.time() < deadline:
        # 检查 token
        try:
            token = driver.execute_script('return document.querySelector("input[name=\'cf-turnstile-response\']") ? document.querySelector("input[name=\'cf-turnstile-response\']").value : ""')
            if token and len(token) > 10:
                log.info(f"  ✅ Turnstile token 已生成 (长度 {len(token)})")
                return True
        except Exception:
            pass

        # 检查按钮是否可用
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


# ---------- 其他函数保持不变（FOFA_API、Shodan、DNS、Speedtest 等）----------
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
                        # 2captcha 解码逻辑（略，保持原样）
                        token = None  # 这里需要你实现 2captcha 逻辑
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

        # 后续搜索逻辑保持不变...
        # ...（你原来的代码中搜索部分不变）

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


# ---------- 其他函数（check_cf_proxy、abuseipdb_check、get_dns_records 等）保持不变 ----------
# ...（完整代码中剩下的函数均不变）

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
