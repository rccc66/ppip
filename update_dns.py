import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re, time, json, base64, logging, subprocess, requests, urllib3
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
    options.add_experimental_option("prefs", {"intl.accept_languages": "zh-CN,zh"})

    # SOCKS5 代理（仿 Hohai 脚本策略）
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

    # 反指纹注入（CDP，在每个新页面加载前生效）
    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": """
            try { Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN','zh','en-US','en']}); } catch(e){}
            try { Object.defineProperty(navigator, 'language', {get: () => 'zh-CN'}); } catch(e){}
            try { Object.defineProperty(navigator, 'webdriver', {get: () => undefined}); } catch(e){}
            try { Object.defineProperty(navigator, 'plugins', {get: () => [
                {name:'Chrome PDF Plugin'},{name:'Chrome PDF Viewer'},{name:'Native Client'}]}); } catch(e){}
            try { if(!window.chrome) window.chrome={}; if(!window.chrome.runtime) window.chrome.runtime={}; } catch(e){}
            try { var g = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(p) {
                    if(p===37445) return 'Intel Inc.';
                    if(p===37446) return 'Intel Iris OpenGL Engine';
                    return g.call(this, p); }; } catch(e){}
        """})
        log.info("✅ 反指纹脚本已注入")
    except Exception: pass

    # 代理自检
    if os.getenv("GITHUB_ACTIONS") or os.getenv("FORCE_PROXY"):
        try:
            driver.set_page_load_timeout(20)
            driver.get("https://api.ipify.org?format=text")
            time.sleep(2)
            ip = driver.find_element(By.TAG_NAME, "body").text.strip()
            log.info(f"🌐 Chrome 出口 IP: {ip}")
        except Exception as e:
            log.warning(f"代理自检失败: {e}")
        try: driver.set_page_load_timeout(60)
        except Exception: pass

    return driver


def _save_debug(driver, tag):
    """保存截图 + HTML 到 debug/ 目录"""
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


# ---------- Turnstile 处理（精简版） ----------
def handle_turnstile(driver, max_wait_checkbox=30, max_wait_token=30):
    """
    精简逻辑：
      1. 等 checkbox 出现（最多 30s）
      2. ActionChains 物理点击 checkbox
      3. 等 token 生成或按钮启用（最多 30s）
    成功返回 True，失败返回 False。
    """
    # 1) 等任意 Turnstile 相关元素出现（容器或 token input）
    try:
        WebDriverWait(driver, 15).until(
            lambda d: d.find_elements(By.CSS_SELECTOR, "div.cf-turnstile")
                    or d.find_elements(By.CSS_SELECTOR, 'input[name="cf-turnstile-response"]'))
    except TimeoutException:
        log.info("  未找到 Turnstile 容器")
        _save_debug(driver, "no_widget")
        return False

    # 2) 等 checkbox 可见——关键：checkbox 不在 .cf-turnstile 里！
    # CF 用 CSS Modules 生成随机 className（HZKZ0/YGJrG8/pgnB1 等），
    # 每次刷新都变，所以只能用稳定的特征找：
    #   - aria-label="请验证您是真人"（中文固定）
    #   - 或任意 input[type=checkbox] 在含 "请验证您是真人" 文字的容器里
    log.info(f"  等待 Turnstile checkbox 出现 (最多 {max_wait_checkbox}s)...")
    checkbox = None
    deadline = time.time() + max_wait_checkbox
    loop_count = 0

    while time.time() < deadline:
        loop_count += 1

        # 先检查 token（万一 CF 自动通过了）
        try:
            token = driver.execute_script(
                "var i=document.querySelector('input[name=\"cf-turnstile-response\"]');"
                "return i?i.value:'';")
            if token and len(token) > 10:
                log.info(f"  ✅ Turnstile 自动通过 (token 长度 {len(token)})")
                return True
        except Exception: pass

        # 检查按钮启用
        try:
            btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
            if btn.is_enabled() and not btn.get_attribute("disabled"):
                log.info("  ✅ 提交按钮已启用 (Turnstile 自动通过)")
                return True
        except Exception: pass

        # 全文档搜 checkbox——用稳定的 aria-label 找
        # 关键修复：CF 的 input[type=checkbox] 通常被 CSS 隐藏（opacity:0），
        # 用 label 的伪元素显示视觉效果，所以 is_displayed() 会返回 False！
        # 不检查 is_displayed()，只要 aria-label 匹配就尝试点击
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, 'input[type="checkbox"]'):
                try:
                    aria = el.get_attribute("aria-label") or ""
                    if "真人" in aria or "verify" in aria.lower() or "human" in aria.lower():
                        checkbox = el
                        # 不再检查 is_displayed，直接用
                        try:
                            disp = el.is_displayed()
                            sz = el.size
                        except Exception:
                            disp = "?"; sz = {}
                        log.info(f"  ✅ 找到 checkbox (aria='{aria}', "
                                 f"displayed={disp}, size={sz})")
                        break
                except StaleElementReferenceException: continue
                except Exception: continue
        except Exception: pass

        # 兜底：找含"请验证您是真人"文字的 label，点它
        if not checkbox:
            try:
                for label in driver.find_elements(By.TAG_NAME, "label"):
                    try:
                        txt = label.text or ""
                        if "真人" in txt or "verify" in txt.lower() or "human" in txt.lower():
                            checkbox = label
                            log.info(f"  ✅ 找到 label: '{txt}'")
                            break
                    except StaleElementReferenceException: continue
                    except Exception: continue
            except Exception: pass

        if checkbox: break

        # 每 5s 打印一次诊断：页面上有多少 checkbox、多少 label
        # 关键：用 JS 深度遍历，包括 shadow DOM 和 iframe
        if loop_count % 5 == 0:
            try:
                info = driver.execute_script("""
                    // 1) 主文档里的 checkbox
                    var cbs = document.querySelectorAll('input[type="checkbox"]');
                    var labels = document.querySelectorAll('label');

                    // 2) 检查 .cf-turnstile 内部
                    var cfWidget = document.querySelector('div.cf-turnstile');
                    var cfInnerHTML = cfWidget ? cfWidget.innerHTML.substring(0, 500) : 'no_widget';
                    var cfChildrenCount = cfWidget ? cfWidget.children.length : 0;

                    // 3) 检查 .cf-turnstile 内的 iframe（CF widget 通常用 iframe 包裹）
                    var cfIframes = cfWidget ? cfWidget.querySelectorAll('iframe') : [];
                    var cfIframeInfo = [];
                    for (var i = 0; i < cfIframes.length; i++) {
                        cfIframeInfo.push({
                            id: cfIframes[i].id || '',
                            src: (cfIframes[i].src || '').substring(0, 100),
                            width: cfIframes[i].offsetWidth,
                            height: cfIframes[i].offsetHeight
                        });
                    }

                    // 4) 全文档 iframe
                    var allIframes = document.querySelectorAll('iframe');
                    var allIframeInfo = [];
                    for (var i = 0; i < allIframes.length; i++) {
                        allIframeInfo.push({
                            id: allIframes[i].id || '',
                            src: (allIframes[i].src || '').substring(0, 80),
                            w: allIframes[i].offsetWidth,
                            h: allIframes[i].offsetHeight
                        });
                    }

                    // 5) 检查 cf-turnstile-response token
                    var cfInput = document.querySelector('input[name="cf-turnstile-response"]');

                    // 6) 检查是否有 shadow DOM 容器（CF 可能用）
                    var turnstileWrapper = document.querySelector('.turnstile-wrapper');
                    var wrapperHTML = turnstileWrapper ?
                        turnstileWrapper.innerHTML.substring(0, 800) : 'no_wrapper';

                    return {
                        checkboxCount: cbs.length,
                        labelCount: labels.length,
                        cfChildrenCount: cfChildrenCount,
                        cfInnerHTML: cfInnerHTML,
                        cfIframeCount: cfIframes.length,
                        cfIframeInfo: cfIframeInfo,
                        totalIframeCount: allIframes.length,
                        allIframeInfo: allIframeInfo,
                        hasCfTokenInput: !!cfInput,
                        cfTokenLen: cfInput ? (cfInput.value || '').length : 0,
                        wrapperHTML: wrapperHTML
                    };
                """)
                log.info(f"  [{loop_count}s] 诊断:")
                for k, v in info.items():
                    val_str = str(v)
                    if len(val_str) > 200:
                        val_str = val_str[:200] + "..."
                    log.info(f"     {k}: {val_str}")
            except Exception as e:
                log.info(f"  诊断异常: {e}")

        time.sleep(1)

    if not checkbox:
        log.info("  ❌ checkbox 未出现")
        _save_debug(driver, "no_checkbox")
        return False

    # 3) ActionChains 物理点击 checkbox
    try:
        ActionChains(driver).move_to_element(checkbox).pause(0.3).click().perform()
        log.info("  👉 已点击 checkbox")
    except Exception as e:
        log.info(f"  ActionChains 失败: {e}, 尝试 JS 点击")
        try:
            driver.execute_script("arguments[0].click();", checkbox)
            log.info("  👉 JS 点击 checkbox")
        except Exception as e2:
            log.info(f"  JS 点击也失败: {e2}")
            _save_debug(driver, "click_fail")
            return False

    # 4) 等 token 生成或按钮启用
    log.info(f"  等待 Turnstile 验证完成 (最多 {max_wait_token}s)...")
    deadline = time.time() + max_wait_token
    while time.time() < deadline:
        try:
            token = driver.execute_script(
                "var i=document.querySelector('input[name=\"cf-turnstile-response\"]');"
                "return i?i.value:'';")
            if token and len(token) > 10:
                log.info(f"  ✅ Turnstile token 已生成 (长度 {len(token)})")
                try:
                    btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                    driver.execute_script("arguments[0].disabled = false;", btn)
                except Exception: pass
                return True
        except Exception: pass

        try:
            btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
            if btn.is_enabled() and not btn.get_attribute("disabled"):
                log.info("  ✅ 提交按钮已启用")
                return True
        except Exception: pass

        time.sleep(1)

    log.info("  ❌ 验证超时")
    _save_debug(driver, "verify_timeout")
    return False


def _solve_turnstile_with_2captcha(sitekey, page_url):
    """2captcha 兜底解 Turnstile"""
    if not TWOCAPTCHA_API_KEY:
        return None
    log.info(f"  2captcha 提交任务 (sitekey={sitekey})")
    try:
        r = requests.post("https://2captcha.com/in.php", data={
            "key": TWOCAPTCHA_API_KEY, "method": "turnstile",
            "sitekey": sitekey, "pageurl": page_url, "json": 1}, timeout=30)
        d = r.json()
        if d.get("status") != 1: return None
        task_id = d["request"]
        for _ in range(30):
            time.sleep(5)
            r = requests.get("https://2captcha.com/res.php",
                params={"key": TWOCAPTCHA_API_KEY, "action": "get", "id": task_id, "json": 1}, timeout=30)
            d = r.json()
            if d.get("status") == 1: return d["request"]
            if d.get("request") != "CAPCHA_NOT_READY": return None
    except Exception as e:
        log.info(f"  2captcha 异常: {e}")
    return None


# ---------- Shodan API ----------
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
    except requests.exceptions.HTTPError as e:
        log.error(f"❌ Shodan HTTP {e.response.status_code}: {e.response.text[:200]}")
        return []
    except Exception as e:
        log.error(f"❌ Shodan 异常: {e}")
        return []

    if "error" in data:
        log.error(f"❌ Shodan 错误: {data['error']}")
        return []

    matches = data.get("matches", [])
    log.info(f"✅ Shodan 返回 {len(matches)} 条 (total={data.get('total', 0)})")
    ips = [m.get("ip_str", "") for m in matches
           if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', m.get("ip_str", ""))]
    ips = list(dict.fromkeys(ips))
    log.info(f"提取 {len(ips)} 个去重 IP")
    return ips


# ---------- FOFA API ----------
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

    if data.get("error"):
        err = data.get('errmsg', data.get('error'))
        log.error(f"❌ FOFA API 错误: {err}")
        return []

    results = data.get("results", [])
    log.info(f"✅ FOFA API 返回 {len(results)} 条")
    ips = []
    for item in results:
        ip = item.get("ip") if isinstance(item, dict) else (item[0] if item else "")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
            ips.append(str(ip))
    ips = list(dict.fromkeys(ips))
    log.info(f"提取 {len(ips)} 个去重 IP")
    return ips


# ---------- FOFA 浏览器 ----------
def fofa_search_via_browser():
    driver = create_driver()
    ips = []
    try:
        for attempt in range(3):
            log.info(f"登录尝试 {attempt + 1}/3 ...")
            driver.get(LOGIN_PAGE)
            try:
                WebDriverWait(driver, 30).until(
                    lambda d: d.execute_script("return document.readyState") == "complete")
            except TimeoutException: pass
            time.sleep(3)

            if "fofa.info" in driver.current_url and "login" not in driver.current_url.lower():
                log.info("  ✅ 已登录")
                break

            # 填用户名密码
            try:
                u = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "username")))
                u.clear(); u.send_keys(FOFA_EMAIL)
                p = driver.find_element(By.NAME, "password")
                p.clear(); p.send_keys(FOFA_PASSWORD)
            except TimeoutException:
                log.info("  找不到登录表单")
                _save_debug(driver, "no_form")
                continue

            # 处理 Turnstile
            if not handle_turnstile(driver):
                # 兜底：2captcha
                if TWOCAPTCHA_API_KEY:
                    try:
                        div = driver.find_element(By.CSS_SELECTOR, "div.cf-turnstile")
                        sitekey = div.get_attribute("data-sitekey")
                        token = _solve_turnstile_with_2captcha(sitekey, driver.current_url)
                        if token:
                            driver.execute_script("""
                                var i = document.querySelector('input[name="cf-turnstile-response"]');
                                if (!i) { i = document.createElement('input'); i.type='hidden';
                                    i.name='cf-turnstile-response';
                                    document.querySelector('form#login-form').appendChild(i); }
                                i.value = arguments[0];
                                if (typeof window.onTurnstileSuccess === 'function') window.onTurnstileSuccess();
                            """, token)
                            log.info("  ✅ 2captcha token 注入完成")
                        else:
                            log.info("  2captcha 未返回 token")
                            continue
                    except Exception as e:
                        log.info(f"  2captcha 流程异常: {e}")
                        continue
                else:
                    log.info("  未配置 TWOCAPTCHA_API_KEY")
                    continue

            # 勾选服务协议
            try:
                cb = driver.find_element(By.ID, "fofa_service")
                if not cb.is_selected():
                    driver.execute_script("arguments[0].click();", cb)
            except Exception: pass

            # 提交
            try:
                btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                driver.execute_script("arguments[0].disabled = false;", btn)
                btn.click()
                time.sleep(5)
            except Exception as e:
                log.info(f"  提交异常: {e}")

            log.info(f"  提交后 URL: {driver.current_url}")
            if ("fofa.info" in driver.current_url and
                "login" not in driver.current_url.replace("f_login", "").lower()):
                log.info("  ✅ 登录成功")
                break
            log.info("  ❌ 登录失败")
            _save_debug(driver, "login_fail")
            time.sleep(1)

        # 确保在 fofa.info
        if "fofa.info" not in driver.current_url:
            driver.get("https://fofa.info/")
            time.sleep(5)

        # 搜索
        qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
        driver.get(f"https://fofa.info/result?qbase64={qbase64}")
        time.sleep(5)

        # 等数据加载
        page_source = ""
        for _ in range(15):
            page_source = driver.page_source
            if "hsxa-ip" in page_source or "hsxa-meta-data-item" in page_source:
                log.info("  ✅ 数据已加载")
                break
            time.sleep(2)
        else:
            log.info("  数据未加载")
            _save_debug(driver, "no_data")

    except Exception as e:
        log.error(f"异常: {e}")
        _save_debug(driver, "error")
        page_source = ""
    finally:
        try: driver.quit()
        except Exception: pass

    # 解析 IP
    ips = []
    if "hsxa-ip" in (page_source or ""):
        soup = BeautifulSoup(page_source, "html.parser")
        for div in soup.find_all("div", class_="hsxa-ip"):
            for a in div.find_all("a", class_="hsxa-jump-a"):
                if "display:none" in (a.get("style") or ""): continue
                t = a.get_text(strip=True)
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', t):
                    ips.append(t); break
    if not ips and page_source:
        f = re.findall(r'data-clipboard-text="https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', page_source)
        if f: ips = f
    ips = list(dict.fromkeys(ips))
    log.info(f"提取 {len(ips)} 个去重 IP")
    return ips


def fofa_search():
    """调度入口：Shodan > FOFA API > 浏览器"""
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


# ---------- CF / DNS / AbuseIPDB ----------
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
