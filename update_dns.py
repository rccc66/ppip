import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re, time, json, base64, logging, subprocess, requests, urllib3, urllib.parse
import shutil
import undetected_chromedriver as uc
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
    NoSuchElementException,
    StaleElementReferenceException,
)

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
# FOFA API：强烈推荐配置，绕过 Turnstile 浏览器登录
FOFA_API_KEY = os.getenv("FOFA_API_KEY", "")
# FOFA API 用的 qbase64 是 base64 编码后的查询，size 限制 100-10000
_fofa_api_size_raw = (os.getenv("FOFA_API_SIZE") or "").strip()
FOFA_API_SIZE = int(_fofa_api_size_raw) if _fofa_api_size_raw else 100
# 可选：如果 Turnstile 自动通过失败，用 2captcha 兜底
TWOCAPTCHA_API_KEY = os.getenv("TWOCAPTCHA_API_KEY", "")
FOFA_QUERY = ('server=="cloudflare" && header="Forbidden" && country=="US" && '
              'port="443" && (asn=="31898" || asn=="16509" || asn=="14618" || asn=="8075")')
PROXY_CHECK_URL = "https://check.proxyip.cmliussss.net"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
ABUSE_THRESHOLD = 20
LOGIN_PAGE = "https://i.nosec.org/login?locale=zh-CN&service=https://fofa.info/f_login"

# ---------- Chrome 驱动 ----------
def create_driver():
    """
    在 GitHub Actions / FORCE_PROXY 环境下强制 Chrome 走 SOCKS5 代理：
      - 配置了 SOCKS5_PROXY secret → 走 gost 桥接的 127.0.0.1:1080（住宅代理）
      - 没配置 SOCKS5_PROXY     → 直连 WARP 40000 端口（CF WARP 出口 IP）

    WARP 出口是 Cloudflare 自己的 IP 段，对 Turnstile 友好得多。
    """
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    # 关键：用 --lang=zh-CN 才能改 navigator.language；uc 默认是 en-US
    # 注意 uc 用 prefs 才能让 navigator.languages 也跟着变
    options.add_argument("--lang=zh-CN")
    options.add_argument("--disable-blink-features=AutomationControlled")
    # 增强：让 uc 指纹更接近真实浏览器
    options.add_argument("--disable-features=IsolateOrigins,site-per-process,AutomationControlled")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-notifications")
    options.add_argument("--start-maximized")
    # 真实 UA（避免 uc 默认 UA 被 CF 识别）
    options.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")
    # 启用 console 日志抓取（用于诊断 Turnstile 错误）
    options.add_argument("--enable-logging")
    options.add_argument("--log-level=0")
    options.add_argument("--v=0")
    options.set_capability("goog:loggingPrefs", {"browser": "ALL", "driver": "ALL"})

    # 关键：用 prefs 让 navigator.languages 真正变成 zh-CN
    # 这是 CF 指纹检测的关键之一——UA 说 zh-CN 但 navigator.languages 是 en-US 就露馅
    prefs = {
        "intl.accept_languages": "zh-CN,zh",
        "intl.notification_locale": "zh-CN",
    }
    options.add_experimental_option("prefs", prefs)

    # 关键：代理设置（仿照 Hohai 脚本 v6 策略）
    if os.getenv("GITHUB_ACTIONS") or os.getenv("FORCE_PROXY"):
        if os.getenv("SOCKS5_PROXY"):
            proxy_addr = "socks5://127.0.0.1:1080"
        else:
            proxy_addr = "socks5://127.0.0.1:40000"
        options.add_argument(f"--proxy-server={proxy_addr}")
        log.info(f"🌐 已配置 Chrome 走 SOCKS5 代理: {proxy_addr}")
    elif os.getenv("SOCKS5_PROXY"):
        options.add_argument("--proxy-server=socks5://127.0.0.1:1080")
        log.info("🌐 已配置 Chrome 走 SOCKS5 代理: 127.0.0.1:1080")

    headless_mode = False  # 配合 xvfb-run

    browser_path = (shutil.which("google-chrome")
                    or shutil.which("google-chrome-stable")
                    or shutil.which("chromium-browser")
                    or shutil.which("chromium"))

    detected_version = None
    if browser_path:
        try:
            out = subprocess.check_output([browser_path, "--version"], text=True).strip()
            detected_version = int(out.split()[-1].split(".")[0])
            log.info(f"锁定浏览器路径: {browser_path}, 版本号: {detected_version}")
        except Exception as e:
            log.info(f"获取版本失败: {e}")

    driver = uc.Chrome(
        options=options,
        browser_executable_path=browser_path,
        version_main=detected_version,
        headless=headless_mode,
    )
    driver.implicitly_wait(5)

    # 关键反检测：在每个新页面加载前注入 JS，修补指纹矛盾
    # 这比 Chrome args 更彻底，因为 args 改不了 navigator.languages
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": """
                // 1) 修补 navigator.languages（CF 检测 UA 说 zh-CN 但 languages 是 en-US）
                try {
                    Object.defineProperty(navigator, 'languages', {
                        get: function() { return ['zh-CN', 'zh', 'en-US', 'en']; }
                    });
                    Object.defineProperty(navigator, 'language', {
                        get: function() { return 'zh-CN'; }
                    });
                } catch(e) {}

                // 2) 修补 navigator.platform（与 UA 的 Linux x86_64 一致）
                try {
                    Object.defineProperty(navigator, 'platform', {
                        get: function() { return 'Linux x86_64'; }
                    });
                } catch(e) {}

                // 3) 彻底清除 webdriver 标志（uc 已部分做了，但再保险一次）
                try {
                    Object.defineProperty(navigator, 'webdriver', {
                        get: function() { return undefined; }
                    });
                } catch(e) {}

                // 4) 修补 navigator.plugins（CF 检测空 plugins 数组=自动化）
                try {
                    Object.defineProperty(navigator, 'plugins', {
                        get: function() {
                            return [
                                {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer',
                                 description: 'Portable Document Format'},
                                {name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer',
                                 description: ''},
                                {name: 'Native Client', filename: 'internal-nacl-plugin',
                                 description: ''}
                            ];
                        }
                    });
                } catch(e) {}

                // 5) 修补 navigator.permissions.query（CF 检测自动化会返回异常）
                try {
                    var origQuery = window.navigator.permissions.query;
                    window.navigator.permissions.query = function(params) {
                        if (params && params.name === 'notifications') {
                            return Promise.resolve({state: Notification.permission});
                        }
                        return origQuery.call(window.navigator.permissions, params);
                    };
                } catch(e) {}

                // 6) 修补 window.chrome（uc 缺这个对象，CF 检测 chrome.runtime 是否存在）
                try {
                    if (!window.chrome) {
                        window.chrome = {};
                    }
                    if (!window.chrome.runtime) {
                        window.chrome.runtime = {
                            PlatformOs: {MAC: 'mac', WIN: 'win', ANDROID: 'android', CROS: 'cros',
                                         LINUX: 'linux', OPENBSD: 'openbsd'},
                            PlatformArch: {ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64'},
                            PlatformNaclArch: {ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64'},
                            connect: function() {},
                            sendMessage: function() {}
                        };
                    }
                    if (!window.chrome.csi) {
                        window.chrome.csi = function() { return {}; };
                    }
                    if (!window.chrome.loadTimes) {
                        window.chrome.loadTimes = function() {
                            return {
                                commitLoadTime: Date.now() / 1000 - 5,
                                connectionInfo: 'h2',
                                finishDocumentLoadTime: Date.now() / 1000 - 3,
                                finishLoadTime: Date.now() / 1000 - 2,
                                firstPaintAfterLoadTime: 0,
                                firstPaintTime: Date.now() / 1000 - 4,
                                navigationType: 'Other',
                                npnNegotiatedProtocol: 'h2',
                                requestTime: Date.now() / 1000 - 6,
                                startLoadTime: Date.now() / 1000 - 6,
                                wasAlternateProtocolAvailable: false,
                                wasFetchedViaSpdy: true,
                                wasNpnNegotiated: true
                            };
                        };
                    }
                } catch(e) {}

                // 7) WebGL Vendor/Renderer 修补（CF 检测 SwiftShader=自动化）
                try {
                    var getParameter = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = function(param) {
                        if (param === 37445) return 'Intel Inc.';          // UNMASKED_VENDOR_WEBGL
                        if (param === 37446) return 'Intel Iris OpenGL Engine'; // UNMASKED_RENDERER_WEBGL
                        return getParameter.call(this, param);
                    };
                } catch(e) {}
            """}
        )
        log.info("✅ 已注入反指纹检测脚本")
    except Exception as e:
        log.warning(f"⚠️  反指纹脚本注入失败: {e}")

    # 启用 console log 抓取（用于诊断 Turnstile 错误）
    try:
        driver.execute_cdp_cmd(
            "Browser.grantPermissions",
            {"permissions": ["notifications"]},
        )
    except Exception:
        pass
    try:
        driver.set_log_level("INFO")  # 不一定都支持
    except Exception:
        pass

    # 启动后验证代理是否真的工作
    if os.getenv("GITHUB_ACTIONS") or os.getenv("FORCE_PROXY"):
        _verify_proxy_working(driver)

    return driver


def _verify_proxy_working(driver):
    """启动后验证代理确实工作，并打印出口 IP（仿 Hohai 脚本）。"""
    try:
        driver.set_page_load_timeout(20)
        driver.get("https://api.ipify.org?format=text")
        time.sleep(2)
        body = driver.find_element(By.TAG_NAME, "body").text.strip()
        log.info(f"🌐 Chrome 出口 IP (经代理): {body}")

        try:
            direct = subprocess.check_output(
                ["curl", "-4", "-s", "--max-time", "5", "https://api.ipify.org"],
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            log.info(f"🌐 系统直连 IP: {direct}")

            if direct and body and direct == body:
                log.warning("⚠️  警告: Chrome 出口 IP 与系统直连 IP 相同, 代理可能未生效!")
            else:
                log.info("✅ 代理已生效, Chrome 出口 IP 与直连不同")
        except Exception:
            pass
    except Exception as e:
        log.error(f"❌ 代理验证失败: {e}")


# ---------- 调试工具 ----------
def _save_debug(driver, tag):
    try:
        driver.save_screenshot(f"debug_{tag}_{int(time.time())}.png")
    except Exception:
        pass
    try:
        html = driver.page_source or ""
        with open(f"debug_{tag}_{int(time.time())}.html", "w", encoding="utf-8") as f:
            f.write(html)
    except Exception:
        pass


# ---------- Cloudflare Turnstile 处理 ----------
def _submit_button_enabled(driver):
    """提交按钮初始 disabled，onTurnstileSuccess 后会移除 disabled 属性。"""
    try:
        btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
        return btn.is_enabled() and not btn.get_attribute("disabled")
    except NoSuchElementException:
        return False
    except WebDriverException:
        return False


def _solve_turnstile_with_2captcha(driver, log, sitekey, page_url):
    """2captcha 兜底解 Turnstile。成功返回 token，失败返回 None。"""
    if not TWOCAPTCHA_API_KEY:
        log.info("  未配置 TWOCAPTCHA_API_KEY，跳过外部打码")
        return None
    log.info(f"  提交 2captcha 任务 (sitekey={sitekey}, url={page_url})")
    try:
        resp = requests.post(
            "https://2captcha.com/in.php",
            data={
                "key": TWOCAPTCHA_API_KEY,
                "method": "turnstile",
                "sitekey": sitekey,
                "pageurl": page_url,
                "json": 1,
            },
            timeout=30,
        )
        data = resp.json()
        if data.get("status") != 1:
            log.info(f"  2captcha 提交失败: {data}")
            return None
        task_id = data["request"]
        log.info(f"  2captcha 任务 ID: {task_id}")

        for _ in range(30):
            time.sleep(5)
            r = requests.get(
                "https://2captcha.com/res.php",
                params={"key": TWOCAPTCHA_API_KEY, "action": "get", "id": task_id, "json": 1},
                timeout=30,
            )
            d = r.json()
            if d.get("status") == 1:
                log.info("  2captcha 解出 token")
                return d["request"]
            if d.get("request") != "CAPCHA_NOT_READY":
                log.info(f"  2captcha 失败: {d}")
                return None
        log.info("  2captcha 超时")
        return None
    except Exception as e:
        log.info(f"  2captcha 异常: {type(e).__name__}: {str(e)[:200]}")
        return None


def _inject_turnstile_token(driver, token):
    """把外部打码拿到的 token 注入页面并触发回调启用提交按钮。"""
    try:
        # Turnstile 默认会创建一个名为 cf-turnstile-response 的隐藏 input
        driver.execute_script("""
            var input = document.querySelector('input[name="cf-turnstile-response"]');
            if (!input) {
                input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'cf-turnstile-response';
                document.querySelector('form#login-form').appendChild(input);
            }
            input.value = arguments[0];
            if (typeof window.onTurnstileSuccess === 'function') {
                window.onTurnstileSuccess();
            }
        """, token)
        return True
    except Exception as e:
        log.info(f"  注入 token 失败: {type(e).__name__}: {str(e)[:200]}")
        return False


def _click_turnstile_checkbox(driver, log):
    """
    物理点击 Turnstile iframe（仿 Hohai 脚本策略）。
    不再纠结找具体的 checkbox 元素，而是：
      1) 在主文档里扫所有 iframe，按 src 过滤出 Cloudflare 的
      2) 切入后用 ActionChains 物理移动鼠标到 body 并点击
      3) 轮询主文档里 Turnstile widget 的状态 div 判断结果

    返回 (success: bool, status: str)
      status ∈ {"success", "verifying_timeout", "failed", "expired",
                "no_iframe", "click_error"}
    """
    # 1) 扫描所有 iframe，找 Cloudflare Turnstile 的那个
    # FOFA 的 iframe 在 widget 外层，且 id 形如 cf-chl-widget-XXX
    target_iframe = None
    try:
        all_iframes = driver.find_elements(By.TAG_NAME, "iframe")
        log.info(f"  页面 iframe 总数: {len(all_iframes)}")
        for i, f in enumerate(all_iframes):
            try:
                src = (f.get_attribute("src") or "").lower()
                fid = f.get_attribute("id") or ""
                if not src and not fid:
                    continue
                # 三种识别条件（任一命中即视为 CF iframe）
                is_cf = (
                    "cloudflare" in src
                    or "challenges" in src
                    or "turnstile" in src
                    or fid.startswith("cf-chl-widget")
                )
                if is_cf:
                    target_iframe = f
                    try:
                        displayed = f.is_displayed()
                        size = f.size
                    except Exception:
                        displayed = True
                        size = {}
                    log.info(f"  锁定 CF iframe #{i}: id={fid}, "
                             f"src={src[:80]}, displayed={displayed}, "
                             f"size={size.get('width', '?')}x{size.get('height', '?')}")
                    break
            except StaleElementReferenceException:
                continue
            except Exception as e:
                log.info(f"  扫描 iframe #{i} 异常: {type(e).__name__}: {str(e)[:100]}")
                continue

        # 兜底：.cf-turnstile 容器内的任意 iframe
        if target_iframe is None:
            try:
                container = driver.find_element(By.CSS_SELECTOR, "div.cf-turnstile")
                inner_iframes = container.find_elements(By.TAG_NAME, "iframe")
                if inner_iframes:
                    target_iframe = inner_iframes[0]
                    log.info(f"  在 .cf-turnstile 容器内找到 iframe ({len(inner_iframes)} 个)")
            except Exception:
                pass
    except Exception as e:
        log.info(f"  扫描 iframe 异常: {type(e).__name__}: {str(e)[:200]}")

    if target_iframe is None:
        log.info("  未找到 Turnstile iframe")
        _save_debug(driver, "no_iframe")
        return False, "no_iframe"

    # 2) 切入 iframe，用 ActionChains 物理点击 body
    try:
        driver.switch_to.frame(target_iframe)
        box = driver.find_element(By.CSS_SELECTOR, "body")
        # 关键：用 ActionChains 物理移动鼠标并点击，模拟真人
        ActionChains(driver).move_to_element(box).click().perform()
        log.info("  👉 已用 ActionChains 物理点击 CF iframe body")
    except Exception as e:
        log.info(f"  物理点击失败: {type(e).__name__}: {str(e)[:200]}")
        _save_debug(driver, "click_error")
        return False, "click_error"
    finally:
        try:
            driver.switch_to.default_content()
        except Exception:
            pass

    # 3) 轮询主文档里的 Turnstile 状态 div（最多 30s）
    # FOFA 的 Turnstile widget 用 div.JrdWD7 包裹各种状态文案
    for _ in range(15):
        time.sleep(2)
        try:
            state_divs = driver.find_elements(By.CSS_SELECTOR, "div.JrdWD7")
            for div in state_divs:
                try:
                    style = div.get_attribute("style") or ""
                    style_norm = style.replace(" ", "")
                    if "display:none" in style_norm or "visibility:hidden" in style_norm:
                        continue
                    text = (div.text or "").strip()
                    if not text:
                        continue
                    if "成功" in text:
                        log.info(f"  Turnstile 状态: 成功 ({text})")
                        return True, "success"
                    if "失败" in text:
                        log.info(f"  Turnstile 状态: 失败 ({text})")
                        return False, "failed"
                    if "过期" in text:
                        log.info(f"  Turnstile 状态: 过期 ({text})")
                        return False, "expired"
                    # "正在验证…" 等继续等
                except StaleElementReferenceException:
                    continue
                except Exception:
                    continue
        except Exception:
            pass

        # 兜底：如果状态 div 没找到，但提交按钮已经启用了，也算成功
        if _submit_button_enabled(driver):
            log.info("  Turnstile 状态: 提交按钮已启用 (视为成功)")
            return True, "success"

    log.info("  点击后状态轮询超时（30s 内未到终态）")
    return False, "verifying_timeout"


def _refresh_turnstile(driver, log):
    """点击刷新链接（验证失败/过期时）。"""
    try:
        # 先在主文档找
        refresh_links = driver.find_elements(By.CSS_SELECTOR, "a[href='#refresh']")
        if refresh_links:
            driver.execute_script("arguments[0].click();", refresh_links[0])
            log.info("  已点击刷新链接")
            time.sleep(2)
            return True
    except Exception:
        pass
    return False


def handle_turnstile(driver, log, auto_timeout=45, max_click_retries=3):
    """
    FOFA 登录页使用 Cloudflare Turnstile 替代图片验证码。
    实测发现：FOFA 页面 render 后 widget 内会创建 div + input，但 iframe 不一定出现。
    新策略：
      1) 等 .cf-turnstile 容器出现
      2) 等 window.turnstile api.js 加载完成
      3) 检查 widget 内部状态（iframe 数 + token value）
      4) 如果 iframe=0 且 token 空，主动调 turnstile.reset() / render() 强制重启
      5) 监听 cf-turnstile-response 的 value 变化（最可靠的成功信号）
      6) 兜底 A：ActionChains 物理点击 iframe
      7) 兜底 B：2captcha 外部打码
    """
    # 1) 等待 Turnstile 容器 div 出现
    try:
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.cf-turnstile"))
        )
    except TimeoutException:
        log.info("  未找到 Turnstile 容器 div.cf-turnstile")
        _save_debug(driver, "no_turnstile_div")
        return False

    # 2) 等 window.turnstile 加载
    log.info("  等待 window.turnstile api.js 加载 (最多 15s)...")
    turnstile_loaded = False
    for _ in range(15):
        try:
            loaded = driver.execute_script(
                "return typeof window.turnstile !== 'undefined' && window.turnstile !== null;"
            )
            if loaded:
                turnstile_loaded = True
                log.info("  ✅ window.turnstile 已加载")
                break
        except Exception:
            pass
        time.sleep(1)
    if not turnstile_loaded:
        log.info("  ❌ window.turnstile 未加载，可能 api.js 被拦或网络异常")
        _save_debug(driver, "no_turnstile_api")

    # 3) 取 sitekey 和 page_url
    sitekey = None
    page_url = driver.current_url
    try:
        div = driver.find_element(By.CSS_SELECTOR, "div.cf-turnstile")
        sitekey = div.get_attribute("data-sitekey")
    except Exception:
        pass
    log.info(f"  Turnstile sitekey={sitekey}, page={page_url}")

    # 4) 检查 widget 当前状态（全文档扫描 iframe）
    def _get_widget_state():
        try:
            return driver.execute_script("""
                var widget = document.querySelector('div.cf-turnstile');
                if (!widget) return {found: false};

                // 全文档扫描 CF iframe（FOFA 的 iframe 不一定在 widget 内）
                var allIframes = document.querySelectorAll('iframe');
                var cfIframes = [];
                var cfIframeIds = [];
                var cfIframeVisible = [];
                for (var i = 0; i < allIframes.length; i++) {
                    var f = allIframes[i];
                    var src = (f.src || '').toLowerCase();
                    var id = f.id || '';
                    if (src.indexOf('cloudflare') >= 0
                        || src.indexOf('challenges') >= 0
                        || src.indexOf('turnstile') >= 0
                        || id.indexOf('cf-chl-widget') === 0) {
                        cfIframes.push(src.substring(0, 100));
                        cfIframeIds.push(id);
                        try {
                            cfIframeVisible.push(f.offsetWidth > 0 && f.offsetHeight > 0);
                        } catch(e) {
                            cfIframeVisible.push(true);
                        }
                    }
                }

                // 也扫描 widget 内部
                var widgetIframes = widget.querySelectorAll('iframe');

                // token input 可能在 widget 内，也可能在 form 里
                var inputs = document.querySelectorAll('input[name="cf-turnstile-response"]');
                var inputValue = inputs.length > 0 ? (inputs[0].value || '') : '';

                // 提交按钮状态
                var btn = document.querySelector('button[type="submit"]');
                var btnDisabled = btn ? btn.disabled : true;

                return {
                    found: true,
                    widgetIframeCount: widgetIframes.length,
                    cfIframeCount: cfIframes.length,
                    cfIframeSrcs: cfIframes,
                    cfIframeIds: cfIframeIds,
                    cfIframeVisible: cfIframeVisible,
                    totalIframes: allIframes.length,
                    tokenValue: inputValue,
                    tokenLength: inputValue.length,
                    btnDisabled: btnDisabled
                };
            """)
        except Exception as e:
            log.info(f"  获取 widget 状态异常: {type(e).__name__}: {str(e)[:200]}")
            return {"found": False}

    state = _get_widget_state()
    log.info(f"  widget 初始状态: {state}")

    # 4.5) 关键诊断：如果初始状态就是无 iframe 无 token，立刻保存截图+HTML+JS console
    if (state.get("cfIframeCount", 0) == 0
            and state.get("widgetIframeCount", 0) == 0
            and not state.get("tokenValue")):
        log.info("  ⚠️  初始就无 iframe 无 token, 保存诊断现场...")
        _save_debug(driver, "initial_no_widget")

        # 额外打印页面上所有 iframe 的完整信息（用 JS）
        try:
            all_iframes_info = driver.execute_script("""
                var iframes = document.querySelectorAll('iframe');
                var info = [];
                for (var i = 0; i < iframes.length; i++) {
                    var f = iframes[i];
                    info.push({
                        index: i,
                        id: f.id || '',
                        name: f.name || '',
                        src: (f.src || '').substring(0, 200),
                        width: f.offsetWidth,
                        height: f.offsetHeight,
                        visible: f.offsetWidth > 0 && f.offsetHeight > 0,
                        parentId: f.parentElement ? f.parentElement.id : '',
                        parentClass: f.parentElement ? f.parentElement.className : ''
                    });
                }
                return info;
            """)
            log.info(f"  📋 页面所有 iframe 详情: {all_iframes_info}")
        except Exception as e:
            log.info(f"  获取 iframe 详情失败: {e}")

        # 检查 navigator.webdriver 等关键指纹
        try:
            fingerprint = driver.execute_script("""
                return {
                    webdriver: navigator.webdriver,
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    languages: navigator.languages,
                    cookieEnabled: navigator.cookieEnabled,
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    deviceMemory: navigator.deviceMemory,
                    maxTouchPoints: navigator.maxTouchPoints,
                    vendor: navigator.vendor,
                    hasCDP: typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Array !== 'undefined'
                         || typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Promise !== 'undefined'
                         || typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol !== 'undefined',
                    turnstileExists: typeof window.turnstile !== 'undefined',
                    turnstileRenderExists: !!(window.turnstile && window.turnstile.render),
                    turnstileResetExists: !!(window.turnstile && window.turnstile.reset),
                    turnstileGetResponseExists: !!(window.turnstile && window.turnstile.getResponse),
                    widgetInnerHTML: (document.querySelector('div.cf-turnstile') || {}).innerHTML || '',
                    documentTitle: document.title,
                    documentReadyState: document.readyState
                };
            """)
            log.info(f"  🔍 浏览器指纹 & Turnstile API 状态:")
            for k, v in fingerprint.items():
                if k == 'widgetInnerHTML':
                    log.info(f"     {k}: {str(v)[:200]}")
                else:
                    log.info(f"     {k}: {v}")
        except Exception as e:
            log.info(f"  获取指纹失败: {e}")

        # 检查浏览器 console 日志
        try:
            logs = driver.get_log("browser")
            if logs:
                log.info(f"  📜 浏览器 console 日志 (最近 20 条):")
                for entry in logs[-20:]:
                    log.info(f"     [{entry.get('level', '?')}] {entry.get('message', '')[:200]}")
        except Exception:
            pass

    # 5) 如果 iframe 已存在但 token 还没生成，**不要 reset**（reset 会破坏已渲染的 iframe）
    #    只在确实没有 iframe 且没有 token 时才尝试强制重新 render
    if (state.get("cfIframeCount", 0) == 0
            and state.get("widgetIframeCount", 0) == 0
            and not state.get("tokenValue")):
        log.info("  全文档无 CF iframe 且无 token, 强制重新 render widget...")

        # 关键：FOFA 用 Turbolinks 加载页面，第二次访问时 api.js 已缓存但 widget 是新的，
        # api.js 不会自动 render 新 widget（console 会报 "Cannot find Widget" 警告）。
        # 必须先用 turnstile.remove() 清理掉旧 widget ID，再调 turnstile.render() 用 DOM 节点
        # （而不是 widgetId）作为参数，让 api.js 重新绑定。
        render_result = driver.execute_script("""
            try {
                var widget = document.querySelector('div.cf-turnstile');
                if (!widget) return 'no_widget';
                if (!window.turnstile) return 'no_turnstile_api';
                if (!window.turnstile.render) return 'no_render_api';

                // 1) 用 turnstile.remove() 清理所有旧 widget（如果有 API）
                if (window.turnstile.remove) {
                    var inputs = document.querySelectorAll('input[id^="cf-chl-widget-"]');
                    for (var i = 0; i < inputs.length; i++) {
                        var oldId = inputs[i].id.replace('_response', '');
                        try { window.turnstile.remove(oldId); } catch(e) {}
                    }
                }

                // 2) 保留 widget 容器，清空内部 DOM（让 api.js 重建）
                widget.innerHTML = '';

                // 3) 用 DOM 节点直接调 render（不要用 widgetId）
                var sitekey = widget.getAttribute('data-sitekey');
                var action = widget.getAttribute('data-action');

                var newWidgetId = window.turnstile.render(widget, {
                    sitekey: sitekey,
                    action: action,
                    'error-callback': function() {
                        if (typeof window.onTurnstileExpired === 'function') {
                            window.onTurnstileExpired();
                        }
                    },
                    'expired-callback': function() {
                        if (typeof window.onTurnstileExpired === 'function') {
                            window.onTurnstileExpired();
                        }
                    },
                    callback: function(token) {
                        var input = document.querySelector('input[name="cf-turnstile-response"]');
                        if (!input) {
                            input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = 'cf-turnstile-response';
                            var form = document.querySelector('form#login-form');
                            if (form) form.appendChild(input);
                        }
                        input.value = token;
                        if (typeof window.onTurnstileSuccess === 'function') {
                            window.onTurnstileSuccess();
                        }
                    }
                });
                return 'render_ok: ' + newWidgetId;
            } catch(e) {
                return 'error: ' + e.message + ' | stack: ' + (e.stack || '').substring(0, 300);
            }
        """)
        log.info(f"  强制 render 结果: {render_result}")

        # render 后等 iframe 出现
        log.info("  等待 CF iframe 渲染 (最多 25s)...")
        for i in range(25):
            time.sleep(1)
            state = _get_widget_state()
            if state.get("cfIframeCount", 0) > 0 or state.get("tokenValue"):
                log.info(f"  ✅ iframe 已出现 / token 已生成 (等了 {i+1}s)")
                break
        log.info(f"  render 后 widget 状态: {state}")

        # 如果还是没 iframe，再打印一次 console 看具体错误
        if state.get("cfIframeCount", 0) == 0 and not state.get("tokenValue"):
            log.info("  render 后仍无 iframe, 抓取 console 日志诊断...")
            try:
                logs = driver.get_log("browser")
                if logs:
                    # 只打印新的日志（含 turnstile/cf 关键字的）
                    recent = logs[-30:]
                    for entry in recent:
                        msg = entry.get('message', '')
                        if any(kw in msg.lower() for kw in
                               ['turnstile', 'cloudflare', 'cf-chl', 'challenge', 'error']):
                            log.info(f"     [{entry.get('level', '?')}] {msg[:300]}")
            except Exception:
                pass
            _save_debug(driver, "render_failed")

    # 6) 主策略：监听 token + 按钮，最多 auto_timeout 秒
    log.info(f"  等待 Turnstile 自动通过 (最多 {auto_timeout}s)...")
    deadline = time.time() + auto_timeout
    last_log_time = time.time()
    while time.time() < deadline:
        # 检查 token
        try:
            token = driver.execute_script(
                "var i = document.querySelector('input[name=\"cf-turnstile-response\"]');"
                "return i ? i.value : '';"
            )
        except Exception:
            token = ""

        if token and len(token) > 10:
            log.info(f"  ✅ Turnstile token 已生成 (长度 {len(token)})")
            try:
                btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                driver.execute_script("arguments[0].disabled = false;", btn)
                log.info("  ✅ 已强制启用提交按钮")
            except Exception:
                pass
            return True

        if _submit_button_enabled(driver):
            log.info("  ✅ 提交按钮已启用 (onTurnstileSuccess 已触发)")
            return True

        # 每 5s 打印一次状态
        if time.time() - last_log_time > 5:
            cur_state = _get_widget_state()
            elapsed = int(time.time() - (deadline - auto_timeout))
            log.info(f"  [{elapsed}s] token_len={cur_state.get('tokenLength', 0)}, "
                     f"cf_iframe={cur_state.get('cfIframeCount', 0)}, "
                     f"total_iframes={cur_state.get('totalIframes', 0)}, "
                     f"btn_disabled={cur_state.get('btnDisabled', True)}")
            last_log_time = time.time()

        time.sleep(1)

    log.info(f"  Turnstile 自动通过超时 ({auto_timeout}s)")

    # 7) 兜底 A：ActionChains 点击 CF iframe
    state = _get_widget_state()
    if state.get("cfIframeCount", 0) > 0 or state.get("totalIframes", 0) > 0:
        log.info("  尝试 ActionChains 物理点击 CF iframe...")
        for attempt in range(1, max_click_retries + 1):
            log.info(f"  尝试点击 Turnstile (第 {attempt}/{max_click_retries} 次)...")
            clicked, status = _click_turnstile_checkbox(driver, log)

            if status == "success":
                log.info("  ✅ 点击后 Turnstile 通过")
                try:
                    WebDriverWait(driver, 5).until(_submit_button_enabled)
                    return True
                except TimeoutException:
                    log.info("  Turnstile 通过但按钮未启用，JS 强制启用")
                    try:
                        btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                        driver.execute_script("arguments[0].disabled = false;", btn)
                        return True
                    except Exception:
                        pass

            if status in ("failed", "expired"):
                _refresh_turnstile(driver, log)
                continue
            if status == "no_iframe":
                time.sleep(3)
                continue
            if status == "verifying_timeout":
                _refresh_turnstile(driver, log)
                time.sleep(2)
                continue
            _save_debug(driver, f"click_{status}")
            time.sleep(2)
    else:
        log.info("  页面无 iframe, 跳过 ActionChains 点击")

    # 8) 兜底 B：2captcha 外部打码
    if sitekey and TWOCAPTCHA_API_KEY:
        token = _solve_turnstile_with_2captcha(driver, log, sitekey, page_url)
        if token:
            if _inject_turnstile_token(driver, token):
                try:
                    WebDriverWait(driver, 5).until(_submit_button_enabled)
                    log.info("  ✅ 2captcha token 注入后提交按钮已启用")
                    return True
                except TimeoutException:
                    log.info("  token 已注入但按钮未启用，尝试直接提交")
                    return True
    elif not TWOCAPTCHA_API_KEY:
        log.info("  未配置 TWOCAPTCHA_API_KEY，跳过外部打码")

    log.info("  ❌ Turnstile 验证未通过")
    _save_debug(driver, "turnstile_final_fail")
    return False


# ---------- FOFA API（推荐路径，绕过 Turnstile） ----------
def fofa_search_via_api():
    """
    通过 FOFA API 直接搜索，无需浏览器、无需解 Turnstile。
    FOFA API 文档：https://fofa.info/api/api_pages
    接口：/api/v1/search/all
    """
    if not FOFA_API_KEY:
        log.info("未配置 FOFA_API_KEY，跳过 API 模式")
        return []

    log.info("===== 使用 FOFA API 搜索 IP =====")
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    url = "https://fofa.info/api/v1/search/all"
    # 免费版只支持基础字段。as_organization、asn 等需要付费会员
    params = {
        "email": FOFA_EMAIL,
        "key": FOFA_API_KEY,
        "qbase64": qbase64,
        "size": FOFA_API_SIZE,
        "fields": "ip,port,server,country",
    }
    log.info(f"API 请求: {url} (qbase64 长度={len(qbase64)}, size={FOFA_API_SIZE})")

    try:
        resp = requests.get(url, params=params, timeout=30, verify=True)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.error(f"❌ FOFA API 请求异常: {type(e).__name__}: {str(e)[:300]}")
        return []

    if data.get("error"):
        err_msg = data.get('errmsg', data.get('error'))
        log.error(f"❌ FOFA API 返回错误: {err_msg}")
        # 常见错误码提示
        err_str = str(err_msg)
        if "820001" in err_str:
            log.error("  → 提示: 字段权限不足，免费版只支持 ip/port/server/country 等基础字段")
        elif "820000" in err_str:
            log.error("  → 提示: 账号无 API 权限或 key 错误")
        elif "820002" in err_str or "820003" in err_str:
            log.error("  → 提示: API 调用次数耗尽或会员到期")
        elif "820200" in err_str:
            log.error("  → 提示: 查询语句语法错误")
        return []

    results = data.get("results", [])
    log.info(f"✅ FOFA API 返回 {len(results)} 条结果")

    ips = []
    for item in results:
        if isinstance(item, dict):
            ip = item.get("ip") or item.get("host") or ""
        else:
            # 旧版 API 返回列表形式 [ip, port, ...]
            ip = item[0] if item else ""
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
            ips.append(str(ip))

    ips = list(dict.fromkeys(ips))
    log.info(f"提取到 {len(ips)} 个去重 IP")
    return ips


# ---------- FOFA 搜索（浏览器版，作为 fallback） ----------
def fofa_search_via_browser():
    """原浏览器自动化流程，作为 API 不可用时的 fallback。"""
    driver = create_driver()
    ips = []

    try:
        # ===== 登录（最多 3 次） =====
        for attempt in range(3):
            log.info(f"登录尝试 {attempt + 1}/3 ...")
            # 重置 page_load_timeout（_verify_proxy_working 设成了 20s，这里放宽）
            try:
                driver.set_page_load_timeout(60)
            except Exception:
                pass

            driver.get(LOGIN_PAGE)

            # 等 document.readyState=complete
            try:
                WebDriverWait(driver, 30).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
            except TimeoutException:
                log.info("  页面 readyState 超时，继续")

            # 等 Turnstile api.js 加载（关键！readyState=complete 不代表 api.js 已加载）
            log.info("  等 Turnstile api.js 加载...")
            api_js_ready = False
            for _ in range(15):
                try:
                    if driver.execute_script(
                        "return typeof window.turnstile !== 'undefined' && window.turnstile !== null;"
                    ):
                        api_js_ready = True
                        log.info("  ✅ Turnstile api.js 已加载")
                        break
                except Exception:
                    pass
                time.sleep(1)
            if not api_js_ready:
                log.info("  ❌ Turnstile api.js 加载失败")
                _save_debug(driver, "no_turnstile_api")

            # 再等 2-3s 让 api.js 完成 widget render
            time.sleep(3)

            if "fofa.info" in driver.current_url and "login" not in driver.current_url.lower():
                log.info("  ✅ 已登录")
                break

            # 填用户名密码
            try:
                username_input = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "username"))
                )
                username_input.clear()
                username_input.send_keys(FOFA_EMAIL)

                password_input = driver.find_element(By.NAME, "password")
                password_input.clear()
                password_input.send_keys(FOFA_PASSWORD)
            except TimeoutException:
                log.info("  找不到登录表单")
                _save_debug(driver, "no_login_form")
                continue

            # 处理 Cloudflare Turnstile（替代原图片验证码）
            # auto_timeout=45 给充足时间让 iframe 加载完 + 自动通过
            if not handle_turnstile(driver, log, auto_timeout=45):
                time.sleep(1)
                continue

            # 勾选服务协议
            try:
                checkbox = driver.find_element(By.ID, "fofa_service")
                if not checkbox.is_selected():
                    driver.execute_script("arguments[0].click();", checkbox)
            except Exception:
                pass

            # 提交
            try:
                submit_btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                # JS 强制启用，万一 onTurnstileSuccess 没触发但 token 已注入
                driver.execute_script("arguments[0].disabled = false;", submit_btn)
                submit_btn.click()
                time.sleep(5)
            except Exception as e:
                log.info(f"  提交异常: {type(e).__name__}: {str(e)[:200]}")

            log.info(f"  提交后 URL: {driver.current_url}")

            if ("fofa.info" in driver.current_url and
                "login" not in driver.current_url.replace("f_login", "").lower()):
                log.info("  ✅ 登录成功")
                break

            if "i.nosec.org" in driver.current_url:
                log.info("  ❌ 登录失败（账号密码错误？或 Turnstile token 被拒）")
                _save_debug(driver, "login_fail")
                time.sleep(1)

        # ===== 确保在 fofa.info 页面 =====
        if "f_login" in driver.current_url:
            driver.get("https://fofa.info/")
            time.sleep(5)

        if "fofa.info" not in driver.current_url:
            driver.get("https://fofa.info/")
            time.sleep(3)

        log.info(f"当前 URL: {driver.current_url}")

        # ===== 搜索方式 1：URL 直接跳转 =====
        qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
        search_url = f"https://fofa.info/result?qbase64={qbase64}"
        log.info(f"访问搜索页: {search_url}")
        driver.get(search_url)
        time.sleep(5)

        loaded = False
        for wait_round in range(15):
            page_source = driver.page_source
            if "hsxa-ip" in page_source or "hsxa-meta-data-item" in page_source:
                log.info(f"  数据已加载 (等待 {(wait_round + 1) * 2}s)")
                loaded = True
                break
            time.sleep(2)

        # ===== 搜索方式 2：搜索框 =====
        if not loaded:
            log.info("  URL 方式未加载数据，尝试搜索框...")
            driver.save_screenshot("url_method_failed.png")

            search_selectors = [
                ('textarea[data-testid="result-search-input"]',
                 'span[data-testid="result-search-submit"] button'),
                ('textarea[data-testid="home-search-input"]',
                 'span[data-testid="home-search-submit"] button'),
            ]

            for textarea_sel, btn_sel in search_selectors:
                try:
                    search_textarea = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, textarea_sel))
                    )
                    driver.execute_script("arguments[0].value = '';", search_textarea)
                    search_textarea.click()
                    time.sleep(0.5)
                    driver.execute_script(
                        "arguments[0].value = arguments[1]; "
                        "arguments[0].dispatchEvent(new Event('input', {bubbles: true}));",
                        search_textarea, FOFA_QUERY
                    )
                    time.sleep(1)

                    search_btn = driver.find_element(By.CSS_SELECTOR, btn_sel)
                    search_btn.click()
                    log.info(f"  点击搜索按钮: {btn_sel}")
                    time.sleep(5)

                    for wait_round in range(15):
                        page_source = driver.page_source
                        if "hsxa-ip" in page_source or "hsxa-meta-data-item" in page_source:
                            log.info("  搜索框方式数据已加载")
                            loaded = True
                            break
                        time.sleep(2)

                    if loaded:
                        break
                except Exception as e:
                    log.info(f"  搜索框 {textarea_sel} 失败: {e}")
                    driver.get("https://fofa.info/")
                    time.sleep(3)
                    continue

        page_source = driver.page_source
        log.info(f"页面长度: {len(page_source)}, URL: {driver.current_url}")

        if not loaded:
            driver.save_screenshot("no_data.png")
            log.info("所有搜索方式均未加载数据")

    except Exception as e:
        log.error(f"异常: {e}")
        try:
            driver.save_screenshot("error.png")
        except:
            pass
        page_source = ""
    finally:
        try:
            driver.quit()
        except:
            pass

    # ----- 解析 IP -----
    if "hsxa-ip" in page_source:
        log.info("从页面提取 IP (BeautifulSoup)...")
        soup = BeautifulSoup(page_source, "html.parser")
        for div in soup.find_all("div", class_="hsxa-ip"):
            for a in div.find_all("a", class_="hsxa-jump-a"):
                if a.get("style") and "display:none" in a.get("style", ""):
                    continue
                ip_text = a.get_text(strip=True)
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_text):
                    ips.append(ip_text)
                    break

    if not ips and page_source:
        log.info("尝试正则提取 IP...")
        found = re.findall(r'data-clipboard-text="https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', page_source)
        if found:
            ips = found
        else:
            found = re.findall(r'class="hsxa-jump-a"[^>]*>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<', page_source)
            if found:
                ips = found

    ips = list(dict.fromkeys(ips))
    log.info(f"提取到 {len(ips)} 个去重IP")
    return ips


# ---------- FOFA 搜索（调度入口：API 优先，浏览器兜底） ----------
def fofa_search():
    """
    调度入口：
      1. 配置了 FOFA_API_KEY → 直接走 API（推荐，绕过 Turnstile）
      2. API 不可用 / 失败 → 回退到浏览器自动化
    """
    if FOFA_API_KEY:
        log.info("检测到 FOFA_API_KEY, 优先使用 FOFA API")
        ips = fofa_search_via_api()
        if ips:
            return ips
        log.warning("⚠️ FOFA API 未返回 IP, 回退到浏览器自动化模式")

    # 浏览器 fallback
    log.info("===== 使用浏览器模式搜索 IP =====")
    return fofa_search_via_browser()


def check_cf_proxy(ip):
    try:
        resp = requests.get(f"https://{ip}/cdn-cgi/trace", verify=False, timeout=5)
        if "cloudflare" in resp.text.lower():
            return True
    except:
        pass
    for scheme in ("http", "https"):
        try:
            resp = requests.head(f"{scheme}://{ip}", verify=False, timeout=5)
            if "cloudflare" in resp.headers.get("Server", "").lower():
                return True
        except:
            continue
    return False

def abuseipdb_check(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()["data"]["abuseConfidenceScore"]

def get_dns_records():
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    resp = requests.get(CF_DNS_RECORDS_URL, headers=headers,
                        params={"type": "A", "name": fqdn}, timeout=15)
    resp.raise_for_status()
    return resp.json().get("result", [])

def create_dns_record(ip):
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    for r in get_dns_records():
        if r["content"] == ip:
            log.info(f"IP {ip} 已存在，跳过")
            return
    data = {"type": "A", "name": fqdn, "content": ip, "ttl": 1, "proxied": False}
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data, timeout=15)
    resp.raise_for_status()
    log.info(f"已添加 DNS: {fqdn} -> {ip}")

def delete_dns_record(record_id, ip):
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    resp = requests.delete(f"{CF_DNS_RECORDS_URL}/{record_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    log.info(f"已删除 DNS 记录: {ip}")

def check_proxy_ips():
    log.info("===== 第五步：检测 ProxyIP =====")
    log.info("等待 30 秒让 DNS 生效...")
    time.sleep(30)

    records = get_dns_records()
    if not records:
        log.info("没有 DNS 记录需要检测")
        return {}

    all_ips = [r["content"] for r in records]
    log.info(f"当前 DNS 中的 IP ({len(all_ips)} 个): {all_ips}")

    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    log.info(f"用浏览器检测域名: {fqdn}")

    driver = create_driver()
    valid_ips = set()

    try:
        driver.get(PROXY_CHECK_URL)
        time.sleep(3)

        input_box = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "inputList"))
        )
        input_box.clear()
        input_box.send_keys(fqdn)

        try:
            submit_btn = driver.find_element(By.CSS_SELECTOR,
                                             'button[type="submit"], .check-btn, #checkBtn')
            submit_btn.click()
            log.info("  点击提交按钮")
        except:
            input_box.send_keys(Keys.RETURN)
            log.info("  回车提交")

        log.info("  等待检测结果...")
        last_count = 0
        stable_rounds = 0
        for _ in range(90):
            time.sleep(2)
            page_source = driver.page_source
            cur = page_source.count("result-item")
            if cur > 0:
                if cur == last_count:
                    stable_rounds += 1
                else:
                    stable_rounds = 0
                    last_count = cur
                    log.info(f"  已加载 {cur} 个结果...")
                if stable_rounds >= 5:
                    log.info(f"  结果加载完成，共 {cur} 个")
                    break

        time.sleep(3)
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, "html.parser")
        result_items = soup.find_all("div", class_="result-item")
        log.info(f"  找到 {len(result_items)} 个检测结果")
        for item in result_items:
            classes = item.get("class", [])
            ok = "success" in classes
            ip_span = item.find(class_="result-ip")
            if ip_span:
                ip_port = ip_span.get_text(strip=True)
                ip = ip_port.split(":")[0]
                if ok:
                    valid_ips.add(ip)
                    log.info(f"  ✅ {ip} 有效")
                else:
                    log.info(f"  ❌ {ip} 无效")
        driver.save_screenshot("proxyip_result.png")
    except Exception as e:
        log.error(f"  浏览器检测异常: {e}")
        try:
            driver.save_screenshot("proxyip_error.png")
        except:
            pass
    finally:
        try:
            driver.quit()
        except:
            pass

    ip_status = {ip: ("valid" if ip in valid_ips else "invalid") for ip in all_ips}
    log.info(f"  有效: {len(valid_ips)}, 无效: {len(all_ips) - len(valid_ips)}")
    return ip_status

def run_cloudflare_speedtest(valid_ips):
    if not valid_ips:
        log.info("没有有效 IP 可供 CloudflareST 测速")
        return []
    log.info("===== 第七步：CloudflareST 真实下载测速 =====")
    ip_file = "cf_ips.txt"
    result_file = "cf_speedtest.csv"
    with open(ip_file, "w", encoding="utf-8") as f:
        for ip in valid_ips:
            f.write(ip + "\n")
    binary = "./cfst"
    if not os.path.exists(binary):
        log.info("未找到 cfst 可执行文件")
        return []
    cmd = [
        binary,
        "-f", ip_file,
        "-o", result_file,
        "-n", "200",
        "-t", "4",
        "-dn", "10",
        "-dt", "10",
        "-tp", "443",
        "-tl", "300",
        "-sl", "0",
        "-p", "10",
        "-allip",
        "-url", "http://speed.cloudflare.com/__down?bytes=99999999",
    ]
    try:
        log.info(f"执行命令: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        log.info("CloudflareST 输出：")
        if result.stdout:
            for line in result.stdout.splitlines():
                log.info(line)
        if result.stderr:
            for line in result.stderr.splitlines():
                log.info(f"[stderr] {line}")
        if result.returncode != 0:
            log.info(f"CloudflareST 返回非 0 状态码: {result.returncode}")
    except Exception as e:
        log.info(f"CloudflareST 执行失败: {e}")
        return []

    speed_results = []
    if os.path.exists(result_file):
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = [x.strip() for x in line.split(",")]
                if len(parts) >= 6:
                    ip = parts[0]
                    try:
                        speed = float(parts[5])
                    except:
                        speed = 0.0
                    speed_results.append({
                        "ip": ip,
                        "sent": parts[1] if len(parts) > 1 else "",
                        "recv": parts[2] if len(parts) > 2 else "",
                        "loss": parts[3] if len(parts) > 3 else "",
                        "latency": parts[4] if len(parts) > 4 else "",
                        "speed_mbps": speed,
                        "region": parts[6] if len(parts) > 6 else "",
                    })
            if speed_results:
                log.info("===== CloudflareST 下载速度排名（越大越好） =====")
                speed_results.sort(key=lambda x: x["speed_mbps"], reverse=True)
                for idx, item in enumerate(speed_results, 1):
                    log.info(f"  #{idx} {item['ip']} -> {item['speed_mbps']:.2f} MB/s, "
                             f"延迟 {item['latency']}, 丢包 {item['loss']}, 区域 {item['region']}")
            else:
                log.info("cf_speedtest.csv 存在，但未解析到有效数据")
        except Exception as e:
            log.info(f"解析 CloudflareST 结果失败: {e}")
    else:
        log.info("未生成 cf_speedtest.csv，可能测速未成功")
    return speed_results

def cleanup_failed_ips(ip_status):
    log.info("===== 第六步：清理失败 IP =====")
    failed_ips = [ip for ip, s in ip_status.items() if s == "invalid"]
    if not failed_ips:
        log.info("所有 IP 正常")
        return
    log.info(f"需要清理 {len(failed_ips)} 个失败 IP")
    records = get_dns_records()
    for r in records:
        if r["content"] in failed_ips:
            try:
                delete_dns_record(r["id"], r["content"])
            except Exception as e:
                log.info(f"❌ 删除失败 {r['content']}: {e}")

def main():
    log.info("===== 第一步：从 FOFA 搜索 IP =====")
    ips = fofa_search()
    log.info(f"找到 {len(ips)} 个IP: {ips}")
    if not ips:
        return

    log.info("===== 第二步：探测 CF 反代特征 =====")
    cf_ips = []
    for idx, ip in enumerate(ips, 1):
        log.info(f"[{idx}/{len(ips)}] {ip} ...")
        if check_cf_proxy(ip):
            log.info(f"  ✅ {ip}")
            cf_ips.append(ip)
        else:
            log.info(f"  ❌ {ip}")
    log.info(f"CF 节点: {len(cf_ips)} 个")
    if not cf_ips:
        return

    log.info("===== 第三步：AbuseIPDB 检测 =====")
    clean_ips = []
    for ip in cf_ips:
        try:
            score = abuseipdb_check(ip)
            log.info(f"  {ip} 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean_ips.append(ip)
            time.sleep(0.5)
        except Exception as e:
            log.info(f"  {ip} 失败: {e}")
    if not clean_ips:
        return

    log.info("===== 第四步：添加 DNS =====")
    for ip in clean_ips:
        try:
            create_dns_record(ip)
            time.sleep(0.5)
        except Exception as e:
            log.info(f"添加失败 {ip}: {e}")

    ip_status = check_proxy_ips()
    valid_ips = [ip for ip, s in ip_status.items() if s == "valid"]
    run_cloudflare_speedtest(valid_ips)
    cleanup_failed_ips(ip_status)
    log.info("===== 全部完毕 =====")

if __name__ == "__main__":
    main()
