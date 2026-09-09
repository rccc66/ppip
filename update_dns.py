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
    options.add_argument("--lang=zh-CN,zh;q=0.9")
    options.add_argument("--disable-blink-features=AutomationControlled")

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
    target_iframe = None
    try:
        all_iframes = driver.find_elements(By.TAG_NAME, "iframe")
        log.info(f"  页面 iframe 总数: {len(all_iframes)}")
        for f in all_iframes:
            try:
                if not f.is_displayed():
                    continue
                src = f.get_attribute("src") or ""
                if ("cloudflare" in src or "turnstile" in src or "challenges" in src):
                    target_iframe = f
                    log.info(f"  锁定 CF iframe, src={src[:100]}")
                    break
            except StaleElementReferenceException:
                continue
            except Exception:
                continue

        # 兜底：在 .cf-turnstile 容器内找
        if target_iframe is None:
            try:
                container = driver.find_element(By.CSS_SELECTOR, "div.cf-turnstile")
                inner_iframes = container.find_elements(By.TAG_NAME, "iframe")
                for f in inner_iframes:
                    if f.is_displayed():
                        target_iframe = f
                        log.info("  在 .cf-turnstile 容器内找到 iframe")
                        break
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


def handle_turnstile(driver, log, auto_timeout=25, max_click_retries=3):
    """
    FOFA 登录页使用 Cloudflare Turnstile 替代图片验证码。
    策略：
      1) 主：等 Turnstile managed 模式自动通过（uc + 真实指纹下常自动放行）
      2) 兜底 A：手动点击 Turnstile iframe 内 checkbox，最多重试 max_click_retries 次
      3) 兜底 B：2captcha 外部打码（需配置 TWOCAPTCHA_API_KEY）
    成功返回 True，失败返回 False。
    """
    # 1) 等待 Turnstile 组件渲染
    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.cf-turnstile"))
        )
    except TimeoutException:
        log.info("  未找到 Turnstile 组件，可能页面结构已变或已登录")
        _save_debug(driver, "no_turnstile")
        return False

    # 取 sitekey 和 page_url，给兜底 B 用
    sitekey = None
    page_url = driver.current_url
    try:
        div = driver.find_element(By.CSS_SELECTOR, "div.cf-turnstile")
        sitekey = div.get_attribute("data-sitekey")
    except Exception:
        pass
    log.info(f"  Turnstile sitekey={sitekey}, page={page_url}")

    # 2) 主策略：等提交按钮自动启用
    log.info(f"  等待 Turnstile 自动通过 (最多 {auto_timeout}s)...")
    try:
        WebDriverWait(driver, auto_timeout).until(_submit_button_enabled)
        log.info("  ✅ Turnstile 自动通过，提交按钮已启用")
        return True
    except TimeoutException:
        log.info("  Turnstile 未自动通过，转为点击 checkbox")

    # 3) 兜底 A：点击 checkbox，最多重试 max_click_retries 次
    for attempt in range(1, max_click_retries + 1):
        log.info(f"  尝试点击 Turnstile checkbox (第 {attempt}/{max_click_retries} 次)...")
        clicked, status = _click_turnstile_checkbox(driver, log)

        if status == "success":
            log.info("  ✅ 点击后 Turnstile 通过")
            # 等提交按钮启用（onTurnstileSuccess 回调触发）
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
            log.info(f"  状态={status}，刷新后重试")
            _refresh_turnstile(driver, log)
            continue

        if status == "no_iframe":
            # iframe 还没渲染完，等一下再试
            time.sleep(3)
            continue

        if status == "verifying_timeout":
            # 验证中但超时，刷新重试
            _refresh_turnstile(driver, log)
            time.sleep(2)
            continue

        # click_error 等其他情况
        _save_debug(driver, f"click_{status}")
        time.sleep(2)

    # 4) 兜底 B：2captcha 外部打码
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


# ---------- FOFA 搜索 ----------
def fofa_search():
    driver = create_driver()
    ips = []

    try:
        # ===== 登录 =====
        for attempt in range(10):
            log.info(f"登录尝试 {attempt + 1}/10 ...")
            driver.get(LOGIN_PAGE)
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
            if not handle_turnstile(driver, log, auto_timeout=25):
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
