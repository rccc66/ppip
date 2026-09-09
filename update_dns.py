import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re, time, json, base64, logging, subprocess, requests, urllib3, urllib.parse
import shutil
import ddddocr
import undetected_chromedriver as uc
from io import BytesIO
from collections import Counter
from PIL import Image, ImageFilter, ImageEnhance
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
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
FOFA_QUERY = ('server=="cloudflare" && header="Forbidden" && country=="US" && '
              'port="443" && (asn=="31898" || asn=="16509" || asn=="14618" || asn=="8075")')
PROXY_CHECK_URL = "https://check.proxyip.cmliussss.net"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
ABUSE_THRESHOLD = 20
LOGIN_PAGE = "https://i.nosec.org/login?locale=zh-CN&service=https://fofa.info/f_login"

# ---------- OCR ----------
def preprocess_captcha(image_bytes):
    img = Image.open(BytesIO(image_bytes))
    candidates = []
    buf = BytesIO()
    img.save(buf, format="PNG")
    candidates.append(buf.getvalue())

    gray = img.convert("L")
    enhanced = ImageEnhance.Contrast(gray).enhance(2.0)
    bw = enhanced.point(lambda x: 255 if x > 128 else 0, "1")
    buf = BytesIO(); bw.save(buf, format="PNG"); candidates.append(buf.getvalue())

    sharp = gray.filter(ImageFilter.SHARPEN)
    bw2 = sharp.point(lambda x: 255 if x > 100 else 0, "1")
    buf = BytesIO(); bw2.save(buf, format="PNG"); candidates.append(buf.getvalue())

    big = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)
    big_gray = big.convert("L")
    big_enh = ImageEnhance.Contrast(big_gray).enhance(2.5)
    big_bw = big_enh.point(lambda x: 255 if x > 120 else 0, "1")
    buf = BytesIO(); big_bw.save(buf, format="PNG"); candidates.append(buf.getvalue())

    median = gray.filter(ImageFilter.MedianFilter(3))
    med_bw = median.point(lambda x: 255 if x > 130 else 0, "1")
    buf = BytesIO(); med_bw.save(buf, format="PNG"); candidates.append(buf.getvalue())
    return candidates

def ocr_captcha(image_bytes):
    ocr = ddddocr.DdddOcr(show_ad=False)
    candidates = preprocess_captcha(image_bytes)
    results = []
    for img_data in candidates:
        try:
            txt = ocr.classification(img_data)
            clean = re.sub(r'[^a-zA-Z]', '', txt).lower()
            if 4 <= len(clean) <= 6:
                results.append(clean[:5])
        except:
            continue
    if not results:
        return ""
    best = Counter(results).most_common(1)[0][0]
    log.info(f"  OCR 候选: {results} -> {best}")
    return best

# ---------- Chrome 驱动（已应用强制对齐修复） ----------
def create_driver():
    """
    强制对齐浏览器路径与驱动版本，避免 CI 环境多版本冲突。
    """
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    # 反自动化特征，避免被 FOFA/WAF 拦截
    options.add_argument("--disable-blink-features=AutomationControlled")
    headless_mode = False  # 如需无头请改为 True

    # 1️⃣ 锁定具体的浏览器执行路径优先级
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

    # 2️⃣ 强制 uc 使用上述锁定的二进制文件，确保驱动与浏览器版本绝对匹配
    driver = uc.Chrome(
        options=options,
        browser_executable_path=browser_path,
        version_main=detected_version,
        headless=headless_mode,
    )
    return driver


# ---------- 验证码处理（修复版） ----------
CAPTCHA_IMG_SELECTORS = [
    (By.ID, "captcha_image"),
    (By.ID, "captchaImage"),
    (By.CSS_SELECTOR, "img[id*='captcha']"),
    (By.CSS_SELECTOR, "img.captcha"),
    (By.CSS_SELECTOR, "img[alt*='captcha' i]"),
    (By.XPATH, "//img[contains(@src,'captcha') or contains(@src,'rucaptcha')]"),
]
CAPTCHA_INPUT_SELECTORS = [
    (By.NAME, "_rucaptcha"),
    (By.NAME, "captcha"),
    (By.ID, "captcha"),
    (By.CSS_SELECTOR, "input[name*='captcha' i]"),
]


def _switch_to_captcha_iframe(driver):
    """如果验证码在 iframe 里，切进去；否则什么都不做。"""
    try:
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        for fr in iframes:
            try:
                driver.switch_to.frame(fr)
                found = driver.find_elements(
                    By.CSS_SELECTOR,
                    "img[id*='captcha'], img[src*='captcha'], img[src*='rucaptcha']",
                )
                if found:
                    return True
                driver.switch_to.default_content()
            except Exception:
                driver.switch_to.default_content()
                continue
    except Exception:
        driver.switch_to.default_content()
    return False


def _save_debug(driver, tag):
    """失败时保存截图和 HTML，方便事后排查页面结构变化。"""
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


def handle_captcha(driver, ocr_fn, log):
    """
    在已打开登录页的 driver 上完成验证码识别并填入。
    成功返回 True，失败返回 False。
    """
    in_iframe = _switch_to_captcha_iframe(driver)
    log.info(f"  验证码 iframe 模式: {in_iframe}")

    # 1) 等元素可见（而非仅 present），避免 screenshot_as_png 抛空 Message
    captcha_img = None
    used_selector = None
    for by, sel in CAPTCHA_IMG_SELECTORS:
        try:
            captcha_img = WebDriverWait(driver, 4).until(
                EC.visibility_of_element_located((by, sel))
            )
            used_selector = (by, sel)
            break
        except TimeoutException:
            continue
        except Exception as e:
            log.info(f"  selector {sel} 异常: {type(e).__name__}: {str(e)[:200]}")
            continue

    if captcha_img is None:
        log.info("  找不到可见验证码图片，可能页面结构已变更或改用滑块验证")
        _save_debug(driver, "no_captcha")
        if in_iframe:
            driver.switch_to.default_content()
        return False

    # 2) 再等一下确保图片渲染完（避免 zero-size screenshot）
    try:
        WebDriverWait(driver, 3).until(
            lambda d: captcha_img.size["width"] > 10 and captcha_img.size["height"] > 10
        )
    except Exception:
        log.info(f"  验证码尺寸异常: {captcha_img.size}")
        _save_debug(driver, "captcha_size")
        if in_iframe:
            driver.switch_to.default_content()
        return False

    # 3) 截图，分阶段捕获真正错误
    try:
        captcha_bytes = captcha_img.screenshot_as_png
    except StaleElementReferenceException:
        log.info("  验证码元素已失效（DOM 刷新）")
        if in_iframe:
            driver.switch_to.default_content()
        return False
    except WebDriverException as e:
        # 这就是原来 "Message: 空字符串 + stacktrace" 的真凶
        log.info(f"  验证码截图失败 WebDriverException: "
                 f"msg={str(e.msg)[:300]!r}, stack={str(e.stacktrace)[:300]}")
        _save_debug(driver, "screenshot_fail")
        if in_iframe:
            driver.switch_to.default_content()
        return False
    except Exception as e:
        log.info(f"  验证码截图未知异常: {type(e).__name__}: {str(e)[:300]}")
        _save_debug(driver, "screenshot_unknown")
        if in_iframe:
            driver.switch_to.default_content()
        return False

    # 4) OCR
    try:
        captcha_text = ocr_fn(captcha_bytes)
    except Exception as e:
        log.info(f"  OCR 异常: {type(e).__name__}: {str(e)[:300]}")
        if in_iframe:
            driver.switch_to.default_content()
        return False

    log.info(f"  验证码识别: {captcha_text!r} (selector={used_selector})")
    if len(captcha_text) < 4:
        try:
            captcha_img.click()  # 点击刷新
            time.sleep(1)
        except Exception:
            pass
        if in_iframe:
            driver.switch_to.default_content()
        return False

    # 5) 找输入框，可能在 iframe 外
    if in_iframe:
        driver.switch_to.default_content()

    captcha_input = None
    for by, sel in CAPTCHA_INPUT_SELECTORS:
        try:
            captcha_input = WebDriverWait(driver, 3).until(
                EC.visibility_of_element_located((by, sel))
            )
            break
        except TimeoutException:
            continue
    if captcha_input is None:
        log.info("  找不到验证码输入框")
        _save_debug(driver, "no_input")
        return False

    captcha_input.clear()
    captcha_input.send_keys(captcha_text)
    return True


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

            # ===== 验证码处理（修复版） =====
            if not handle_captcha(driver, ocr_captcha, log):
                continue

            try:
                checkbox = driver.find_element(By.ID, "fofa_service")
                if not checkbox.is_selected():
                    driver.execute_script("arguments[0].click();", checkbox)
            except:
                pass

            try:
                submit_btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                submit_btn.click()
                time.sleep(5)
            except:
                pass

            log.info(f"  提交后 URL: {driver.current_url}")

            if ("fofa.info" in driver.current_url and
                "login" not in driver.current_url.replace("f_login", "").lower()):
                log.info("  ✅ 登录成功")
                break

            if "i.nosec.org" in driver.current_url:
                log.info("  ❌ 验证码错误或登录失败")
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
