import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re
import time
import base64
import logging
import subprocess
import requests
import urllib3
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
from selenium.common.exceptions import TimeoutException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger(__name__)

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
    log.info(f"  OCR 候选: {results} -> {best}")
    return best


# ========== Chrome 驱动 ==========
def create_driver():
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")

    version_main = None
    try:
        output = subprocess.check_output(["google-chrome", "--version"]).decode().strip()
        version_main = int(output.split()[-1].split(".")[0])
        log.info(f"检测到 Chrome 版本: {version_main}")
    except Exception as e:
        log.info(f"无法检测 Chrome 版本: {e}")

    driver = uc.Chrome(options=options, headless=False, version_main=version_main)
    return driver


# ========== FOFA 登录 + 搜索 ==========
def fofa_search():
    driver = create_driver()
    ips = []

    try:
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
                continue

            try:
                captcha_img = WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.ID, "captcha_image"))
                )
                captcha_bytes = captcha_img.screenshot_as_png
                captcha_text = ocr_captcha(captcha_bytes)
                log.info(f"  验证码: {captcha_text}")

                if len(captcha_text) < 4:
                    captcha_img.click()
                    time.sleep(1)
                    continue

                captcha_input = driver.find_element(By.NAME, "_rucaptcha")
                captcha_input.clear()
                captcha_input.send_keys(captcha_text)
            except Exception as e:
                log.info(f"  验证码处理失败: {e}")
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

            if "fofa.info" in driver.current_url and "login" not in driver.current_url.replace("f_login", "").lower():
                log.info("  ✅ 登录成功")
                break

            if "i.nosec.org" in driver.current_url:
                log.info("  ❌ 验证码错误或登录失败")
                time.sleep(1)

        if "fofa.info" not in driver.current_url:
            driver.get("https://fofa.info/")
            time.sleep(3)

        log.info(f"当前 URL: {driver.current_url}")

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

        if not loaded:
            log.info("  URL 方式未加载数据，尝试搜索框...")
            driver.save_screenshot("url_method_failed.png")

            search_selectors = [
                ('textarea[data-testid="result-search-input"]', 'span[data-testid="result-search-submit"] button'),
                ('textarea[data-testid="home-search-input"]', 'span[data-testid="home-search-submit"] button'),
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
                        "arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new Event('input', {bubbles: true}));",
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


# ========== ProxyIP 浏览器检测 ==========
def check_proxy_ips():
    log.info("===== 第四步：检测 ProxyIP =====")
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
    ip_status = {}
    latency_results = []

    try:
        driver.get(PROXY_CHECK_URL)
        time.sleep(3)

        input_box = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "inputList"))
        )
        input_box.clear()
        input_box.send_keys(fqdn)

        try:
            submit_btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], .check-btn, #checkBtn')
            submit_btn.click()
            log.info("  点击提交按钮")
        except:
            input_box.send_keys(Keys.RETURN)
            log.info("  回车提交")

        log.info("  等待检测结果...")
        last_count = 0
        stable_rounds = 0

        for wait_round in range(90):
            time.sleep(2)
            page_source = driver.page_source
            current_count = page_source.count("result-item")

            if current_count > 0:
                if current_count == last_count:
                    stable_rounds += 1
                else:
                    stable_rounds = 0
                    last_count = current_count
                    log.info(f"  已加载 {current_count} 个结果...")

                if stable_rounds >= 5:
                    log.info(f"  结果加载完成，共 {current_count} 个")
                    break

        time.sleep(3)
        page_source = driver.page_source

        soup = BeautifulSoup(page_source, "html.parser")
        result_items = soup.find_all("div", class_="result-item")
        log.info(f"  找到 {len(result_items)} 个检测结果")

        for ip in all_ips:
            ip_status[ip] = {
                "status": "invalid",
                "latency_ms": None,
            }

        for item in result_items:
            classes = item.get("class", [])
            is_success = "success" in classes

            ip_span = item.find("span", class_="result-ip")
            badge_span = item.find("span", class_=lambda x: x and "status-badge" in x)

            if not ip_span:
                continue

            ip_port = ip_span.get_text(strip=True)
            ip = ip_port.split(":")[0]

            latency_ms = None
            if badge_span:
                badge_text = badge_span.get_text(strip=True)
                m = re.search(r'(\d+)\s*ms', badge_text, re.I)
                if m:
                    latency_ms = int(m.group(1))

            if ip not in ip_status:
                ip_status[ip] = {
                    "status": "invalid",
                    "latency_ms": None,
                }

            if is_success:
                ip_status[ip]["status"] = "valid"
                ip_status[ip]["latency_ms"] = latency_ms
                log.info(f"  ✅ {ip} 有效, 延迟: {latency_ms} ms")
                if latency_ms is not None:
                    latency_results.append((ip, latency_ms))
            else:
                ip_status[ip]["status"] = "invalid"
                ip_status[ip]["latency_ms"] = latency_ms
                log.info(f"  ❌ {ip} 无效, 延迟: {latency_ms} ms")

        if latency_results:
            latency_results.sort(key=lambda x: x[1])
            log.info("===== ProxyIP 延迟排名（越小越好） =====")
            for idx, (ip, latency) in enumerate(latency_results, 1):
                log.info(f"  #{idx} {ip} -> {latency} ms")
        else:
            log.info("没有可用节点可供延迟排名")

        driver.save_screenshot("proxyip_result.png")

    except Exception as e:
        log.error(f"  浏览器检测异常: {e}")
        try:
            driver.save_screenshot("proxyip_error.png")
        except:
            pass

        for ip in all_ips:
            if ip not in ip_status:
                ip_status[ip] = {
                    "status": "invalid",
                    "latency_ms": None,
                }

    finally:
        try:
            driver.quit()
        except:
            pass

    valid_count = sum(1 for v in ip_status.values() if v["status"] == "valid")
    invalid_count = sum(1 for v in ip_status.values() if v["status"] == "invalid")
    log.info(f"  有效: {valid_count}, 无效: {invalid_count}")

    return ip_status


# ========== CloudflareST 真下载测速 ==========
def run_cloudflare_speedtest(valid_ips):
    if not valid_ips:
        log.info("没有有效 IP 可供 CloudflareST 测速")
        return []

    log.info("===== 第五步：CloudflareST 真实下载测速 =====")

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
        "-f", ip_file,     # IP 列表文件
        "-o", result_file, # 结果输出文件
        "-n", "200",       # 延迟测速线程
        "-t", "4",         # 延迟测速次数
        "-dn", "5",        # 下载测速数量
        "-dt", "10",       # 下载测速时间（秒）
        "-tp", "443",      # 测速端口
        "-tll", "40",      # 平均延迟下限
        "-tl", "150",      # 平均延迟上限
        "-sl", "1",        # 下载速度下限（MB/s）
        "-p", "10",        # 显示结果数量
        "-allip",          # 测速全部 IP
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
                # 常见格式:
                # IP地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
                if len(parts) >= 6:
                    ip = parts[0]
                    sent = parts[1] if len(parts) > 1 else ""
                    recv = parts[2] if len(parts) > 2 else ""
                    loss = parts[3] if len(parts) > 3 else ""
                    latency = parts[4] if len(parts) > 4 else ""
                    speed = parts[5] if len(parts) > 5 else ""
                    region = parts[6] if len(parts) > 6 else ""

                    try:
                        speed_float = float(speed)
                    except:
                        speed_float = 0.0

                    speed_results.append({
                        "ip": ip,
                        "sent": sent,
                        "recv": recv,
                        "loss": loss,
                        "latency": latency,
                        "speed_mbps": speed_float,
                        "region": region
                    })

            if speed_results:
                log.info("===== CloudflareST 下载速度排名（越大越好） =====")
                speed_results.sort(key=lambda x: x["speed_mbps"], reverse=True)
                for idx, item in enumerate(speed_results, 1):
                    log.info(
                        f"  #{idx} {item['ip']} -> "
                        f"{item['speed_mbps']:.2f} MB/s, "
                        f"延迟 {item['latency']}, "
                        f"丢包 {item['loss']}, "
                        f"地区 {item['region']}"
                    )
            else:
                log.info("cf_speedtest.csv 存在，但没有解析到测速结果")
        except Exception as e:
            log.info(f"解析 CloudflareST 结果失败: {e}")
    else:
        log.info("未生成 cf_speedtest.csv，可能测速未成功")

    return speed_results


# ========== 清理 ==========
def cleanup_failed_ips(ip_status):
    log.info("===== 第六步：清理失败 IP =====")
    failed_ips = [ip for ip, meta in ip_status.items() if meta.get("status") == "invalid"]
    if not failed_ips:
        log.info("所有 IP 正常")
        return

    log.info(f"需要清理 {len(failed_ips)} 个失败 IP: {failed_ips}")
    records = get_dns_records()
    for r in records:
        if r["content"] in failed_ips:
            try:
                delete_dns_record(r["id"], r["content"])
            except Exception as e:
                log.info(f"❌ 删除失败 {r['content']}: {e}")


# ========== 主流程 ==========
def main():
    log.info("===== 第一步：从 FOFA 搜索 IP =====")
    ips = fofa_search()
    log.info(f"找到 {len(ips)} 个IP: {ips}")
    if not ips:
        return

    log.info("===== 第二步：AbuseIPDB 检测 =====")
    clean_ips = []
    for ip in ips:
        try:
            score = abuseipdb_check(ip)
            log.info(f"  {ip} 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean_ips.append(ip)
            time.sleep(0.5)
        except Exception as e:
            log.info(f"  {ip} 失败: {e}")

    log.info(f"AbuseIPDB 通过 {len(clean_ips)} 个IP: {clean_ips}")
    if not clean_ips:
        return

    log.info("===== 第三步：添加 DNS =====")
    for ip in clean_ips:
        try:
            create_dns_record(ip)
            time.sleep(0.5)
        except Exception as e:
            log.info(f"添加失败 {ip}: {e}")

    ip_status = check_proxy_ips()

    valid_ips = [ip for ip, meta in ip_status.items() if meta.get("status") == "valid"]
    run_cloudflare_speedtest(valid_ips)

    cleanup_failed_ips(ip_status)

    log.info("===== 全部完毕 =====")


if __name__ == "__main__":
    main()
