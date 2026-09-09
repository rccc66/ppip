import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re, time, json, logging, subprocess, requests, urllib3
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import undetected_chromedriver as uc
import shutil

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger(__name__)

# ---------- 环境变量 ----------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
# 关键：os.getenv(name, default) 在 secret 存在但值为空时会返回空字符串，
# 不是 default。需要手动 fallback。
CF_DNS_NAME = (os.getenv("CLOUDFLARE_DNS_NAME") or "").strip() or "us"
CF_DOMAIN = os.getenv("CLOUDFLARE_DOMAIN")
ABUSE_THRESHOLD = 20

# PPIP 数据源（替代 FOFA）
PPIP_RESOLVE_URL = "https://ppip.ishtq.de5.net/resolve"
PPIP_CHECK_URL = "https://api.090227.xyz/check"
# 从这个 ProxyIP 域名解析候选 IP（用户指定）
PPIP_SOURCE_DOMAIN = os.getenv("PPIP_SOURCE_DOMAIN", "ProxyIP.US.CMLiussss.net")
# 检查多少个 IP（每个 IP 都要调 /check，免费 API 别太多）
PPIP_CHECK_LIMIT = int((os.getenv("PPIP_CHECK_LIMIT") or "").strip() or "30")
# 并发数
PPIP_CONCURRENCY = int((os.getenv("PPIP_CONCURRENCY") or "").strip() or "5")

# CloudflareST 二进制
CFST_BINARY = os.getenv("CFST_BINARY", "./cfst")

# ProxyIP 检测页面（保留作为 IP 验证页面）
PROXY_CHECK_URL = "https://check.proxyip.cmliussss.net"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"


# ---------- 第一步：从 PPIP 获取 IP ----------
def fetch_ips_from_ppip():
    """
    从 ppip.ishtq.de5.net 拉取候选 IP 列表。
    /resolve API 返回一个 JSON 数组，元素形如 "1.2.3.4:443"。
    """
    log.info(f"===== 第一步：从 PPIP 拉取候选 IP =====")
    log.info(f"源域名: {PPIP_SOURCE_DOMAIN}")
    try:
        r = requests.get(PPIP_RESOLVE_URL,
                         params={"proxyip": PPIP_SOURCE_DOMAIN},
                         timeout=30)
        r.raise_for_status()
        targets = r.json()
    except Exception as e:
        log.error(f"❌ PPIP resolve 失败: {e}")
        return []

    if not isinstance(targets, list):
        log.error(f"❌ PPIP 返回格式异常: {type(targets)}")
        return []

    log.info(f"✅ PPIP 返回 {len(targets)} 个候选目标")
    # 取前 N 个
    targets = targets[:PPIP_CHECK_LIMIT]
    log.info(f"限制检测前 {PPIP_CHECK_LIMIT} 个")
    return targets


# ---------- 第二步：批量验证 IP（用 PPIP /check API） ----------
def check_ips_via_ppip(targets):
    """
    并发调用 api.090227.xyz/check 验证每个 IP。
    返回有效 IP 列表 [{ip, exit_ip, country, asOrganization, latency}, ...]
    """
    import concurrent.futures
    log.info(f"===== 第二步：批量验证 IP（并发 {PPIP_CONCURRENCY}） =====")

    valid_ips = []
    failed_count = 0

    def check_one(target):
        try:
            r = requests.get(PPIP_CHECK_URL,
                             params={"proxyip": target},
                             timeout=30)
            r.raise_for_status()
            data = r.json()
            if not data.get("success"):
                return None
            ipv4 = data.get("probe_results", {}).get("ipv4", {})
            if not ipv4.get("ok"):
                return None
            exit_info = ipv4.get("exit") or {}
            return {
                "target": target,
                "ip": target.split(":")[0],  # 去掉端口
                "exit_ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "asOrganization": exit_info.get("asOrganization"),
                "latency": data.get("responseTime"),
                "colo": data.get("colo"),
                "bot_score": exit_info.get("botManagement", {}).get("score"),
            }
        except Exception as e:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=PPIP_CONCURRENCY) as ex:
        futures = {ex.submit(check_one, t): t for t in targets}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            result = fut.result()
            if result:
                valid_ips.append(result)
                log.info(f"  [{i}/{len(targets)}] ✅ {result['ip']} "
                         f"({result['country']}, {result['asOrganization']}, "
                         f"{result['latency']}ms)")
            else:
                failed_count += 1
                if i % 10 == 0:
                    log.info(f"  [{i}/{len(targets)}] 进度...")

    log.info(f"✅ 有效 IP: {len(valid_ips)}, 失败: {failed_count}")
    return valid_ips


# ---------- 第三步：AbuseIPDB 检测纯净度 ----------
def abuseipdb_check(ip):
    r = requests.get(ABUSE_CHECK_URL,
                     headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90},
                     timeout=15)
    r.raise_for_status()
    return r.json()["data"]["abuseConfidenceScore"]


def filter_clean_ips(valid_ips):
    """按 AbuseIPDB 评分过滤纯净 IP"""
    log.info(f"===== 第三步：AbuseIPDB 纯净度检测 =====")
    clean = []
    for idx, item in enumerate(valid_ips, 1):
        ip = item["ip"]
        try:
            score = abuseipdb_check(ip)
            log.info(f"  [{idx}/{len(valid_ips)}] {ip} 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean.append(item)
            time.sleep(0.5)
        except Exception as e:
            log.info(f"  [{idx}/{len(valid_ips)}] {ip} 失败: {e}")
    log.info(f"纯净 IP: {len(clean)} 个")
    return clean


# ---------- Cloudflare DNS 操作 ----------
def _verify_cf_config():
    """启动时校验 Cloudflare 配置——把 FQDN 和 zone 信息打印出来，方便定位 9000 错误"""
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    log.info("===== Cloudflare 配置检查 =====")
    log.info(f"  CLOUDFLARE_ZONE_ID: {CF_ZONE_ID}")
    log.info(f"  CLOUDFLARE_DOMAIN: {CF_DOMAIN!r}")
    log.info(f"  CLOUDFLARE_DNS_NAME: {CF_DNS_NAME!r}")
    log.info(f"  拼接的 FQDN: {fqdn!r}")

    # 校验 FQDN 格式
    if not CF_DOMAIN or "." not in CF_DOMAIN:
        log.error(f"❌ CLOUDFLARE_DOMAIN 不像根域名（应该含至少一个点）: {CF_DOMAIN!r}")
        log.error("   请确认 GitHub Secret CLOUDFLARE_DOMAIN 是根域名，例如 example.com，不是 us.example.com")
        return False
    if not CF_DNS_NAME or not re.match(r'^[a-zA-Z0-9-]+$', CF_DNS_NAME):
        log.error(f"❌ CLOUDFLARE_DNS_NAME 含非法字符: {CF_DNS_NAME!r}")
        log.error("   只允许字母数字和连字符，例如 us / hk / jp")
        return False

    # 调用 CF API 验证 zone 是否存在 + token 是否有权限
    try:
        r = requests.get(f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}",
                         headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
                         timeout=15)
        if r.status_code == 200:
            zone = r.json().get("result", {})
            log.info(f"  ✅ Zone 验证通过: name={zone.get('name')!r}, status={zone.get('status')}")
            # 关键校验：zone name 必须等于 CF_DOMAIN 或是其父域名
            zone_name = zone.get("name", "")
            if zone_name and zone_name != CF_DOMAIN:
                log.error(f"❌ Zone 实际 name 是 {zone_name!r}，但 CLOUDFLARE_DOMAIN 是 {CF_DOMAIN!r}")
                log.error(f"   请把 GitHub Secret CLOUDFLARE_DOMAIN 改成 {zone_name!r}")
                return False
            log.info(f"  ✅ Zone 与 CLOUDFLARE_DOMAIN 匹配")
        elif r.status_code == 403:
            log.error(f"❌ Token 无权限访问 zone（403）: {r.text[:200]}")
            return False
        elif r.status_code == 404:
            log.error(f"❌ Zone 不存在（404），CLOUDFLARE_ZONE_ID 错了: {CF_ZONE_ID}")
            return False
        else:
            log.error(f"❌ Zone 验证失败 HTTP {r.status_code}: {r.text[:200]}")
            return False
    except Exception as e:
        log.error(f"❌ Zone 验证异常: {e}")
        return False

    return True


def get_dns_records():
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    r = requests.get(CF_DNS_RECORDS_URL,
                     headers={"Authorization": f"Bearer {CF_API_TOKEN}",
                              "Content-Type": "application/json"},
                     params={"type": "A", "name": fqdn},
                     timeout=15)
    r.raise_for_status()
    return r.json().get("result", [])


def create_dns_record(ip):
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    for r in get_dns_records():
        if r["content"] == ip:
            log.info(f"IP {ip} 已存在")
            return
    payload = {"type": "A", "name": fqdn, "content": ip,
               "ttl": 1, "proxied": False}
    r = requests.post(CF_DNS_RECORDS_URL,
                      headers={"Authorization": f"Bearer {CF_API_TOKEN}",
                               "Content-Type": "application/json"},
                      json=payload, timeout=15)
    if r.status_code != 200:
        try:
            err = r.json()
            log.error(f"❌ 添加 {ip} 失败 HTTP {r.status_code}: {err}")
        except Exception:
            log.error(f"❌ 添加 {ip} 失败 HTTP {r.status_code}: {r.text[:300]}")
        r.raise_for_status()
    log.info(f"已添加 DNS: {fqdn} -> {ip}")


def delete_dns_record(rid, ip):
    r = requests.delete(f"{CF_DNS_RECORDS_URL}/{rid}",
                        headers={"Authorization": f"Bearer {CF_API_TOKEN}",
                                 "Content-Type": "application/json"},
                        timeout=15)
    r.raise_for_status()
    log.info(f"已删除: {ip}")


def add_ips_to_dns(clean_ips):
    """添加 IP 到 Cloudflare DNS，返回成功添加的 IP 列表"""
    log.info(f"===== 第四步：添加 DNS 记录 =====")
    added = []
    for idx, item in enumerate(clean_ips, 1):
        ip = item["ip"]
        try:
            create_dns_record(ip)
            added.append(ip)
        except Exception as e:
            # create_dns_record 内部已打印详细错误，这里只做汇总
            pass
        time.sleep(0.3)
    log.info(f"添加成功 {len(added)}/{len(clean_ips)} 个 IP")
    return added


# ---------- 第五步：浏览器复检 ProxyIP（用检测页） ----------
def create_driver():
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--lang=zh-CN")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")

    if os.getenv("GITHUB_ACTIONS") or os.getenv("FORCE_PROXY"):
        proxy = "socks5://127.0.0.1:1080" if os.getenv("SOCKS5_PROXY") else "socks5://127.0.0.1:40000"
        options.add_argument(f"--proxy-server={proxy}")
        log.info(f"🌐 Chrome 走 SOCKS5: {proxy}")

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
    return driver


def verify_proxyips_via_browser():
    """用浏览器访问 PROXY_CHECK_URL 复检 IP 是否真的能用"""
    log.info(f"===== 第五步：浏览器复检 ProxyIP =====")
    log.info("等待 30 秒让 DNS 生效...")
    time.sleep(30)

    records = get_dns_records()
    if not records:
        log.info("无 DNS 记录")
        return {}

    all_ips = [r["content"] for r in records]
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    log.info(f"复检 {fqdn} ({len(all_ips)} 个 IP)")

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
        log.error(f"复检异常: {e}")
    finally:
        try: driver.quit()
        except Exception: pass

    return {ip: ("valid" if ip in valid else "invalid") for ip in all_ips}


# ---------- 第七步：CloudflareST 测速 ----------
def run_cloudflare_speedtest(valid_ips):
    if not valid_ips:
        log.info("无有效 IP，跳过测速")
        return []
    log.info(f"===== CloudflareST 测速 =====")
    with open("cf_ips.txt", "w") as f:
        for ip in valid_ips: f.write(ip + "\n")
    if not os.path.exists(CFST_BINARY):
        log.info(f"未找到 {CFST_BINARY}，跳过测速")
        return []
    cmd = [CFST_BINARY, "-f", "cf_ips.txt", "-o", "cf_speedtest.csv",
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


# ---------- 第六步：清理失败 IP ----------
def cleanup_failed_ips(ip_status):
    failed = [ip for ip, s in ip_status.items() if s == "invalid"]
    if not failed: return
    log.info(f"===== 清理 {len(failed)} 个失败 IP =====")
    records = get_dns_records()
    for r in records:
        if r["content"] in failed:
            try: delete_dns_record(r["id"], r["content"])
            except Exception as e: log.info(f"删除失败 {r['content']}: {e}")


# ---------- 主流程 ----------
def main():
    import sys
    # 第 0 步：先校验 Cloudflare 配置（避免做了一堆工作最后 DNS 加不上）
    if not _verify_cf_config():
        log.error("❌ Cloudflare 配置校验失败，请按上面提示修复 GitHub Secrets")
        sys.exit(1)

    # 第一步：从 PPIP 拉取候选 IP
    targets = fetch_ips_from_ppip()
    if not targets:
        log.error("❌ 未获取到候选 IP")
        sys.exit(1)

    # 第二步：批量验证 IP
    valid_ips = check_ips_via_ppip(targets)
    if not valid_ips:
        log.error("❌ 无有效 IP")
        sys.exit(1)

    # 第三步：AbuseIPDB 纯净度过滤
    clean_ips = filter_clean_ips(valid_ips)
    if not clean_ips:
        log.error("❌ 无纯净 IP")
        sys.exit(1)

    # 第四步：添加到 Cloudflare DNS（关键：检查是否至少有 1 个成功）
    added_ips = add_ips_to_dns(clean_ips)
    if not added_ips:
        log.error("❌ DNS 添加全部失败，请检查 CLOUDFLARE_API_TOKEN 权限 / CLOUDFLARE_ZONE_ID / CLOUDFLARE_DOMAIN")
        sys.exit(1)
    log.info(f"成功添加 {len(added_ips)} 个 DNS 记录")

    # 第五步：浏览器复检
    ip_status = verify_proxyips_via_browser()

    # 第六步：清理失败 IP
    cleanup_failed_ips(ip_status)

    # 第七步：CloudflareST 测速
    valid_after_check = [ip for ip, s in ip_status.items() if s == "valid"]
    run_cloudflare_speedtest(valid_after_check)

    log.info("===== 全部完毕 =====")


if __name__ == "__main__":
    main()
