import os
os.environ["ORT_LOG_LEVEL"] = "ERROR"

import re, time, json, logging, subprocess, requests, urllib3
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger(__name__)

# ---------- 环境变量 ----------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CF_DNS_NAME = (os.getenv("CLOUDFLARE_DNS_NAME") or "").strip() or "us"
CF_DOMAIN = os.getenv("CLOUDFLARE_DOMAIN")
# 纯净度阈值：只保留评分 == 0 的 IP
ABUSE_THRESHOLD = 0

# PPIP 数据源
PPIP_RESOLVE_URL = "https://ppip.ishtq.de5.net/resolve"
PPIP_CHECK_URL = "https://api.090227.xyz/check"
PPIP_SOURCE_DOMAIN = os.getenv("PPIP_SOURCE_DOMAIN", "ProxyIP.US.CMLiussss.net")
PPIP_CHECK_LIMIT = int((os.getenv("PPIP_CHECK_LIMIT") or "").strip() or "30")
PPIP_CONCURRENCY = int((os.getenv("PPIP_CONCURRENCY") or "").strip() or "10")
# 单次请求超时（秒）—— 30s 太长，200 个 IP / 5 并发 = 1200s 会超 workflow timeout
PPIP_CHECK_TIMEOUT = int((os.getenv("PPIP_CHECK_TIMEOUT") or "").strip() or "15")
# 失败重试次数（避免瞬时网络抖动误删）
PPIP_CHECK_RETRIES = int((os.getenv("PPIP_CHECK_RETRIES") or "").strip() or "1")
# 延迟阈值（毫秒）：复检时延迟超过此值的 IP 也删除，0 表示不启用
# 默认 50，可用 PPIP_MAX_LATENCY_MS 覆盖；设为 0 关闭延迟清理
PPIP_MAX_LATENCY_MS = int((os.getenv("PPIP_MAX_LATENCY_MS") or "").strip() or "50")

CFST_BINARY = os.getenv("CFST_BINARY", "./cfst")

ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"


# ---------- Cloudflare 配置校验 ----------
def _verify_cf_config():
    """启动时校验 Cloudflare 配置，避免做了一堆工作最后 DNS 加不上"""
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    log.info("===== Cloudflare 配置检查 =====")
    log.info(f"  CLOUDFLARE_ZONE_ID: {CF_ZONE_ID}")
    log.info(f"  CLOUDFLARE_DOMAIN: {CF_DOMAIN!r}")
    log.info(f"  CLOUDFLARE_DNS_NAME: {CF_DNS_NAME!r}")
    log.info(f"  拼接的 FQDN: {fqdn!r}")

    if not CF_DOMAIN or "." not in CF_DOMAIN:
        log.error(f"❌ CLOUDFLARE_DOMAIN 不像根域名: {CF_DOMAIN!r}")
        return False
    if not CF_DNS_NAME or not re.match(r'^[a-zA-Z0-9-]+$', CF_DNS_NAME):
        log.error(f"❌ CLOUDFLARE_DNS_NAME 含非法字符: {CF_DNS_NAME!r}")
        return False

    try:
        r = requests.get(f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}",
                         headers={"Authorization": f"Bearer {CF_API_TOKEN}"}, timeout=15)
        if r.status_code == 200:
            zone = r.json().get("result", {})
            zone_name = zone.get("name", "")
            log.info(f"  ✅ Zone: name={zone_name!r}, status={zone.get('status')}")
            if zone_name and zone_name != CF_DOMAIN:
                log.error(f"❌ Zone 实际 name 是 {zone_name!r}，但 CLOUDFLARE_DOMAIN 是 {CF_DOMAIN!r}")
                return False
        elif r.status_code == 403:
            log.error(f"❌ Token 无权限访问 zone（403）")
            return False
        elif r.status_code == 404:
            log.error(f"❌ Zone 不存在（404），CLOUDFLARE_ZONE_ID 错了")
            return False
        else:
            log.error(f"❌ Zone 验证失败 HTTP {r.status_code}")
            return False
    except Exception as e:
        log.error(f"❌ Zone 验证异常: {e}")
        return False
    return True


# ---------- 第一步：从 PPIP 拉取候选 IP ----------
def fetch_ips_from_ppip():
    log.info(f"===== 第一步：从 PPIP 拉取候选 IP =====")
    log.info(f"源域名: {PPIP_SOURCE_DOMAIN}")
    try:
        r = requests.get(PPIP_RESOLVE_URL,
                         params={"proxyip": PPIP_SOURCE_DOMAIN}, timeout=30)
        r.raise_for_status()
        targets = r.json()
    except Exception as e:
        log.error(f"❌ PPIP resolve 失败: {e}")
        return []

    if not isinstance(targets, list):
        log.error(f"❌ PPIP 返回格式异常: {type(targets)}")
        return []

    log.info(f"✅ PPIP 返回 {len(targets)} 个候选目标")
    targets = targets[:PPIP_CHECK_LIMIT]
    log.info(f"限制检测前 {PPIP_CHECK_LIMIT} 个")
    return targets


# ---------- 第二步：批量验证 IP ----------
def _check_one_ip(target):
    """调用 PPIP /check 验证单个 IP，返回详情 dict 或 None。失败重试 PPIP_CHECK_RETRIES 次。"""
    last_err = None
    for attempt in range(PPIP_CHECK_RETRIES + 1):
        try:
            r = requests.get(PPIP_CHECK_URL,
                             params={"proxyip": target}, timeout=PPIP_CHECK_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            if not data.get("success"):
                return None  # 明确失败，不重试
            ipv4 = data.get("probe_results", {}).get("ipv4", {})
            if not ipv4.get("ok"):
                return None  # 明确失败，不重试
            exit_info = ipv4.get("exit") or {}
            return {
                "target": target,
                "ip": target.split(":")[0],
                "exit_ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "asOrganization": exit_info.get("asOrganization"),
                "latency": data.get("responseTime"),
                "colo": data.get("colo"),
            }
        except Exception as e:
            last_err = e
            # 网络异常/超时/429 等才重试；其它直接放弃
            if attempt < PPIP_CHECK_RETRIES:
                time.sleep(1)
                continue
    # 所有重试都失败
    return None


def check_ips_via_ppip(targets, label="第二步"):
    """并发验证 IP，返回有效 IP 详情列表"""
    log.info(f"===== {label}：批量验证 IP（并发 {PPIP_CONCURRENCY}） =====")
    valid_ips = []
    failed_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=PPIP_CONCURRENCY) as ex:
        futures = {ex.submit(_check_one_ip, t): t for t in targets}
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


# ---------- 第三步：AbuseIPDB 纯净度检测 ----------
def abuseipdb_check(ip):
    r = requests.get(ABUSE_CHECK_URL,
                     headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90},
                     timeout=15)
    r.raise_for_status()
    return r.json()["data"]["abuseConfidenceScore"]


def filter_clean_ips(valid_ips):
    """只保留 AbuseIPDB 评分 == 0 的 IP"""
    log.info(f"===== 第三步：AbuseIPDB 纯净度检测（只保留评分=0） =====")
    clean = []
    for idx, item in enumerate(valid_ips, 1):
        ip = item["ip"]
        try:
            score = abuseipdb_check(ip)
            status = "✅" if score == 0 else "❌"
            log.info(f"  [{idx}/{len(valid_ips)}] {status} {ip} 评分: {score}")
            if score == ABUSE_THRESHOLD:
                clean.append(item)
            time.sleep(0.5)
        except Exception as e:
            log.info(f"  [{idx}/{len(valid_ips)}] ❌ {ip} 失败: {e}")
    log.info(f"纯净 IP（评分=0）: {len(clean)} 个")
    return clean


# ---------- Cloudflare DNS 操作 ----------
# 缓存现有 DNS IP 集合，避免每次 create_dns_record 都拉全部记录
_DNS_IP_CACHE = None
_DNS_CACHE_TIME = 0
_DNS_CACHE_TTL = 60  # 缓存 60 秒


def get_dns_records():
    """获取所有 DNS A 记录（自动翻页，避免 >100 条被漏掉）"""
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}",
               "Content-Type": "application/json"}
    all_records = []
    page = 1
    per_page = 200  # Cloudflare API 最大允许 1000，用 200 安全
    while True:
        r = requests.get(CF_DNS_RECORDS_URL, headers=headers,
                         params={"type": "A", "name": fqdn,
                                 "page": page, "per_page": per_page},
                         timeout=15)
        r.raise_for_status()
        data = r.json()
        records = data.get("result", [])
        all_records.extend(records)
        # 检查是否还有下一页
        result_info = data.get("result_info", {})
        total_pages = result_info.get("total_pages", 1)
        if page >= total_pages or not records:
            break
        page += 1
    return all_records


def _get_existing_dns_ips():
    """获取现有 DNS 记录的 IP 集合，带缓存避免每次添加都拉全表"""
    global _DNS_IP_CACHE, _DNS_CACHE_TIME
    now = time.time()
    if _DNS_IP_CACHE is not None and (now - _DNS_CACHE_TIME) < _DNS_CACHE_TTL:
        return _DNS_IP_CACHE
    records = get_dns_records()
    _DNS_IP_CACHE = {r["content"] for r in records if r.get("content")}
    _DNS_CACHE_TIME = now
    return _DNS_IP_CACHE


def _invalidate_dns_cache():
    """添加/删除后让缓存失效"""
    global _DNS_IP_CACHE
    _DNS_IP_CACHE = None


def create_dns_record(ip):
    existing = _get_existing_dns_ips()
    if ip in existing:
        log.info(f"IP {ip} 已存在")
        return
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
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
    # 更新缓存
    existing.add(ip)
    _DNS_IP_CACHE = existing


def delete_dns_record(rid, ip):
    r = requests.delete(f"{CF_DNS_RECORDS_URL}/{rid}",
                        headers={"Authorization": f"Bearer {CF_API_TOKEN}",
                                 "Content-Type": "application/json"},
                        timeout=15)
    r.raise_for_status()
    log.info(f"已删除: {ip}")


def add_ips_to_dns(clean_ips):
    log.info(f"===== 第四步：添加 DNS 记录 =====")
    added = []
    for item in clean_ips:
        try:
            create_dns_record(item["ip"])
            added.append(item["ip"])
        except Exception:
            pass
        time.sleep(0.3)
    log.info(f"添加成功 {len(added)}/{len(clean_ips)} 个 IP")
    return added


# ---------- 第五步：用 PPIP API 复检 IP ----------
def verify_proxyips_via_api():
    """调用 PPIP /check 复检所有 DNS 记录里的 IP。
    返回 (ip_status, latency_map):
      ip_status: {ip: 'valid'/'invalid'}
      latency_map: {ip: latency_ms}
    """
    log.info(f"===== 第五步：用 PPIP API 复检 IP =====")

    records = get_dns_records()
    if not records:
        log.info("无 DNS 记录")
        return {}, {}

    all_ips = [r["content"] for r in records]
    log.info(f"复检 {len(all_ips)} 个 IP")

    targets = [f"{ip}:443" for ip in all_ips]
    valid_results = check_ips_via_ppip(targets, label="复检")

    valid_ips = {r["ip"] for r in valid_results}
    latency_map = {r["ip"]: r.get("latency") for r in valid_results if r.get("latency") is not None}

    log.info(f"复检通过: {len(valid_ips)}/{len(all_ips)}")

    ip_status = {ip: ("valid" if ip in valid_ips else "invalid") for ip in all_ips}
    return ip_status, latency_map


# ---------- 第七步：CloudflareST 测速 ----------
def run_cloudflare_speedtest(valid_ips):
    if not valid_ips:
        log.info("无有效 IP，跳过测速")
        return []
    log.info(f"===== CloudflareST 测速 =====")
    with open("cf_ips.txt", "w") as f:
        for ip in valid_ips:
            f.write(ip + "\n")
    if not os.path.exists(CFST_BINARY):
        log.info(f"未找到 {CFST_BINARY}，跳过测速")
        return []
    cmd = [CFST_BINARY, "-f", "cf_ips.txt", "-o", "cf_speedtest.csv",
           "-n", "200", "-t", "4", "-dn", "10", "-dt", "10", "-tp", "443",
           "-tl", "300", "-sl", "0", "-p", "10", "-allip",
           "-url", "http://speed.cloudflare.com/__down?bytes=99999999"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        for line in (r.stdout or "").splitlines():
            log.info(line)
        for line in (r.stderr or "").splitlines():
            log.info(f"[stderr] {line}")
    except Exception as e:
        log.info(f"测速失败: {e}")
        return []

    results = []
    if os.path.exists("cf_speedtest.csv"):
        try:
            with open("cf_speedtest.csv") as f:
                lines = f.readlines()
            for line in lines[1:]:
                p = [x.strip() for x in line.strip().split(",") if x.strip()]
                if len(p) >= 6:
                    try:
                        speed = float(p[5])
                    except Exception:
                        speed = 0.0
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


# ---------- 第六步：清理失败 + 高延迟 IP ----------
def cleanup_failed_ips(ip_status, latency_map=None):
    """清理失败 IP + 延迟超过 PPIP_MAX_LATENCY_MS 的 IP"""
    latency_map = latency_map or {}

    # 1) 收集失败 IP
    failed = [ip for ip, s in ip_status.items() if s == "invalid"]

    # 2) 收集高延迟 IP
    high_latency = []
    if PPIP_MAX_LATENCY_MS > 0:
        for ip, lat in latency_map.items():
            if lat is not None and lat > PPIP_MAX_LATENCY_MS:
                # 仅当 check 通过但延迟高时，加入清理列表
                if ip_status.get(ip) == "valid":
                    high_latency.append((ip, lat))

    # 3) 合并去重
    to_delete = set(failed) | {ip for ip, _ in high_latency}

    if not to_delete:
        log.info("===== 无需清理 =====")
        return

    log.info(f"===== 清理 {len(to_delete)} 个 IP =====")
    log.info(f"  失败: {len(failed)} 个")
    log.info(f"  高延迟(>{PPIP_MAX_LATENCY_MS}ms): {len(high_latency)} 个")

    if high_latency:
        for ip, lat in high_latency[:10]:  # 只打印前 10 个避免刷屏
            log.info(f"  高延迟示例: {ip} ({lat}ms)")
        if len(high_latency) > 10:
            log.info(f"  ... 还有 {len(high_latency)-10} 个高延迟 IP")

    records = get_dns_records()
    deleted_count = 0
    for r in records:
        if r["content"] in to_delete:
            try:
                delete_dns_record(r["id"], r["content"])
                deleted_count += 1
            except Exception as e:
                log.info(f"删除失败 {r['content']}: {e}")
    log.info(f"已删除 {deleted_count} 个 DNS 记录")


# ---------- 主流程 ----------
def run_cleanup_only():
    """独立清理模式：只跑第五步复检 + 第六步清理，跳过 1-4 步。
    用法：python update_dns.py cleanup
    适合：之前 workflow 超时没清理干净的旧失败记录
    """
    import sys
    if not _verify_cf_config():
        log.error("❌ Cloudflare 配置校验失败")
        sys.exit(1)

    records = get_dns_records()
    if not records:
        log.info("无 DNS 记录可清理")
        return

    log.info(f"===== 独立清理模式：复检 {len(records)} 个 DNS 记录 =====")
    ip_status, latency_map = verify_proxyips_via_api()
    if ip_status:
        cleanup_failed_ips(ip_status, latency_map)
    log.info("===== 清理完毕 =====")


def main():
    import sys
    # 支持 `python update_dns.py cleanup` 子命令
    if len(sys.argv) > 1 and sys.argv[1] == "cleanup":
        return run_cleanup_only()

    if not _verify_cf_config():
        log.error("❌ Cloudflare 配置校验失败")
        sys.exit(1)

    targets = fetch_ips_from_ppip()
    if not targets:
        log.error("❌ 未获取到候选 IP")
        sys.exit(1)

    valid_ips = check_ips_via_ppip(targets, label="第二步")
    if not valid_ips:
        log.error("❌ 无有效 IP")
        sys.exit(1)

    clean_ips = filter_clean_ips(valid_ips)
    if not clean_ips:
        log.error("❌ 无纯净 IP（评分=0）")
        sys.exit(1)

    added_ips = add_ips_to_dns(clean_ips)
    if not added_ips:
        log.error("❌ DNS 添加全部失败")
        sys.exit(1)
    log.info(f"成功添加 {len(added_ips)} 个 DNS 记录")

    # 关键：用 try/finally 保证即使复检异常，cleanup 也会执行
    ip_status = {}
    latency_map = {}
    try:
        ip_status, latency_map = verify_proxyips_via_api()
    except Exception as e:
        log.error(f"❌ 复检异常: {e}")
        log.info("尝试独立清理流程...")
        try:
            ip_status, latency_map = verify_proxyips_via_api()
        except Exception as e2:
            log.error(f"❌ 独立清理也失败: {e2}")

    if ip_status:
        cleanup_failed_ips(ip_status, latency_map)
        # 测速只用通过 + 低延迟的 IP
        valid_after_check = [ip for ip, s in ip_status.items() if s == "valid"
                            and (not latency_map or latency_map.get(ip, 0) <= PPIP_MAX_LATENCY_MS)]
        run_cloudflare_speedtest(valid_after_check)

    log.info("===== 全部完毕 =====")


if __name__ == "__main__":
    main()
