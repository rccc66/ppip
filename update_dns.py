import os
import requests
import base64
import time
from bs4 import BeautifulSoup

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CF_DNS_NAME = os.getenv("CLOUDFLARE_DNS_NAME", "us")
CF_DOMAIN = os.getenv("CLOUDFLARE_DOMAIN")
FOFA_COOKIE = os.getenv("FOFA_COOKIE")

FOFA_QUERY = 'server=="cloudflare" && header=="Forbidden" && asn=="31898" && country=="US"'
PROXY_CHECK_URL = "https://pp.rr66.workers.dev"

ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

MAX_IPS = 100
ABUSE_THRESHOLD = 20

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Referer": "https://fofa.info/",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-GPC": "1"
}


# ========== FOFA 搜索（支持分页） ==========
def fofa_search_all():
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    headers = HEADERS.copy()
    headers["Cookie"] = FOFA_COOKIE

    all_ips = []
    page = 1
    page_size = 100

    print(f"开始从 FOFA 分页搜索IP（最多获取 {MAX_IPS} 个）...")

    while len(all_ips) < MAX_IPS:
        url = f"https://fofa.info/result?qbase64={qbase64}&after=7d&sort=update_time&page={page}&size={page_size}"
        print(f"FOFA 搜索第 {page} 页...")

        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            print(f"第 {page} 页请求失败: {e}")
            break

        soup = BeautifulSoup(resp.text, "html.parser")
        ip_nodes = soup.select("div.hsxa-ip a.hsxa-jump-a")
        ips = [node.text.strip() for node in ip_nodes if node.text.strip()]

        if not ips:
            print("无更多IP，停止分页")
            break

        all_ips.extend(ips)
        print(f"第 {page} 页获取 {len(ips)} 个IP，累计 {len(all_ips)} 个")

        # 如果本页获取的IP少于page_size，说明没有下一页
        if len(ips) < page_size:
            print("已到最后一页")
            break

        page += 1
        time.sleep(1)  # 避免请求过快

    # 去重并限制数量
    all_ips = list(dict.fromkeys(all_ips))[:MAX_IPS]
    print(f"总共获取 {len(all_ips)} 个去重后的IP")
    return all_ips


# ========== AbuseIPDB 检测 ==========
def abuseipdb_check(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["data"].get("abuseConfidenceScore", 0)


# ========== Cloudflare DNS 操作 ==========
def get_all_dns_records():
    name = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
    params = {"type": "A", "name": name}
    r = requests.get(CF_DNS_RECORDS_URL, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    return r.json().get("result", [])


def get_existing_record(ip):
    for record in get_all_dns_records():
        if record["content"] == ip:
            return record
    return None


def create_dns_record(ip):
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    }
    record_name = f"{CF_DNS_NAME}.{CF_DOMAIN}"

    existing = get_existing_record(ip)
    if existing:
        print(f"IP {ip} 已有对应 DNS 记录，无需新增")
        return

    data = {
        "type": "A",
        "name": record_name,
        "content": ip,
        "ttl": 120,
        "proxied": False,
    }
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data, timeout=30)
    resp.raise_for_status()
    print(f"添加 DNS 记录 {record_name} -> {ip}")


def delete_dns_record(record_id, ip):
    url = f"{CF_DNS_RECORDS_URL}/{record_id}"
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
    resp = requests.delete(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        print(f"已删除 DNS 记录: {ip}")
    else:
        print(f"删除 DNS 记录失败 {ip}: {resp.text}")


# ========== ProxyIP 检测 ==========
def check_proxy_ip():
    record_name = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    check_url = f"{PROXY_CHECK_URL}/check"

    print(f"正在检测 ProxyIP: {record_name}")

    # 尝试 GET 请求
    try:
        resp = requests.get(
            check_url,
            params={"proxyip": record_name},
            headers={"User-Agent": HEADERS["User-Agent"]},
            timeout=60,
        )
        resp.raise_for_status()
    except Exception as e:
        print(f"GET 请求失败，尝试 POST: {e}")
        try:
            resp = requests.post(
                check_url,
                json={"proxyip": record_name},
                headers={
                    "User-Agent": HEADERS["User-Agent"],
                    "Content-Type": "application/json",
                },
                timeout=60,
            )
            resp.raise_for_status()
        except Exception as e2:
            print(f"POST 请求也失败: {e2}")
            return []

    failed_ips = []

    try:
        data = resp.json()
        print(f"ProxyIP 检测返回: {data}")

        # 检查 success 字段
        if not data.get("success"):
            print("检测失败，标记所有 IP 为失败")
            records = get_all_dns_records()
            for record in records:
                failed_ips.append(record["content"])
            return failed_ips

        # 如果返回了 ips 列表
        if "ips" in data:
            for item in data.get("ips", []):
                ip = item.get("ip", "")
                status = item.get("status", "")
                if status in ("error", "fail", "failed", False):
                    failed_ips.append(ip)

        # 如果返回了 results 列表
        if "results" in data:
            for item in data.get("results", []):
                ip = item.get("ip", "")
                status = item.get("status", "")
                if status in ("error", "fail", "failed", False):
                    failed_ips.append(ip)

    except ValueError:
        # 不是 JSON，尝试解析 HTML
        print("返回非 JSON，尝试解析 HTML...")
        soup = BeautifulSoup(resp.text, "html.parser")
        ip_items = soup.select("div.ip-item")
        for item in ip_items:
            ip_span = item.select_one("span.copy-btn[data-copy]")
            error_icon = item.select_one("span.status-icon.status-error")
            if ip_span and error_icon:
                ip = ip_span["data-copy"].strip()
                failed_ips.append(ip)

    return failed_ips


def cleanup_failed_ips():
    print("\n===== 开始检测 ProxyIP 状态 =====")

    # 等待 DNS 生效
    print("等待 30 秒让 DNS 记录生效...")
    time.sleep(30)

    failed_ips = check_proxy_ip()

    if not failed_ips:
        print("所有 IP 检测正常，无需清理")
        return

    print(f"检测到失败的 IP: {failed_ips}")

    records = get_all_dns_records()
    for record in records:
        if record["content"] in failed_ips:
            print(f"删除失败 IP 的 DNS 记录: {record['content']}")
            delete_dns_record(record["id"], record["content"])


# ========== 主流程 ==========
def main():
    # 第一步：FOFA 搜索（分页）
    print("===== 第一步：从 FOFA 分页搜索 IP（最近一周更新） =====")
    try:
        ips = fofa_search_all()
        print(f"找到 {len(ips)} 个IP: {ips}")
    except Exception as e:
        print(f"FOFA 搜索失败: {e}")
        return

    if not ips:
        print("未找到任何IP")
        return

    # 第二步：AbuseIPDB 纯净度检测
    print("\n===== 第二步：AbuseIPDB 纯净度检测 =====")
    clean_ips = []
    for idx, ip in enumerate(ips, 1):
        try:
            score = abuseipdb_check(ip)
            print(f"[{idx}/{len(ips)}] IP {ip} 的 AbuseIPDB 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean_ips.append(ip)
            time.sleep(0.5)  # 避免API请求过快
        except Exception as e:
            print(f"检查 IP {ip} 失败: {e}")

    print(f"\n纯净IP列表（共 {len(clean_ips)} 个）: {clean_ips}")

    if not clean_ips:
        print("没有纯净 IP，跳过 DNS 添加")
        return

    # 第三步：添加 DNS 记录
    print("\n===== 第三步：添加 Cloudflare DNS 记录 =====")
    for ip in clean_ips:
        try:
            create_dns_record(ip)
            time.sleep(0.5)
        except Exception as e:
            print(f"添加 DNS 记录失败 {ip}: {e}")

    # 第四步：检测 ProxyIP 并清理失败记录
    cleanup_failed_ips()

    print("\n===== 全部完成 =====")


if __name__ == "__main__":
    main()
