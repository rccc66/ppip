import os
import requests
import base64
import time
import re
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

ABUSE_THRESHOLD = 20

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Referer": "https://fofa.info/",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-GPC": "1"
}


# ========== FOFA 搜索 ==========
def fofa_search():
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    url = f"https://fofa.info/result?qbase64={qbase64}"

    headers = HEADERS.copy()
    headers["Cookie"] = FOFA_COOKIE

    print(f"请求 FOFA: {url}")
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")

    # 从 hsxa-ip div 中提取 IP
    ips = []
    ip_divs = soup.find_all("div", class_="hsxa-ip")
    for div in ip_divs:
        a_tags = div.find_all("a", class_="hsxa-jump-a")
        for a in a_tags:
            if a.get("style") and "display:none" in a.get("style", ""):
                continue
            ip_text = a.get_text(strip=True)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_text):
                ips.append(ip_text)
                break

    # 去重
    ips = list(dict.fromkeys(ips))
    print(f"提取到 {len(ips)} 个去重IP")
    return ips


# ========== AbuseIPDB 检测 ==========
def abuseipdb_check(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()["data"]["abuseConfidenceScore"]


# ========== Cloudflare DNS ==========
def get_dns_records():
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    params = {"type": "A", "name": fqdn}
    resp = requests.get(CF_DNS_RECORDS_URL, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json().get("result", [])


def create_dns_record(ip):
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"

    existing = get_dns_records()
    for r in existing:
        if r["content"] == ip:
            print(f"IP {ip} 已存在，跳过")
            return

    data = {"type": "A", "name": fqdn, "content": ip, "ttl": 1, "proxied": False}
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data, timeout=15)
    resp.raise_for_status()
    print(f"已添加 DNS: {fqdn} -> {ip}")


def delete_dns_record(record_id, ip):
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    url = f"{CF_DNS_RECORDS_URL}/{record_id}"
    resp = requests.delete(url, headers=headers, timeout=15)
    resp.raise_for_status()
    print(f"已删除 DNS 记录: {ip}")


# ========== ProxyIP 检测并清理 ==========
def cleanup_failed_ips():
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    print(f"\n===== 第四步：检测 ProxyIP 并清理失败记录 =====")
    print(f"等待 30 秒让 DNS 生效...")
    time.sleep(30)

    # 获取当前所有 DNS 记录
    records = get_dns_records()
    if not records:
        print("没有 DNS 记录需要检测")
        return

    all_ips = [r["content"] for r in records]
    print(f"当前 DNS 记录中的 IP: {all_ips}")

    # 逐个检测每个 IP
    failed_ips = []
    for ip in all_ips:
        try:
            check_url = f"{PROXY_CHECK_URL}/check?ip={ip}&port=443"
            print(f"检测 IP: {ip}")
            resp = requests.get(check_url, timeout=30)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    print(f"  返回: {data}")
                    if data.get("success") == False:
                        failed_ips.append(ip)
                        print(f"  ❌ IP {ip} 检测失败")
                    else:
                        print(f"  ✅ IP {ip} 检测通过")
                except:
                    # 如果不是 JSON，尝试解析 HTML
                    soup = BeautifulSoup(resp.text, "html.parser")
                    error_icons = soup.find_all(class_="status-error")
                    if error_icons:
                        failed_ips.append(ip)
                        print(f"  ❌ IP {ip} 检测失败（HTML）")
                    else:
                        print(f"  ✅ IP {ip} 检测通过（HTML）")
            else:
                failed_ips.append(ip)
                print(f"  ❌ IP {ip} 请求失败: {resp.status_code}")
        except Exception as e:
            print(f"  检测 IP {ip} 出错: {e}")
            failed_ips.append(ip)

    # 如果没有单独检测接口，尝试批量检测
    if not failed_ips:
        try:
            check_url = f"{PROXY_CHECK_URL}/check?proxyip={fqdn}"
            print(f"\n尝试批量检测: {check_url}")
            resp = requests.get(check_url, timeout=60)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    print(f"批量检测返回: {data}")
                    # 解析批量结果中的失败 IP
                    if isinstance(data, dict):
                        results = data.get("results", data.get("ips", []))
                        if isinstance(results, list):
                            for item in results:
                                if isinstance(item, dict):
                                    ip = item.get("ip", "")
                                    success = item.get("success", item.get("valid", True))
                                    if not success and ip:
                                        failed_ips.append(ip)
                except:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    error_items = soup.find_all(class_="status-error")
                    for item in error_items:
                        parent = item.find_parent(class_="ip-item") or item.find_parent("div")
                        if parent:
                            copy_btn = parent.find(class_="copy-btn")
                            if copy_btn and copy_btn.get("data-copy"):
                                ip = copy_btn["data-copy"]
                                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                                    failed_ips.append(ip)
        except Exception as e:
            print(f"批量检测出错: {e}")

    # 去重
    failed_ips = list(dict.fromkeys(failed_ips))

    if not failed_ips:
        print("所有 IP 检测正常，无需清理")
        return

    print(f"\n需要删除的失败 IP: {failed_ips}")
    for record in records:
        if record["content"] in failed_ips:
            try:
                delete_dns_record(record["id"], record["content"])
            except Exception as e:
                print(f"删除记录失败 {record['content']}: {e}")


# ========== 主流程 ==========
def main():
    print("===== 第一步：从 FOFA 搜索 IP =====")
    ips = fofa_search()
    print(f"找到 {len(ips)} 个IP: {ips}")

    if not ips:
        print("未找到任何IP")
        return

    print("\n===== 第二步：AbuseIPDB 纯净度检测 =====")
    clean_ips = []
    for idx, ip in enumerate(ips, 1):
        try:
            score = abuseipdb_check(ip)
            print(f"[{idx}/{len(ips)}] IP {ip} 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean_ips.append(ip)
            time.sleep(0.5)
        except Exception as e:
            print(f"检查 IP {ip} 失败: {e}")

    print(f"\n纯净IP（共 {len(clean_ips)} 个）: {clean_ips}")

    if not clean_ips:
        print("没有纯净 IP，跳过 DNS 添加")
        return

    print("\n===== 第三步：添加 Cloudflare DNS 记录 =====")
    for ip in clean_ips:
        try:
            create_dns_record(ip)
            time.sleep(0.5)
        except Exception as e:
            print(f"添加 DNS 失败 {ip}: {e}")

    cleanup_failed_ips()

    print("\n===== 全部完成 =====")


if __name__ == "__main__":
    main()
