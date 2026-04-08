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


def fofa_search():
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    url = f"https://fofa.info/result?qbase64={qbase64}"
    headers = HEADERS.copy()
    headers["Cookie"] = FOFA_COOKIE
    print(f"请求 FOFA: {url}")

    resp = None
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            break
        except requests.exceptions.ReadTimeout:
            print(f"超时，第 {attempt+1}/3 次重试...")
            if attempt == 2:
                return []
            time.sleep(5)
        except Exception as e:
            print(f"请求失败: {e}")
            if attempt == 2:
                return []
            time.sleep(5)

    if resp is None:
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    ips = []
    for div in soup.find_all("div", class_="hsxa-ip"):
        for a in div.find_all("a", class_="hsxa-jump-a"):
            if a.get("style") and "display:none" in a.get("style", ""):
                continue
            ip_text = a.get_text(strip=True)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_text):
                ips.append(ip_text)
                break

    ips = list(dict.fromkeys(ips))
    print(f"提取到 {len(ips)} 个去重IP")
    return ips


def abuseipdb_check(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()["data"]["abuseConfidenceScore"]


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
            print(f"IP {ip} 已存在，跳过")
            return
    data = {"type": "A", "name": fqdn, "content": ip, "ttl": 1, "proxied": False}
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data, timeout=15)
    resp.raise_for_status()
    print(f"已添加 DNS: {fqdn} -> {ip}")


def delete_dns_record(record_id, ip):
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    resp = requests.delete(f"{CF_DNS_RECORDS_URL}/{record_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    print(f"已删除 DNS 记录: {ip}")


def cleanup_failed_ips():
    print(f"\n===== 第四步：检测 ProxyIP 并清理失败记录 =====")
    print("等待 30 秒让 DNS 生效...")
    time.sleep(30)

    records = get_dns_records()
    if not records:
        print("没有 DNS 记录需要检测")
        return

    all_ips = [r["content"] for r in records]
    print(f"当前 DNS 中的 IP ({len(all_ips)} 个): {all_ips}\n")

    failed_ips = []

    # 逐个检测每个 IP
    for ip in all_ips:
        try:
            check_url = f"{PROXY_CHECK_URL}/check?proxyip={ip}:443"
            resp = requests.get(check_url, timeout=30)
            resp.raise_for_status()

            data = resp.json()
            success = data.get("success", False)
            response_time = data.get("responseTime", -1)
            message = data.get("message", "")

            if success:
                print(f"✅ {ip} 有效 ({response_time}ms)")
            else:
                print(f"❌ {ip} 无效 - {message}")
                failed_ips.append(ip)

        except Exception as e:
            print(f"❌ {ip} 检测出错: {e}")
            failed_ips.append(ip)

        time.sleep(1)

    if not failed_ips:
        print("\n所有 IP 检测正常，无需清理")
        return

    print(f"\n需要删除的失败 IP ({len(failed_ips)} 个): {failed_ips}")
    for record in records:
        if record["content"] in failed_ips:
            try:
                delete_dns_record(record["id"], record["content"])
            except Exception as e:
                print(f"删除失败 {record['content']}: {e}")


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
            print(f"[{idx}/{len(ips)}] {ip} 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean_ips.append(ip)
            time.sleep(0.5)
        except Exception as e:
            print(f"检查 {ip} 失败: {e}")

    print(f"\n纯净IP（{len(clean_ips)} 个）: {clean_ips}")
    if not clean_ips:
        print("没有纯净 IP，跳过")
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
