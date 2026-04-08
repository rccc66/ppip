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

FOFA_QUERY = 'server=="cloudflare" && header="Forbidden" && asn=="31898" && country="US"'

ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

MAX_IPS = 3
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


def fofa_search_by_requests():
    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    url = f"https://fofa.info/result?qbase64={qbase64}"
    
    headers = HEADERS.copy()
    headers["Cookie"] = FOFA_COOKIE
    
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, 'html.parser')
    ip_list = []

    for div in soup.select("div.hsxa-ip a.hsxa-jump-a")[:MAX_IPS]:
        ip = div.text.strip()
        if ip:
            ip_list.append(ip)
    
    return ip_list


def abuseipdb_check(ip):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    score = data["data"].get("abuseConfidenceScore", 0)
    return score


def get_existing_record(ip):
    params = {"type": "A", "name": f"{CF_DNS_NAME}.{CF_DOMAIN}"}
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
    r = requests.get(CF_DNS_RECORDS_URL, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    result = r.json()
    for record in result.get("result", []):
        if record["content"] == ip:
            return record
    return None


def create_or_update_dns(ip):
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
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
        "proxied": False
    }
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data, timeout=30)
    resp.raise_for_status()
    print(f"添加 DNS 记录 {record_name} -> {ip}")


def main():
    print("开始从FOFA搜索IP...")
    try:
        ips = fofa_search_by_requests()
        print(f"找到IP: {ips}")
    except Exception as e:
        print(f"FOFA 搜索失败: {e}")
        return

    if not ips:
        print("未找到任何IP")
        return

    clean_ips = []
    for ip in ips:
        try:
            score = abuseipdb_check(ip)
            print(f"IP {ip} 的 AbuseIPDB 评分: {score}")
            if score < ABUSE_THRESHOLD:
                clean_ips.append(ip)
        except Exception as e:
            print(f"检查 IP {ip} 失败: {e}")

    print(f"纯净IP列表: {clean_ips}")

    for ip in clean_ips:
        try:
            create_or_update_dns(ip)
        except Exception as e:
            print(f"添加 DNS 记录失败 {ip}: {e}")


if __name__ == "__main__":
    main()
