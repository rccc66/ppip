import os
import requests
import base64

FOFA_EMAIL = os.getenv("FOFA_EMAIL")
FOFA_API_KEY = os.getenv("FOFA_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CF_DNS_NAME = os.getenv("CLOUDFLARE_DNS_NAME", "us")  # 默认 us.example.com
CF_DOMAIN = os.getenv("CLOUDFLARE_DOMAIN")  # 你的主域名，比如 example.com

FOFA_QUERY = 'server=="cloudflare" && header="Forbidden" && asn=="31898" && country="US"'
FOFA_SEARCH_URL = "https://fofa.info/api/v1/search/all"

ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

MAX_IPS = 3
ABUSE_THRESHOLD = 20


def fofa_search():
    query_b64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    params = {
        "email": FOFA_EMAIL,
        "key": FOFA_API_KEY,
        "qbase64": query_b64,
        "fields": "ip"
    }
    resp = requests.get(FOFA_SEARCH_URL, params=params)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("results"):
        return []
    ips = [item[0] for item in data["results"] if item and item[0]]
    return ips[:MAX_IPS]


def abuseipdb_check(ip):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params)
    resp.raise_for_status()
    data = resp.json()
    score = data["data"].get("abuseConfidenceScore", 0)
    return score


def get_existing_record(ip):
    params = {"type": "A", "name": f"{CF_DNS_NAME}.{CF_DOMAIN}"}
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
    r = requests.get(CF_DNS_RECORDS_URL, headers=headers, params=params)
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

    # 先查看是否已有当前 IP 的记录
    existing = get_existing_record(ip)
    if existing:
        print(f"IP {ip} 已有对应 DNS 记录，无需新增")
        return
    
    # 新增记录
    data = {
        "type": "A",
        "name": record_name,
        "content": ip,
        "ttl": 120,  # 2分钟 ttl
        "proxied": False
    }
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data)
    resp.raise_for_status()
    print(f"添加 DNS 记录 {record_name} -> {ip}")


def main():
    print("开始从FOFA搜索IP...")
    ips = fofa_search()
    print(f"找到IP: {ips}")
    
    clean_ips = []
    for ip in ips:
        score = abuseipdb_check(ip)
        print(f"IP {ip} 的 AbuseIPDB 评分: {score}")
        if score < ABUSE_THRESHOLD:
            clean_ips.append(ip)
    
    print(f"纯净IP列表: {clean_ips}")

    for ip in clean_ips:
        create_or_update_dns(ip)


if __name__ == "__main__":
    main()
