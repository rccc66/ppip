import os
import requests
import base64
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CF_DNS_NAME = os.getenv("CLOUDFLARE_DNS_NAME", "us")
CF_DOMAIN = os.getenv("CLOUDFLARE_DOMAIN")

FOFA_QUERY = 'server=="cloudflare" && header="Forbidden" && asn=="31898" && country="US"'
FOFA_SEARCH_URL = "https://fofa.info/"

ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CF_DNS_RECORDS_URL = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

MAX_IPS = 3
ABUSE_THRESHOLD = 20


def fofa_search_web():
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    ips = []

    try:
        driver.get(FOFA_SEARCH_URL)

        wait = WebDriverWait(driver, 20)
        textarea = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "textarea.fofa-search-input-textarea"))
        )
        textarea.clear()
        textarea.send_keys(FOFA_QUERY)

        submit = driver.find_element(By.CSS_SELECTOR, '[data-testid="home-search-submit"] button')
        submit.click()

        wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, "div.hsxa-ip a.hsxa-jump-a")))

        time.sleep(3)

        ip_nodes = driver.find_elements(By.CSS_SELECTOR, "div.hsxa-ip a.hsxa-jump-a")

        for ip_node in ip_nodes[:MAX_IPS]:
            ip_text = ip_node.text.strip()
            if ip_text:
                ips.append(ip_text)

    finally:
        driver.quit()

    return ips


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
    resp = requests.post(CF_DNS_RECORDS_URL, headers=headers, json=data)
    resp.raise_for_status()
    print(f"添加 DNS 记录 {record_name} -> {ip}")


def main():
    print("开始从FOFA网页搜索IP...")
    ips = fofa_search_web()
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
