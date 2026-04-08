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
    fqdn = f"{CF_DNS_NAME}.{CF_DOMAIN}"
    print(f"\n===== 第四步：检测 ProxyIP 并清理失败记录 =====")
    print("等待 30 秒让 DNS 生效...")
    time.sleep(30)

    records = get_dns_records()
    if not records:
        print("没有 DNS 记录需要检测")
        return

    all_ips = [r["content"] for r in records]
    print(f"当前 DNS 中的 IP ({len(all_ips)} 个): {all_ips}")

    failed_ips = []

    # 用域名批量检测，尝试多种 URL 格式
    check_urls = [
        f"{PROXY_CHECK_URL}/check?proxyip={fqdn}",
        f"{PROXY_CHECK_URL}/check?proxyip={fqdn}:443",
        f"{PROXY_CHECK_URL}/api/check?proxyip={fqdn}",
    ]

    resp = None
    for check_url in check_urls:
        try:
            print(f"\n尝试检测: {check_url}")
            resp = requests.get(check_url, timeout=120)
            print(f"状态码: {resp.status_code}")
            if resp.status_code == 200:
                print(f"返回内容前 1000 字符:\n{resp.text[:1000]}")
                break
            else:
                print(f"返回: {resp.text[:500]}")
        except Exception as e:
            print(f"请求失败: {e}")

    if resp is None or resp.status_code != 200:
        # GET 失败，尝试 POST
        try:
            print(f"\n尝试 POST 检测...")
            post_url = f"{PROXY_CHECK_URL}/check"
            for content_type, body in [
                ("application/json", {"proxyip": fqdn}),
                ("application/json", {"proxyip": f"{fqdn}:443"}),
                ("application/json", {"ip": fqdn, "port": 443}),
            ]:
                print(f"POST {post_url} body={body}")
                resp = requests.post(post_url, json=body, timeout=120)
                print(f"状态码: {resp.status_code}")
                if resp.status_code == 200:
                    print(f"返回前 1000 字符:\n{resp.text[:1000]}")
                    break
        except Exception as e:
            print(f"POST 失败: {e}")

    if resp and resp.status_code == 200:
        # 尝试解析 JSON
        try:
            data = resp.json()
            print(f"\nJSON 解析成功: {data}")

            # 情况1: 返回 results 数组
            results = None
            for key in ["results", "ips", "data", "ip_results"]:
                if key in data and isinstance(data[key], list):
                    results = data[key]
                    break

            if results:
                for item in results:
                    if isinstance(item, dict):
                        ip = item.get("ip", "")
                        ok = item.get("success", item.get("valid", item.get("status", True)))
                        if ok == False or ok == "error" or ok == "fail" or ok == "failed":
                            if ip:
                                failed_ips.append(ip)
                                print(f"  ❌ {ip} 无效")
                            else:
                                print(f"  ❌ 无效项（无IP）: {item}")
                        else:
                            print(f"  ✅ {ip} 有效")

            # 情况2: 单个结果
            elif "success" in data:
                if data["success"] == False:
                    ip = data.get("ip", "")
                    if ip:
                        failed_ips.append(ip)

        except ValueError:
            # 不是 JSON，解析 HTML
            print("\n返回 HTML，解析中...")
            soup = BeautifulSoup(resp.text, "html.parser")

            # 方法1: 查找 id 匹配 ip-status-line 的元素
            lines = soup.find_all(id=re.compile(r'ip-status-line'))
            if lines:
                print(f"找到 {len(lines)} 个 ip-status-line")
                for line in lines:
                    error = line.find(class_="status-error")
                    copy_btn = line.find(class_="copy-btn")
                    if copy_btn and copy_btn.get("data-copy"):
                        ip = copy_btn["data-copy"]
                        if error:
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                                failed_ips.append(ip)
                                print(f"  ❌ {ip}")
                        else:
                            print(f"  ✅ {ip}")

            # 方法2: 查找 status-error class
            if not lines:
                errors = soup.find_all(class_="status-error")
                print(f"找到 {len(errors)} 个 status-error 元素")
                for err in errors:
                    parent = err.find_parent("div")
                    while parent:
                        copy_btn = parent.find(class_="copy-btn")
                        if copy_btn and copy_btn.get("data-copy"):
                            ip = copy_btn["data-copy"]
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                                failed_ips.append(ip)
                                print(f"  ❌ {ip}")
                            break
                        parent = parent.find_parent("div")

    failed_ips = list(dict.fromkeys(failed_ips))

    if not failed_ips:
        print("\n未检测到失败 IP，无需清理")
        return

    print(f"\n需要删除的失败 IP: {failed_ips}")
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
