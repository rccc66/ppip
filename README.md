# 项目说明

本项目主要用于对目标 IP 进行搜索、筛选与检测，并结合 Cloudflare DNS 完成相关解析管理。

---

## 📌 功能简介

- 支持使用 **FOFA** 搜索目标 IP
- 支持使用 **AbuseIPDB** 查询 IP 信息
- 支持通过自定义接口进行 **代理检测**
- 支持通过 **Cloudflare API** 管理 DNS 解析
- 支持自定义 **FOFA 查询语句**
- 支持自定义 **代理检测地址**

---

## ⚙️ 使用前准备

在运行本项目之前，请先准备好以下信息：

- AbuseIPDB API Key
- Cloudflare API Token
- Cloudflare Zone ID
- Cloudflare 域名与子域名前缀
- FOFA Cookie

> **注意：**
> 变量名请严格按照代码中的名称填写，**不要自行修改变量名**。  
> 特别是以下两个变量名，请保持与代码一致：
>
> - `CCLOUDFLARE_API_TOKEN`
> - `CCLOUDFLARE_DNS_NAME`

---

## 🧩 需要的变量

| 变量名 | 说明 | 示例 |
|---|---|---|
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) 的 API Key，用于查询 IP 信息 | `your_abuseipdb_api_key` |
| `CCLOUDFLARE_API_TOKEN` | Cloudflare 的 API Token | `your_cloudflare_api_token` |
| `CLOUDFLARE_ZONE_ID` | Cloudflare 的 Zone ID（区域 ID） | `your_zone_id` |
| `CCLOUDFLARE_DNS_NAME` | Cloudflare 托管域名的 DNS 前缀，例如：`us` | `us` |
| `CLOUDFLARE_DOMAIN` | Cloudflare 托管的主域名 | `example.com` |
| `FFOFA_COOKIE` | FOFA 的 Cookie | `your_fofa_cookie` |

---

## 📝 环境变量示例

如果你使用本地环境变量或 `.env` 文件，可以参考以下示例：

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
CCLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ZONE_ID=your_zone_id
CCLOUDFLARE_DNS_NAME=us
CLOUDFLARE_DOMAIN=example.com
FFOFA_COOKIE=your_fofa_cookie
```

---

## ☁️ GitHub Actions 配置说明

如果你是通过 **GitHub Actions** 运行本项目，建议将上述变量添加到仓库的 **Secrets** 中：

路径如下：

```text
Settings -> Secrets and variables -> Actions
```

建议添加以下 Secrets：

- `ABUSEIPDB_API_KEY`
- `CCLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`
- `CCLOUDFLARE_DNS_NAME`
- `CLOUDFLARE_DOMAIN`
- `FFOFA_COOKIE`

> 请不要将 API Key、Token 或 Cookie 直接写死在公开代码中。

---

## 🛠 可自定义项

以下两项可以根据自己的需求进行修改：

### 1. FOFA 查询语句

代码第 **19 行**：

```python
FOFA_QUERY = 'server=="cloudflare" && header="Forbidden" && asn=="31898" && country=="US"'
```

你可以根据自己的需求，自定义 FOFA 搜索关键词。

例如：

- 按国家筛选
- 按 ASN 筛选
- 按响应头筛选
- 按服务器特征筛选

---

### 2. 代理检测地址

代码第 **20 行**：

```python
PROXY_CHECK_URL = "https://check.proxyip.cmliussss.net"
```

该地址用于代理查询/检测，你也可以替换为自己的接口地址。

---

## 🌐 域名填写示例

如果你要使用的完整域名是：

```text
us.example.com
```

那么配置应填写为：

```env
CCLOUDFLARE_DNS_NAME=us
CLOUDFLARE_DOMAIN=example.com
```

---

## 🚀 使用方法

### 1. 克隆仓库

```bash
git clone <你的仓库地址>
cd <你的项目目录>
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置环境变量

按上方说明配置所需变量。

### 4. 运行脚本

```bash
python <脚本文件名>.py
```

> 请将 `<你的仓库地址>`、`<你的项目目录>` 和 `<脚本文件名>.py` 替换为你实际项目中的内容。

---

## ❗ 注意事项

> **除以下两项外，其它内容不要擅自修改：**
>
> - `FOFA_QUERY`
> - `PROXY_CHECK_URL`

否则可能会导致脚本运行异常或功能失效。

另外请注意：

- 请妥善保管你的 API Key、Token 和 Cookie
- 不要将敏感信息上传到公开仓库
- 第三方接口可能存在频率限制、风控或失效情况
- 使用前请确保自己的操作符合相关法律法规及平台规则

---

## ⚠️ 免责声明

本项目仅供学习、研究与合法授权场景使用。  
使用者在使用本项目时，应自行承担由此产生的一切风险与责任。  
如因不当使用造成任何问题，与项目作者无关。

---
