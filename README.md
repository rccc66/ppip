# 配置说明

在使用本项目之前，请先正确配置以下变量。

## 需要的变量

| 变量名 | 说明 | 示例 |
|---|---|---|
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) 的 API Key，用于查询 IP 信息 | `your_abuseipdb_api_key` |
| `CCLOUDFLARE_API_TOKEN` | Cloudflare 的 API Token | `your_cloudflare_api_token` |
| `CLOUDFLARE_ZONE_ID` | Cloudflare 的 Zone ID（区域 ID） | `your_zone_id` |
| `CCLOUDFLARE_DNS_NAME` | Cloudflare 托管域名的 DNS 前缀，例如：`us` | `us` |
| `CLOUDFLARE_DOMAIN` | Cloudflare 托管的域名 | `example.com` |
| `FFOFA_COOKIE` | FOFA 的 Cookie | `your_fofa_cookie` |

---

## 环境变量示例

如需通过环境变量配置，可参考以下示例：

```bash
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
CCLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ZONE_ID=your_zone_id
CCLOUDFLARE_DNS_NAME=us
CLOUDFLARE_DOMAIN=example.com
FFOFA_COOKIE=your_fofa_cookie
