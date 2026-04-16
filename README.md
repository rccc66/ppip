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
可自定义项
以下两项可根据个人需求自行修改：

1. FOFA 查询语句
代码第 19 行：

<PYTHON>
FOFA_QUERY = 'server=="cloudflare" && header="Forbidden" && asn=="31898" && country=="US"'
你可以根据自己的需求修改 FOFA 搜索关键词。

2. 代理检测地址
代码第 20 行：

<PYTHON>
PROXY_CHECK_URL = "https://check.proxyip.cmliussss.net"
该地址用于代理查询/检测，也可以替换为你自己的接口地址。

注意事项
除了上述说明中提到的内容外，其它部分请不要擅自修改，以免影响脚本正常运行。
