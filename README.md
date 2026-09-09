# 项目说明

本项目通过 **ProxyIP 检测接口** 拉取候选 IP，结合 **AbuseIPDB** 过滤纯净 IP，再用 **Cloudflare API** 自动维护 DNS 解析，并通过 **CloudflareST** 进行真实下载测速。

整个流程完全基于 HTTP API，**不需要浏览器、不需要登录、不需要解验证码**。

---

## 📌 功能简介

- ✅ 从 **PPIP** 检测接口拉取候选 IP 列表
- ✅ 并发调用 **ProxyIP Check API** 验证 IP 可用性（含出口信息）
- ✅ 通过 **AbuseIPDB** 过滤纯净 IP（仅保留评分 `0` 的 IP）
- ✅ 通过 **Cloudflare API** 自动添加 / 删除 DNS A 记录
- ✅ DNS 生效后再次用 **ProxyIP Check API** 复检
- ✅ 用 **CloudflareST** 对存活 IP 做真实下载测速并排序
- ✅ 自动清理失败的 DNS 记录

---

## ⚙️ 使用前准备

在运行本项目之前，请准备好以下信息：

- [AbuseIPDB](https://www.abuseipdb.com/) 的 API Key
- [Cloudflare](https://dash.cloudflare.com/) 的 API Token（需有 Zone.DNS 编辑权限）
- Cloudflare 的 Zone ID
- Cloudflare 托管的根域名 + 子域名前缀

> **变量名请严格按照下表填写，不要自行修改。**

---

## 🧩 需要的变量

| 变量名 | 必填 | 说明 | 示例 |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | ✅ | [AbuseIPDB](https://www.abuseipdb.com/) 的 API Key，用于查询 IP 纯净度 | `your_abuseipdb_api_key` |
| `CLOUDFLARE_API_TOKEN` | ✅ | Cloudflare API Token（需 Zone.DNS 编辑权限） | `your_cloudflare_api_token` |
| `CLOUDFLARE_ZONE_ID` | ✅ | Cloudflare 的 Zone ID | `your_zone_id` |
| `CLOUDFLARE_DOMAIN` | ✅ | Cloudflare 托管的**根域名**（不是子域名） | `your-domain.com` |
| `CLOUDFLARE_DNS_NAME` | ❌ | 子域名前缀，默认 `us` | `us` |
| `PPIP_SOURCE_DOMAIN` | ❌ | ProxyIP 候选 IP 源域名 | `your-ProxyIP-source-domain` |
| `PPIP_CHECK_LIMIT` | ❌ | 检测的 IP 数量上限，默认 `30` | `30` |
| `PPIP_CONCURRENCY` | ❌ | 并发数，默认 `5` | `5` |
| `CFST_BINARY` | ❌ | CloudflareST 二进制路径，默认 `./cfst` | `./cfst` |

---

## 📝 环境变量示例

如果你使用本地环境变量或 `.env` 文件，可以参考以下示例：

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ZONE_ID=your_zone_id
CLOUDFLARE_DNS_NAME=us
CLOUDFLARE_DOMAIN=your-domain.com
PPIP_SOURCE_DOMAIN=your-ProxyIP-source-domain
PPIP_CHECK_LIMIT=30
PPIP_CONCURRENCY=5
```

---

## ☁️ GitHub Actions 配置说明

如果你通过 **GitHub Actions** 运行本项目，请将上述变量添加到仓库的 **Secrets** 中：

```text
Settings → Secrets and variables → Actions
```

建议添加以下 Secrets：

**必填：**
- `ABUSEIPDB_API_KEY`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`
- `CLOUDFLARE_DOMAIN`

**可选：**
- `CLOUDFLARE_DNS_NAME`
- `PPIP_SOURCE_DOMAIN`
- `PPIP_CHECK_LIMIT`
- `PPIP_CONCURRENCY`

> 请不要将 API Key 或 Token 直接写死在公开代码中。

---

## 🛠 可自定义项(所有自定义推荐使用变量进行更换，非必要不要更改代码)

以下两项可以根据自己的需求修改（在 `update_dns.py` 顶部）：

### 1. PProxyIP 候选 IP 源域名

```python
PPIP_SOURCE_DOMAIN = os.getenv("ProxyIP_SOURCE_DOMAIN", "your-ProxyIP-source-domain")
```

可替换为其它 PPIP 支持的源域名。

---

### 2. 纯净度阈值

```python
ABUSE_THRESHOLD = 0
```

默认 `0` 表示只保留 AbuseIPDB 评分为 0 的 IP。如果想放宽，可改成 `5` 或 `10`。

---

## 🌐 域名填写示例

如果你要使用的完整域名是：

```text
us.your-domain.com
```

那么配置应填写为：

```env
CLOUDFLARE_DNS_NAME=us
CLOUDFLARE_DOMAIN=your-domain.com
```

> ⚠️ **重要**：`CLOUDFLARE_DOMAIN` 必须是 Cloudflare 上的 Zone 根域名，**不要**填子域名（如 `us.your-domain.com`），否则会报 `DNS name is invalid (9000)` 错误。

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

> 依赖只有一个：`requests`

### 3. 配置环境变量

按上方说明配置所需变量。

### 4. 运行脚本

```bash
python update_dns.py
```

### 5. （可选）配置 CloudflareST 测速

如果需要第七步测速，请把 `cfst` 二进制放到项目根目录（或通过 `CFST_BINARY` 指定路径）：

```bash
# 下载 cfst (CloudflareSpeedTest)
wget https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/cst_linux_amd64.tar.gz
tar -xzf cst_linux_amd64.tar.gz
mv cst cfst
chmod +x cfst
```

---

## 🔄 工作流程

```
第 0 步：Cloudflare 配置校验（验证 Token / Zone / 域名）
   ↓
第 1 步：从 ProxyIP /resolve 拉取候选 IP（约 50 个）
   ↓
第 2 步：并发调用 ProxyIP /check 验证 IP 可用性
   ↓
第 3 步：AbuseIPDB 检测，只保留评分=0 的 IP
   ↓
第 4 步：添加到 Cloudflare DNS（A 记录）
   ↓
等 30 秒 DNS 生效
   ↓
第 5 步：再次 ProxyIP /check 复检所有 DNS 记录
   ↓
第 6 步：清理失败的 DNS 记录
   ↓
第 7 步：CloudflareST 真实下载测速 + 排序
```

---

## ❗ 注意事项

- 请妥善保管你的 API Key、Token
- 不要将敏感信息上传到公开仓库
- 第三方接口（ProxyIP / AbuseIPDB）可能存在频率限制
- AbuseIPDB 免费账户每天有查询次数限制（默认 1000 次/天）
- ProxyIP 候选 IP 来自公开接口，可用性随时变化
- 使用前请确保自己的操作符合相关法律法规及平台规则

---

## 🐛 常见问题

### Q1: 报错 `DNS name is invalid (9000)`

`CLOUDFLARE_DOMAIN` 必须是根域名，不能是子域名。

❌ 错误：`CLOUDFLARE_DOMAIN=us.your-domain.com`
✅ 正确：`CLOUDFLARE_DOMAIN=your-domain.com`

### Q2: 报错 `Zone 不存在（404）`

`CLOUDFLARE_ZONE_ID` 配错了，去 Cloudflare Dashboard → 你的网站 → Overview 页面右侧找 Zone ID。

### Q3: 报错 `Token 无权限访问 zone（403）`

API Token 缺权限。去 Cloudflare → My Profile → API Tokens 创建新 Token，权限选：
- `Zone - DNS - Edit`
- `Zone - Zone - Read`

### Q4: 第三步过滤后 IP 数量为 0

所有 IP 的 AbuseIPDB 评分都不为 0。可以：
1. 临时把 `ABUSE_THRESHOLD` 改成 `5` 或 `10`
2. 或把 `PPIP_CHECK_LIMIT` 调到 `50` 拿更多候选

### Q5: 第七步测速跳过

没找到 `cfst` 二进制。按上面的"配置 CloudflareST 测速"步骤下载。

---

## ⚠️ 免责声明

本项目仅供学习、研究与合法授权场景使用。  
使用者在使用本项目时，应自行承担由此产生的一切风险与责任。  
如因不当使用造成任何问题，与项目作者无关。
