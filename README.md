# Leak Sentinel

面向企业安全团队的泄漏监控服务。持续搜索指定的企业域名、电子邮箱和用户名；数据源出现新的泄漏记录时，通过钉钉、企业微信或邮件告警。

> 仅用于监控本人或已获授权的组织资产。项目保存查询目标的加密值、结果元数据和去重指纹，不应用于收集或传播泄漏凭据。

## 功能

- 域名、邮箱、用户名、密码、API 密钥、令牌六类监控对象
- Hudson Rock Community OSINT：域名、邮箱、用户名的 infostealer 暴露统计
- Have I Been Pwned v3：邮箱泄漏事件（需要 HIBP API Key）
- XposedOrNot：免费免密的邮箱泄漏分析
- LeakCheck：免费查询邮箱、用户名的泄漏来源和字段；可选 Pro API Key
- 定时或立即扫描；SHA-256 内容指纹去重，只对新增结果告警
- 资产拖动排序；手动检测后 24 小时内自动任务跳过，保证每天最多自动检查一次
- 情报源独立状态图标、命中数量和第三方接口调用日志
- 每条资产可选择全网监控或仅关注指定网站（支持 `example.com`、`*.example.com`）；调用日志记录原始返回、有效命中和过滤数量
- 泄漏详情展示事件日期、关联网站和泄漏数据类别（以数据源实际返回为准）
- 钉钉机器人（支持加签）、企业微信机器人、SMTP 邮件
- Fernet 加密敏感配置和监控值
- FastAPI、SQLite/PostgreSQL、Python 虚拟环境和 systemd

## LXC 原生部署

适用于 Debian 12、Ubuntu 22.04/24.04 LXC。建议容器至少分配 1 核 CPU、1 GB 内存和 5 GB 磁盘。

```bash
apt-get update && apt-get install -y git
git clone https://github.com/bobxzy-0/leak-sentinel.git
cd leak-sentinel
sudo bash deploy/install-lxc.sh
```

生成密钥并编辑配置：

```bash
/opt/leak-sentinel/.venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
openssl rand -hex 32
nano /etc/leak-sentinel/leak-sentinel.env
systemctl enable --now leak-sentinel
systemctl status leak-sentinel
journalctl -u leak-sentinel -f
```

LXC 模板默认监听 `0.0.0.0:8000`。可在 `/etc/leak-sentinel/leak-sentinel.env` 自定义：

```env
APP_HOST=0.0.0.0
APP_PORT=8080
```

修改后执行 `systemctl restart leak-sentinel`。健康检查示例：`curl http://127.0.0.1:8080/health`，API 文档：`http://LXC-IP:8080/docs`。

`APP_HOST=0.0.0.0` 会监听 LXC 的所有网络接口，请使用防火墙限制来源。生产环境更建议改为 `127.0.0.1`，安装 Nginx 并参考 `deploy/nginx.conf.example` 配置反向代理及 HTTPS。

### 更新版本

```bash
cd /root/leak-sentinel
git pull --ff-only
sudo bash deploy/install-lxc.sh
sudo systemctl restart leak-sentinel
```

```bash
# 登录
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin@example.com&password=your-password'

# 添加监控对象（asset_type: domain / email / username）
curl -X POST http://localhost:8000/api/assets/ \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"asset_type":"domain","label":"Example Corp","value":"example.com"}'

# 立即扫描及分页查看发现项
curl -X POST http://localhost:8000/api/assets/1/scan -H 'Authorization: Bearer <token>'
curl 'http://localhost:8000/api/findings?skip=0&limit=50' -H 'Authorization: Bearer <token>'

# Hudson Rock 免费即时查询（不创建监控资产）
curl -X POST http://localhost:8000/api/search/free \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"target_type":"domain","value":"example.com"}'
```

### 告警渠道

可直接在“系统设置 → 告警通道”添加、启停、删除和测试发送。Webhook 地址、钉钉加签密钥及收件人均使用 `MASTER_KEY` 加密保存。只有去重后的新增有效发现会发送告警。

```bash
curl -X POST http://localhost:8000/api/channels \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"name":"Security DingTalk","channel_type":"dingtalk","webhook_url":"https://oapi.dingtalk.com/robot/send?access_token=...","secret":"SEC..."}'
```

企业微信使用 `channel_type: wecom`；邮件使用 `channel_type: email` 和 `recipients` 数组，并在 `.env` 配置 SMTP。

关注网站示例：

```json
{"asset_type":"username","label":"企业账号","value":"example-user","site_filter_mode":"only","watched_sites":["example.com","*.partner.example"]}
```

密码泄漏接口无法提供关联网站，因此密码、API 密钥和令牌不支持关注网站过滤。

## 数据源

| 数据源 | 域名 | 邮箱 | 用户名 | 凭据 |
|---|---:|---:|---:|---|
| Hudson Rock Community OSINT | ✓ | ✓ | ✓ | 无需 Key（受服务条款和限流约束） |
| HIBP API v3 | — | ✓ | — | `HIBP_API_KEY` |
| HIBP Pwned Passwords | — | — | — | 密码 k-anonymity 查询，无需 API Key |
| XposedOrNot | ✓ | ✓ | — | 免费，无需 API Key |
| LeakCheck Public / Pro | Pro | ✓ | ✓ | Public 免费；Pro 配置 `LEAKCHECK_API_KEY` |

API 密钥和令牌会加密保存并在界面脱敏；系统不会把完整敏感值发送给不适用的第三方数据源。

provider registry 可继续接入 LeakCheck 等合规数据源。本服务不会规避鉴权、限流或授权要求。

## 本地开发

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
uvicorn app.main:app --reload
pytest -q
ruff check app tests
```

核心目录：`providers.py` 负责数据源适配，`scanner.py` 负责去重与持久化，`alert_channels/` 负责告警，`scheduler.py` 负责周期任务。

设计参考 [haltman-io/search-leaks](https://github.com/haltman-io/search-leaks) 的目标路由、限流意识和模块化 provider 思路；管理端原型来自用户提供的 HIBP-monitor。

## License

MIT
