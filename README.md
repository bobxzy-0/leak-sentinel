# Leak Sentinel

面向企业安全团队的泄漏监控服务。持续搜索指定的企业域名、电子邮箱和用户名；数据源出现新的泄漏记录时，通过钉钉、企业微信或邮件告警。

> 仅用于监控本人或已获授权的组织资产。项目保存查询目标的加密值、结果元数据和去重指纹，不应用于收集或传播泄漏凭据。

## 功能

- 域名、邮箱、用户名三类监控对象
- Hudson Rock Community OSINT：域名、邮箱、用户名的 infostealer 暴露统计
- Have I Been Pwned v3：邮箱泄漏事件（需要 HIBP API Key）
- 定时或立即扫描；SHA-256 内容指纹去重，只对新增结果告警
- 钉钉机器人（支持加签）、企业微信机器人、SMTP 邮件
- Fernet 加密敏感配置和监控值
- FastAPI、SQLite/PostgreSQL、Docker Compose、GitHub Actions CI

## 快速开始

```bash
cp .env.example .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# 将输出写入 MASTER_KEY，并修改 JWT_SECRET_KEY / ADMIN_PASSWORD
docker compose up -d --build
```

访问 `http://localhost:8000/docs`。健康检查：`GET /health`。

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
```

### 告警渠道

```bash
curl -X POST http://localhost:8000/api/channels \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"name":"Security DingTalk","channel_type":"dingtalk","webhook_url":"https://oapi.dingtalk.com/robot/send?access_token=...","secret":"SEC..."}'
```

企业微信使用 `channel_type: wecom`；邮件使用 `channel_type: email` 和 `recipients` 数组，并在 `.env` 配置 SMTP。

## 数据源

| 数据源 | 域名 | 邮箱 | 用户名 | 凭据 |
|---|---:|---:|---:|---|
| Hudson Rock Community OSINT | ✓ | ✓ | ✓ | 无需 Key（受服务条款和限流约束） |
| HIBP API v3 | — | ✓ | — | `HIBP_API_KEY` |

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
