# Webhook Mailer

Go + MySQL 的推送邮件后台。管理人员登录后台后可创建多个推送 URL、增加或修改收件邮箱、启停接口，并配置 SMTP 发件地址。每个接口接受 GET 和 POST；原始请求正文和查询参数会通过邮件转发。

## 本地启动

1. 创建 MySQL 数据库和专用账号：

```sql
CREATE DATABASE webhook_mailer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'webhook_user'@'127.0.0.1' IDENTIFIED BY '替换为强密码';
GRANT ALL PRIVILEGES ON webhook_mailer.* TO 'webhook_user'@'127.0.0.1';
```

2. 按 `.env.example` 设置环境变量。首次启动会自动创建所需数据表。

3. 启动：

```sh
go run .
```

访问 `http://127.0.0.1:8080` 打开登录页。纯 HTTP 本地调试时将 `COOKIE_SECURE=false`；生产环境须保持 `true` 并通过 HTTPS 访问。

## 管理页面

- 登录页使用 `ADMIN_USERNAME` 与 `ADMIN_PASSWORD`。
- 接口页会展示每一个对外推送 URL，例如 `https://push.example.com/push/<随机令牌>`。
- 收件邮箱页面可新增邮箱，或修改邮箱地址、启用状态。
- SMTP 页面可修改主机、端口、用户名、发件邮箱；QQ 邮箱授权码从服务器的 `SMTP_PASSWORD` 环境变量读取。

接口的 `recipient_ids` 留空时会投递给全部启用的邮箱。管理页面目前默认采用这一模式；如需让某个接口只投递指定邮箱，可调用管理 API。

## 管理 API

浏览器登录后的会话可直接调用。自动化脚本也可使用 `X-Admin-Token: <ADMIN_TOKEN>`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` / `POST` | `/api/v1/webhooks` | 查看或创建推送接口 |
| `PUT` | `/api/v1/webhooks/{id}` | 修改接口 |
| `GET` / `POST` | `/api/v1/recipients` | 查看或新增推送邮箱 |
| `PUT` | `/api/v1/recipients/{id}` | 修改推送邮箱 |
| `GET` / `PUT` | `/api/v1/smtp` | 查看或修改 SMTP 信息 |

## CentOS 部署

使用 [deploy/webhook-mailer.service](/Users/aiden/Documents/Codex/2026-10-30/wg/deploy/webhook-mailer.service) 作为 systemd 模板，使用 [deploy/nginx.conf](/Users/aiden/Documents/Codex/2026-10-30/wg/deploy/nginx.conf) 作为 Nginx 反向代理模板。将二进制、环境文件放到 `/opt/webhook-mailer`，再执行：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now webhook-mailer
sudo nginx -t && sudo systemctl reload nginx
```

Nginx 需要配置 TLS 证书，并将 `server_name` 改为实际域名。请求正文限制为 1 MiB。
