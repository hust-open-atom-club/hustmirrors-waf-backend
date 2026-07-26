# 部署与联调指南

本文档覆盖从本地构建到生产上线的完整流程。按顺序执行。

---

## 1. 前置条件

| 组件 | 版本要求 | 说明 |
|---|---|---|
| Go | 1.24+ | 构建后端 |
| Nginx | 1.18+ | `auth_request` + `limit_rate` 变量支持 |
| PostgreSQL | 14+ | 生产存储（可选，开发可用内存） |
| Redis | 6+ | 生产计数器（可选，开发可用内存） |
| goose | v3 | 数据库迁移工具 |

---

## 2. 构建

```bash
# 在仓库根目录
make build

# 产物：bin/server
# 验证版本
./bin/server --version
```

带版本元信息构建（推荐）：

```bash
VERSION=v1.0.0 COMMIT=$(git rev-parse --short HEAD) make build
```

---

## 3. 配置

```bash
cp configs/config.example.yaml /etc/mirrors-waf/config.yaml
```

编辑 `/etc/mirrors-waf/config.yaml`，重点确认：

- `server.listen`：后端监听地址，默认 `127.0.0.1:8080`（**不要监听 0.0.0.0**）
- `pow.modes.generic.max_uses`：generic 链接最大使用次数
- `pow.public_salt`：公开盐，**上线前必须改掉默认值**
- `storage.driver`：生产用 `postgres`，测试用 `memory`
- `storage.counter_driver`：生产用 `redis`，测试用 `memory`
- `risk_control.enabled`：是否启用风控规则链
- `admin.enabled`：管理 API，**生产默认关闭**

环境变量覆盖（前缀 `MIRRORS_WAF_`，分隔符 `__`）：

```bash
MIRRORS_WAF_SERVER__LISTEN=127.0.0.1:8080
MIRRORS_WAF_STORAGE__DRIVER=postgres
MIRRORS_WAF_POW__PUBLIC_SALT=prod-salt-2025
```

---

## 4. 数据库迁移（使用 PostgreSQL 时）

```bash
# 配置 DSN
export DATABASE_URL="postgres://user:pass@127.0.0.1:5432/mirrors_pow?sslmode=disable"

# 执行迁移
make migrate-up

# 回滚最后一次迁移（紧急回退时用）
# make migrate-down
```

迁移文件在 `migrations/001_init.sql`，创建三张表：
- `pow_usage`：generic 模式使用记录
- `risk_counter`：风控计数器快照
- `admin_audit_log`：管理操作审计

---

## 5. 启动

### 手动启动（测试用）

```bash
./bin/server --config /etc/mirrors-waf/config.yaml
```

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok"}

curl http://127.0.0.1:8080/readyz
# {"status":"ok","storage":"ok"}
```

### systemd 托管（生产用）

```bash
sudo cp deploy/systemd/mirrors-waf-backend.service /etc/systemd/system/
sudo cp bin/server /usr/local/bin/
sudo mkdir -p /etc/mirrors-waf
sudo cp configs/config.example.yaml /etc/mirrors-waf/config.yaml
# 编辑 /etc/mirrors-waf/config.yaml

sudo systemctl daemon-reload
sudo systemctl enable --now mirrors-waf-backend
sudo systemctl status mirrors-waf-backend
```

查日志：

```bash
journalctl -u mirrors-waf-backend -f
```

---

## 6. Nginx 联调（上线前必做）

这一步验证 Nginx `auth_request` 和后端的完整链路。**必须在一台测试机上跑通，不能直接上生产。**

### 6.1 配置 Nginx

```bash
sudo cp deploy/nginx/mirrors-waf.conf /etc/nginx/conf.d/
# 编辑 server_name、root、listen
sudo nginx -t
sudo systemctl reload nginx
```

### 6.2 准备测试文件

```bash
sudo mkdir -p /srv/mirrors
sudo dd if=/dev/zero of=/srv/mirrors/test.iso bs=1M count=10
sudo dd if=/dev/zero of=/srv/mirrors/test.txt bs=1M count=1
```

### 6.3 联调测试用例

按顺序执行以下测试，每个都要验证通过。

#### 测试 1：非保护文件直接下载（无 token）

```bash
curl -i http://127.0.0.1/test.txt
# 预期：200 OK，无 X-Pow-* 头
```

#### 测试 2：保护文件无 token（应限速放行）

```bash
time curl -o /dev/null http://127.0.0.1/test.iso
# 预期：200 OK
# 响应头含：X-Pow-Result: allow, X-Pow-Decision: unverified_slow, X-Pow-Limit-Rate: 512k
# 下载耗时明显受限速影响（10MB 文件在 512k/s 下约 20 秒）
```

#### 测试 3：保护文件带非法 token（应 403）

```bash
curl -i "http://127.0.0.1/test.iso?token=invalid&sign=0000000000000000000000000000000000000000000000000000000000000000"
# 预期：403 Forbidden
# 响应头含：X-Pow-Result: deny, X-Pow-Error: malformed_token
```

#### 测试 4：直接访问后端 /verify_pow（应 403 或 200，不 500）

```bash
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /test.iso" \
  -H "X-Original-Method: GET" \
  -H "X-Original-Args: " \
  -H "X-Real-IP: 127.0.0.1"
# 预期：200（限速放行）或 403，取决于风控配置
```

#### 测试 5：生成合法 token 并全速下载

用前端签发页面（见 §7）或脚本生成合法 token+sign，然后：

```bash
curl -i "http://127.0.0.1/test.iso?token=<合法token>&sign=<合法sign>"
# 预期：200 OK
# 响应头含：X-Pow-Result: allow, X-Pow-Decision: verified, X-Pow-Limit-Rate: 0
# 下载速度明显快于测试 2
```

#### 测试 6：generic 链接超过使用次数

重复用同一个合法 generic 链接下载，直到 `max_uses` 耗尽：

```bash
# 假设 max_uses=3，第 4 次应返回 403 used_up
for i in 1 2 3 4; do
  echo "=== attempt $i ==="
  curl -s -o /dev/null -w "%{http_code} %{header_x-pow-error}\n" \
    "http://127.0.0.1/test.iso?token=<合法token>&sign=<合法sign>"
done
# 预期：前 3 次 200，第 4 次 403 used_up
```

#### 测试 7：后端故障时 Nginx 行为

```bash
# 停掉后端
sudo systemctl stop mirrors-waf-backend

curl -i http://127.0.0.1/test.iso
# 预期：503（@pow_backend_error），不是 502 或超时
# Nginx auth_request 超时 2 秒后触发 error_page 500 502 503 504 = @pow_backend_error

# 恢复后端
sudo systemctl start mirrors-waf-backend
```

### 6.4 联调检查清单

- [ ] 测试 1-7 全部通过
- [ ] Nginx `access.log` 里能看到 auth_request 子请求
- [ ] 后端日志里有对应的 `pow_verify` 结构化日志
- [ ] `limit_rate` 变量正确传递（下载速度符合预期）
- [ ] 后端故障时 Nginx 返回 503 而非 502

---

## 7. 前端签发页面

用户通过静态页面生成带 token/sign 的下载 URL。页面放在镜像站的 `/static/pow/` 路径下。

### 部署

```bash
sudo mkdir -p /srv/mirrors/static/pow
sudo cp deploy/frontend/* /srv/mirrors/static/pow/
```

文件清单：
- `index.html`：模式选择 + 路径输入 + PoW 计算 + URL 展示
- `pow.js`：Web Worker，本地算 SHA-256 PoW
- `config.json`：公开配置（难度、salt、TTL、受保护扩展名）

### 配置

编辑 `config.json`，和后端配置保持一致：

```json
{
  "algorithm": "sha256",
  "salt": "prod-salt-2025",
  "modes": {
    "ip_bound": {"enabled": true, "difficulty": 22, "ttl_seconds": 86400},
    "generic": {"enabled": true, "difficulty": 22, "ttl_seconds": 1800, "max_uses": 5}
  }
}
```

**注意**：`salt` 和 `difficulty` 必须和后端 `config.yaml` 完全一致，否则生成的 token 无法通过验证。

---

## 8. 灰度上线策略

**不要一次性全量上线。** 按以下阶段推进：

### 阶段 1：限速档（观察期，1 周）

- 后端启用，`pow.dry_run: true`
- Nginx 配置所有大文件走 `auth_request`
- 所有请求走"无 token 限速"档（512k）
- 观察：
  - 后端 QPS、延迟、错误率
  - Nginx `auth_request` 超时次数
  - 是否有正常用户被误拦

### 阶段 2：PoW 加速档（灰度，1 周）

- `pow.dry_run: false`
- 部署前端签发页面
- 引导部分用户通过 PoW 页面生成下载链接
- 观察：
  - PoW 验证成功率
  - generic 链接使用次数分布
  - 用户反馈

### 阶段 3：全量

- 确认无异常后全量开放
- `pow.bypass_all: false`（确保关掉）

---

## 9. 回滚

### 紧急放行（后端故障）

```bash
# 编辑 /etc/mirrors-waf/config.yaml
pow:
  bypass_all: true

sudo systemctl restart mirrors-waf-backend
```

所有请求直接放行，绕过 PoW 和风控。**仅限紧急情况，恢复后立即关闭。**

### 关闭风控

```yaml
risk_control:
  enabled: false
```

### 回退到限速档

```yaml
pow:
  dry_run: true
```

deny 改写为 allow，所有请求走限速档。

### 完全摘掉后端

Nginx 配置移除 `auth_request`，直接走 `try_files`。后端可停掉。

---

## 10. 监控

### Prometheus 指标

后端在 `http://127.0.0.1:8080/metrics` 暴露 Prometheus 指标。关键指标：

| 指标 | 说明 | 告警阈值 |
|---|---|---|
| `mirrors_waf_pow_verify_total` | 验证次数（按 result/reason/mode） | deny 比例 > 30% 持续 5 分钟 |
| `mirrors_waf_pow_verify_latency_seconds` | 验证延迟 | p99 > 100ms |
| `mirrors_waf_storage_operations_total` | 存储操作 | error 比例 > 1% |
| `mirrors_waf_risk_decision_total` | 风控决策 | TOO_MANY 比例突增 |

### Grafana Dashboard

导入 `deploy/observability/grafana-dashboard.json`。

### 告警规则

见 `deploy/observability/alerts.yml`，配 Prometheus Alertmanager。

---

## 11. 压测

上线前在测试环境压测，确认单机容量。

```bash
# 安装 vegeta
go install github.com/tsenart/vegeta@latest

# 压测脚本见 deploy/benchmark/attack.txt
# 场景：纯 PoW 验证（无存储）的 QPS 基线
vegeta attack -duration=60s -rate=500 -targets=deploy/benchmark/verify_pow.txt | tee results.bin
vegeta report -type=text results.bin
```

基线参考（Intel i7-14650HX，内存存储，风控关闭）：

| 场景 | QPS | 单次延迟 | 内存 |
|---|---|---|---|
| 非保护路径 | 209k | 4.8 µs | 3.7 KB/op |
| 保护路径无 token | 114k | 8.8 µs | 3.7 KB/op |
| 保护路径带非法 token | 98k | 10.2 µs | 3.8 KB/op |
| 并发（24 核） | 583k | 1.7 µs | 2.8 KB/op |

实测数据来自 `go test -tags=benchmark -bench=. ./internal/app/...`。

Nginx `auth_request` 超时设 2 秒，单机 QPS 10 万级，远超任何镜像站 auth 子请求的实际负载。瓶颈通常不在后端而在 Nginx 到后端的网络往返——确保两者同机或低延迟互通。

如果实测 QPS 低于基线 50%，检查：
- 存储连接池配置
- Nginx `auth_request` 超时设置
- 后端 GOMAXPROCS

---

## 12. 常见问题

### Q: Nginx `limit_rate` 变量不生效？

A: 检查 Nginx 版本 >= 1.18，且变量非空。`${pow_limit_rate:-0}` 语法需要 Nginx 1.18+。空值会导致 `limit_rate` 不生效（无限速）。

### Q: 后端日志报 `storage_error`？

A: 检查 PostgreSQL / Redis 连接。`storage_error` 通常是存储层故障，后端会返回 500，Nginx 触发 `@pow_backend_error` 返回 503。

### Q: 用户反馈"下载被拒绝"？

A: 查后端日志，按 `request_id` 过滤。常见原因：
- token 过期（`expired`）
- 使用次数耗尽（`used_up`）
- IP 不匹配（`ip_mismatch`，ip_bound 模式）
- PoW 难度不足（`difficulty_not_met`，前端 config.json 和后端配置不一致）

### Q: 前端生成的 token 后端不认？

A: 99% 是 `config.json` 和后端 `config.yaml` 的 `salt` / `difficulty` 不一致。对比两边的值。

### Q: generic 链接用了一次就 used_up？

A: 检查 `pow.modes.generic.max_uses` 配置。如果 `count_head_request: false`（默认），HEAD 请求不计数，GET 才计数。但 Range 请求按 GET 计数。
