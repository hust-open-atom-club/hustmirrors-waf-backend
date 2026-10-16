# 部署与联调指南

本文档覆盖从本地构建到生产上线的完整流程。

## 1. 前置条件

| 组件 | 版本要求 | 说明 |
|---|---|---|
| Go | 1.25.7+ | 构建后端（go.mod 要求的最低工具链版本） |
| Nginx | 1.18+ | `auth_request` + `limit_rate` 变量支持 |
| PostgreSQL | 14+ | 可选，`storage.driver: postgres` 时需要 |
| Redis | 6+ | 可选，`storage.counter_driver: redis` 或 `storage.driver: redis` 时需要 |
| goose | v3 | 数据库迁移工具 |

## 2. 构建

```bash
# 在仓库根目录
make build

# 产物：bin/server
# 验证版本
./bin/server --version
```

带版本元信息构建：

```bash
VERSION=v1.0.0 COMMIT=$(git rev-parse --short HEAD) make build
```

## 3. 配置

```bash
cp configs/config.example.yaml /etc/mirrors-waf/config.yaml
```

编辑 `/etc/mirrors-waf/config.yaml`，重点确认：

- `server.listen`：后端监听地址，默认 `127.0.0.1:8080`
- `pow.modes.generic.max_uses`：generic 链接最大使用次数
- `pow.public_salt`：公开盐
- `storage.driver`：`memory` / `postgres` / `redis`
- `storage.counter_driver`：`memory` / `redis`
- `risk_control.enabled`：是否启用风控规则链

环境变量覆盖（前缀 `MIRRORS_WAF_`，分隔符 `__`）：

```bash
MIRRORS_WAF_SERVER__LISTEN=127.0.0.1:8080
MIRRORS_WAF_STORAGE__DRIVER=postgres
MIRRORS_WAF_POW__PUBLIC_SALT=prod-salt-2025
```

配置的编辑与回滚推荐走 `garmr` CLI（服务无需运行，历史保存在配置文件同目录 `.mirrors-waf-history/`）：

```bash
make build-cli

garmr config edit                 # 编辑 → 校验 → diff → 确认 → 原子写入
garmr config history              # 修订历史
garmr config rollback 3           # 回滚到 revision 3
garmr rule preview -path /ubuntu.iso -pow missing   # 模拟请求走风控链
```

`config edit` 对危险变更（如关闭 PoW、放宽难度）会要求输入确认短语与原因。写入后需重启服务生效。

## 4. 数据库迁移（使用 PostgreSQL 时）

```bash
# 配置 DSN
export DATABASE_URL="postgres://user:pass@127.0.0.1:5432/mirrors_pow?sslmode=disable"

# 执行迁移
make migrate-up

# 回滚最后一次迁移（紧急回退时用）
# make migrate-down
```

迁移文件在 `migrations/001_init.sql`，创建 `pow_usage` 表（generic 模式使用记录）和两个索引。风控计数器不落库，保存在内存或 Redis。

## 5. 启动

### 手动启动

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

### Docker 测试部署

#### 1. 检查测试配置

测试配置位于 `deploy/docker/config.test.yaml`：

- 宿主机只绑定 `127.0.0.1:8080`
- memory storage，不依赖 PostgreSQL/Redis

#### 2. 构建并启动

在仓库根目录执行：

```bash
docker compose -f deploy/docker/compose.test.yaml up -d --build
```

查看状态和日志：

```bash
docker compose -f deploy/docker/compose.test.yaml ps
docker compose -f deploy/docker/compose.test.yaml logs -f mirrors-waf
```

停止并删除容器：

```bash
docker compose -f deploy/docker/compose.test.yaml down
```

#### 3. 健康检查

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

#### 4. 容器安全约束

- 非 root 用户 `10001:10001`
- `read_only: true` root filesystem
- `/tmp` 仅 64 MiB `tmpfs`
- 丢弃全部 Linux capabilities、`no-new-privileges`
- Docker healthcheck 请求 `/healthz`

### systemd 托管

```bash
# unit 以 User=mirrors-waf 运行，并要求 /var/lib/mirrors-waf 可写
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/mirrors-waf -M mirrors-waf
sudo mkdir -p /etc/mirrors-waf /var/lib/mirrors-waf
sudo chown mirrors-waf:mirrors-waf /var/lib/mirrors-waf

sudo cp deploy/systemd/mirrors-waf-backend.service /etc/systemd/system/
sudo cp bin/server /usr/local/bin/
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

## 6. Nginx 联调

```bash
sudo cp deploy/nginx/mirrors-waf.conf /etc/nginx/conf.d/
# 编辑 server_name、root、listen
sudo nginx -t
sudo systemctl reload nginx
```

## 7. 回滚

以下都是手工编辑配置的应急手段；常规配置回退用 `garmr config rollback <revision>`（见第 3 节），有 diff 预览且会自动留档。

### 紧急放行（后端故障）

```bash
# 编辑 /etc/mirrors-waf/config.yaml
pow:
  bypass_all: true

sudo systemctl restart mirrors-waf-backend
```

所有请求直接放行，绕过 PoW 和风控。

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

## 8. 监控

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

## 9. 压测

```bash
go test -tags=benchmark -bench=. -benchmem ./internal/app/...

# 端到端压测（HTTP 层，Nginx 风格请求头）：deploy/benchmark/verify_pow.txt
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

实测数据来自 `go test -tags=benchmark -bench=. ./internal/app/...`。远超镜像站 auth 子请求的实际负载；瓶颈通常在 Nginx 到后端的网络往返，两者应同机或低延迟互通。

如果实测 QPS 低于基线 50%，检查：
- 存储连接池配置
- Nginx `auth_request` 超时设置
- 后端 GOMAXPROCS

## 10. 常见问题

### Q: Nginx `limit_rate` 变量不生效？

A: 用 `X-Pow-Limit-Rate-Bytes`（纯字节数，后端对空值统一输出 `0`），`limit_rate` 需要数字值，`512k` 这类形式会被视为无效。

### Q: 后端日志报 `storage_error`？

A: 检查 PostgreSQL / Redis 连接。`storage_error` 是存储层故障，后端返回 500，Nginx 的 `auth_request` 会把这个 500 透传给客户端。

### Q: 用户反馈"下载被拒绝"？

A: 查后端日志，按 `request_id` 过滤。常见原因：
- token 过期（`expired`）
- 使用次数耗尽（`used_up`）
- IP 不匹配（`ip_mismatch`，ip_bound 模式）
- PoW 难度不足（`difficulty_not_met`，签发方与后端配置不一致）

### Q: 自己签发的 token 后端不认？

A: 通常是签发脚本与后端 `config.yaml` 不一致。检查三处：token 里的 `salt` 必须是后端的 `pow.public_salt` 或 `allowed_previous_salts` 之一；`d` 必须落在对应模式的 `min_difficulty` / `max_difficulty` 区间；`exp - ts` 不能超过 `max_ttl_seconds`。

### Q: generic 链接用了一次就 used_up？

A: 检查 `pow.modes.generic.max_uses` 配置。如果 `count_head_request: false`（默认），HEAD 请求不计数，GET 才计数。但 Range 请求按 GET 计数。
