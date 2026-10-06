# Garmr

<img src="docs/garmr.svg" width="96" alt="Garmr" align="right" />

> 镜像站大文件防盗刷：无 token 限速下载，算一次 PoW 换全速。
> Nginx `auth_request` 下游鉴权服务，token 携带在 URL 中——wget/curl 直接可用，无 Cookie/Session。

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8)](https://go.dev/)
[![Echo](https://img.shields.io/badge/Echo-v4-00ADD8)](https://echo.labstack.com/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## 名字由来

Garmr（加尔姆）是北欧神话中看守 Hel 之门的血胸巨犬——神话里守冥界入口，
这里守镜像站的大文件：未验证的请求限速放行，通过 PoW 的全速通过。

命名致敬 [cerberus](https://github.com/sjtug/cerberus)：同为看门之犬，
希腊的叫 Cerberus，北欧的叫 Garmr。

## 工作原理

### 架构总览

```mermaid
graph TD
    Browser["用户浏览器 / wget / curl"]
    Nginx["Nginx<br/>auth_request 鉴权"]
    Backend["Garmr<br/>/verify_pow"]
    Storage[("PostgreSQL / Redis / 内存<br/>使用次数 + 风控计数")]
    FS["文件服务<br/>ISO / 大文件"]

    Browser -->|"GET /ubuntu.iso<br/>?token=... 和 sign=..."| Nginx
    Nginx -->|"内部子请求<br/>X-Original-URI, X-Original-Args,<br/>X-Real-IP"| Backend
    Backend -->|"读写使用次数<br/>（generic 模式）"| Storage
    Backend -->|"200 + X-Pow-Limit-Rate<br/>或 403 / 429"| Nginx
    Nginx -->|"全速或限速转发"| FS
    FS -->|"文件数据流"| Browser
```

### 验证流程

```mermaid
sequenceDiagram
    actor User as 用户
    participant FE as 前端 PoW 页面
    participant Nginx as Nginx
    participant Auth as Garmr
    participant Store as PostgreSQL / Redis
    participant FS as 文件服务

    User->>FE: 输入文件路径，选择模式
    Note over FE: 构造 token（path/mode/exp/difficulty/salt）<br/>枚举 cnt 计算 SHA-256(canonical)<br/>直到哈希前 d bit 全为 0

    loop PoW 计算（Web Worker）
        FE->>FE: sha256(canonical + cnt)
    end

    FE-->>User: 生成 URL<br/>?token=base64(payload) 和 sign=hex(hash)

    User->>Nginx: GET /ubuntu.iso?token=... 和 sign=...
    Nginx->>Auth: auth_request /verify_pow<br/>X-Original-URI, X-Original-Args, X-Real-IP

    Auth->>Auth: 1. 路径归一化后判断是否受保护
    Auth->>Auth: 2. 解析 token，校验字段<br/>（version/mode/algorithm/path格式/salt）
    Auth->>Auth: 3. token.path == 请求路径？
    Auth->>Auth: 4. 未过期？TTL 合法？
    Auth->>Auth: 5. 重算 SHA-256 == sign？
    Auth->>Auth: 6. 哈希满足前导零难度？

    alt mode = generic（通用链接）
        Auth->>Store: 原子递增使用次数
        Store-->>Auth: 返回当前 uses
        Auth->>Auth: 7. uses <= max_uses？
    else mode = ip_bound（绑定 IP）
        Auth->>Auth: 7. token.ip == 请求 IP？
    end

    alt 全部通过
        Auth-->>Nginx: 200 + X-Pow-Decision: verified<br/>X-Pow-Limit-Rate: 0
        Nginx->>FS: 全速转发
        FS-->>User: 文件数据流
    else 无 token 但低风险
        Auth-->>Nginx: 200 + X-Pow-Decision: unverified_slow<br/>X-Pow-Limit-Rate: 512k
        Nginx->>FS: 限速转发
        FS-->>User: 限速文件数据流
    else 校验失败
        Auth-->>Nginx: 403 + X-Pow-Error
        Nginx-->>User: 返回错误页
    end
```

- **无 token**：大文件限速放行（默认 512k/s），小文件和包管理器元数据全速
- **有合法 token**：PoW 验证通过后全速下载
- **非法 token**：直接 403

PoW 结果携带在 URL 参数中（`?token=...` 和 `sign=...`），不依赖 Cookie/Session，wget/curl 直接可用。

### 风控规则链

`risk_control.enabled=true` 时，请求先过一条 iptables 风格的规则链，再决定是否走PoW 校验。链的入口是 `INPUT`，支持 `ACCEPT` / `REJECT` / `RATE_LIMIT`/`TOO_MANY` / `REQUIRE_POW` / `JUMP` / `LOG` / `MARK`。

规则匹配 `pow_status` 时，取值含义：

| 值 | 含义 |
|---|---|
| `missing` | 没带 token |
| `valid` | token 合法且已通过全部校验 |
| `invalid` | 签名不符、难度不够、path 不匹配、TTL 超过 `max_ttl_seconds` 等 |
| `expired` | 已过期 |
| `mode_disabled` | token 本身合法，但对应模式已被 `enabled: false` 关闭 |
| `unverifiable` | token 本身合法，但**无法校验**——目前仅指 `ip_bound` token 遇到 `X-Real-IP` 缺失 |

后三类不是伪造，但也**不能当作通过**，规则里必须显式拒绝（示例配置已包含）。

> `pow_status` 与 PoW-only 路径共用同一套校验函数：PoW-only 会拒绝的 token，风控路径也不会判为 `valid`。

被风控拒绝的响应会带 `X-Pow-Trace`，格式为 `链:规则` 以 `,` 连接，`>` 表示 JUMP：

```
X-Pow-Trace: INPUT:missing-pow>RISK_CHECK,RISK_CHECK:too-many-1h
```

只记录命中规则，超长截断。完整 trace（含未命中项）用管理 API 的 `rule.preview`。

> `generic` 模式的 `max_uses` 在所有放行路径（`ACCEPT` / `RATE_LIMIT` / `REQUIRE_POW`）上都扣减。
>
> `risk_control.pending` 限制同一 IP 并发的受保护鉴权请求数，超过 `max_per_ip` 返回 429 并阻断 `block_ttl`。状态仅在单进程内，多副本不共享。

## 快速开始

### 构建

```bash
make build
# 产物：bin/server
```

### 启动（开发模式）

```bash
./bin/server --config configs/config.example.yaml
```

### 健康检查

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok"}

curl http://127.0.0.1:8080/readyz
# {"status":"ok","storage":"ok"}
```

### 验证鉴权

```bash
# 非保护路径：200
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /index.html" \
  -H "X-Real-IP: 1.2.3.4"
# X-Pow-Reason: not_protected

# 保护路径无 token：限速放行
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /ubuntu.iso" \
  -H "X-Real-IP: 1.2.3.4"
# HTTP/1.1 200
# X-Pow-Decision: unverified_slow
# X-Pow-Limit-Rate: 512k

# 非法 token：403
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /ubuntu.iso" \
  -H "X-Original-Args: token=invalid&sign=0000...0000" \
  -H "X-Real-IP: 1.2.3.4"
# X-Pow-Error: malformed_token
```

`config.dev.yaml` 关闭风控（`risk_control.enabled=false`），无 token 的保护路径直接 403 而非限速。

## Nginx 接入

完整配置见 [`deploy/nginx/mirrors-waf.conf`](deploy/nginx/mirrors-waf.conf)，核心部分：

```nginx
location ~* \.(iso|img|qcow2|zip|7z|tar|tar\.gz|tar\.xz)$ {
    auth_request /_pow_auth;
    auth_request_set $pow_limit_bytes $upstream_http_x_pow_limit_rate_bytes;
    limit_rate $pow_limit_bytes;
    # ...
}

location = /_pow_auth {
    internal;
    proxy_pass http://127.0.0.1:8080/verify_pow;
    proxy_pass_request_body off;
    proxy_set_header X-Original-URI    $original_path;
    proxy_set_header X-Original-Args   $original_args;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Original-Range  $http_range;
    # ...
}
```

## 生成 PoW 下载链接

后端只验证，不签发。示例脚本：

```python
import base64, hashlib, json, time

def solve_pow(payload, difficulty):
    counter = 0
    while True:
        payload["cnt"] = f"{counter:016x}"
        canonical = "mirrors-pow-v1\n" + \
            f"mode={payload['mode']}\nip={payload.get('ip','')}\n" + \
            f"path={payload['path']}\nts={payload['ts']}\nexp={payload['exp']}\n" + \
            f"difficulty={payload['d']}\ncnt={payload['cnt']}\nsalt={payload['salt']}\n"
        h = hashlib.sha256(canonical.encode()).digest()
        if all((h[i//8] >> (7 - i%8)) & 1 == 0 for i in range(difficulty)):
            return hashlib.sha256(canonical.encode()).hexdigest()
        counter += 1

payload = {
    "v": 1, "mode": "generic", "alg": "sha256", "path": "/ubuntu.iso",
    "ts": int(time.time()), "exp": int(time.time()) + 1800,
    "d": 22, "cnt": "", "salt": "test",
}
sign = solve_pow(payload, 22)
token = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
print(f"https://mirrors.example.edu/ubuntu.iso?token={token}&sign={sign}")
```

## 配置

完整字段见 [`configs/config.example.yaml`](configs/config.example.yaml)。

| 字段 | 默认值 | 说明 |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | 监听地址 |
| `pow.enabled` | `true` | PoW 验证总开关。`false` 时不解析也不校验 token，交由风控链决定 |
| `pow.dry_run` | `false` | dry-run：记录但放行 |
| `pow.bypass_all` | `false` | 紧急绕过 PoW/普通风控；不会绕过 Admin 人工 IP Block |
| `pow.algorithm` | `sha256` | 仅实现 `sha256`，填其他值启动即报错 |
| `pow.modes.ip_bound` | enabled, d=22, ttl=24h | 绑定 IP 长效模式，不计量 |
| `pow.modes.generic` | enabled, d=22, ttl=30m, max_uses=5 | 通用短效模式，按 `max_uses` 计量 |
| `storage.driver` | `memory` | `memory` / `postgres` / `redis` |
| `storage.counter_driver` | `memory` | `memory` / `redis` |
| `risk_control.enabled` | `true` | 风控规则链 |
| `risk_control.pending.enabled` | `true` | 是否启用同一 IP 的受保护请求并发限制与临时 block |
| `risk_control.pending.max_per_ip` | `128` | 同一 IP 同时执行的受保护鉴权请求上限 |
| `risk_control.pending.block_ttl` | `1h` | 超过 pending 上限后的 IP 临时 block 时长 |
| `cleanup.enabled` | `true` | 过期记录回收 |
| `logging.log_access` | `true` | 是否记录放行结果的日志 |
| `logging.log_denied` | `true` | 是否记录拒绝结果的日志 |
| `admin.enabled` | `false` | 管理 API |
| `admin.audit_log` | `true` | 是否记录管理操作审计 |
| `admin.mutations_enabled` | `false` | Admin 写操作总开关；未配置 admin token 时始终只读 |
| `admin.ip_block.enabled` | `false` | 启用实例级人工 IP Block/Unblock |
| `admin.ip_block.default_ttl` | `1h` | 未指定 TTL 时的人工 Block 时长 |
| `admin.ip_block.max_ttl` | `24h` | 人工 Block 最大时长，不支持永久 Block |
| `admin.config_management.enabled` | `false` | 单实例配置草稿、Diff、历史、Apply/回滚；Apply 后需重启生效 |

> `pow.enabled=false` 只跳过 PoW 校验，风控规则照常生效；`bypass_all=true` 则连 PoW 带普通风控一起绕过。Admin 人工 IP Block 优先级高于 `bypass_all`。

> Admin 鉴权只支持 token：配置 `admin.auth.token_file` 或 `admin.auth.token` 即启用（`Authorization: Bearer <token>`）。都不配则无认证，仅接受 loopback 监听或配置了 `allow_cidrs` 的实例。

> 配置管理在显式 `--config <path>` 启动、`admin.mutations_enabled=true`、`admin.config_management.enabled=true` 且配置了 Admin token 时可写。草稿在内存，历史在配置文件同目录 `.mirrors-waf-history/`。Apply/rollback 只写配置文件，需重启生效；敏感值显示为 `${SECRET:KEEP}`，不支持 API 轮换。

> `logging.log_*` 只影响日志不影响指标；5xx 始终记录。

> 以下字段会被校验拒绝而非静默忽略：`pow.modes.*.count_usage`（用 `max_uses`）、`risk_control.chains.*.rules[].match.risk_score_gte`（无风险分组件）。

环境变量覆盖（前缀 `MIRRORS_WAF_`，分隔符 `__`）：

```bash
MIRRORS_WAF_SERVER__LISTEN=127.0.0.1:8080
MIRRORS_WAF_POW__DRY_RUN=true
MIRRORS_WAF_STORAGE__DRIVER=postgres
```

## 项目结构

```
├── cmd/server/               # 入口
├── internal/
│   ├── app/                  # 装配与启动
│   ├── auth/                 # PoW 验证编排
│   ├── pow/                  # token / canonical / sign / difficulty
│   ├── matcher/             # 路径归一化 + 保护规则
│   ├── storage/             # usage: memory/postgres/redis，counter: memory/redis
│   ├── risk/                # iptables 风格规则链
│   ├── transport/echo/      # HTTP 层
│   ├── admin/               # 管理 API
│   ├── config/              # 配置 + 校验
│   ├── configstore/         # 单实例草稿、历史、原子写盘和回滚
│   ├── logging/             # zap 包装
│   └── metrics/             # Prometheus
├── configs/                  # 示例配置
├── migrations/               # PostgreSQL DDL
└── deploy/
    ├── nginx/               # Nginx 接入示例
    ├── systemd/             # systemd unit
    └── observability/       # 告警 + Grafana
```

## 部署

### systemd

```bash
sudo cp deploy/systemd/mirrors-waf-backend.service /etc/systemd/system/
sudo cp bin/server /usr/local/bin/
sudo cp configs/config.example.yaml /etc/mirrors-waf/config.yaml
sudo systemctl enable --now mirrors-waf-backend
```

### PostgreSQL

```bash
createdb mirrors_pow
make migrate-up
```

## 开发

```bash
make build          # 编译（首次自动构建前端并嵌入）
make build-all      # 前端 + 后端
make test           # 单元测试
make test-race      # race detector（需 CGO，Windows 上需装 gcc）
make coverage       # 覆盖率
make admin-ui-check # 管理后台前端类型检查
make lint           # golangci-lint（未安装时退回 go vet）

# PostgreSQL 真实集成测试（使用独立 schema，不会删除数据库中的其他表）
POSTGRES_TEST_DSN='postgres://user:pass@127.0.0.1:5432/mirrors_pow?sslmode=disable' make test-postgres
go test -tags=benchmark -bench=. ./internal/app/...  # 压测
```

管理后台前端在 `admin-ui/`（React + Vite），构建产物经 go:embed 嵌入二进制，改动后跑 `make build-all` 重新嵌入。

`make coverage` 用 `-coverpkg=./...` 把全仓生产代码纳入统计。PostgreSQL 集成测试需要设置 `POSTGRES_TEST_DSN`，否则跳过。

基线（i7-14650HX，内存存储）：

| 场景 | QPS |
|---|---|
| 非保护路径 | 209k |
| 保护路径无 token | 114k |
| 非法 token | 98k |

## 许可证

[MIT](LICENSE)
