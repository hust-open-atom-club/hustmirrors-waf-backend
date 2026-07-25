# mirrors-waf-backend

> 基于 PoW 的镜像站大文件防盗刷后端，作为 Nginx `auth_request` 下游鉴权服务。

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8)](https://go.dev/)
[![Echo](https://img.shields.io/badge/Echo-v4-00ADD8)](https://echo.labstack.com/)
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## 工作原理

### 架构总览

```mermaid
graph TD
    Browser["用户浏览器 / wget / curl"]
    Nginx["Nginx<br/>auth_request 鉴权"]
    Backend["mirrors-waf-backend<br/>/verify_pow"]
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
    participant Auth as mirrors-waf-backend
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

    Auth->>Auth: 1. 路径是否受保护？
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

---

## 快速开始

### 构建

```bash
make build
# 产物：bin/server
```

### 启动（开发模式）

```bash
./bin/server --config configs/config.dev.yaml
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

# 保护路径无 token：200 + 限速头
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /ubuntu.iso" \
  -H "X-Real-IP: 1.2.3.4"
# X-Pow-Decision: unverified_slow
# X-Pow-Limit-Rate: 512k

# 非法 token：403
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /ubuntu.iso" \
  -H "X-Original-Args: token=invalid&sign=0000...0000" \
  -H "X-Real-IP: 1.2.3.4"
# X-Pow-Error: malformed_token
```

---

## Nginx 接入

完整配置见 [`deploy/nginx/mirrors-waf.conf`](deploy/nginx/mirrors-waf.conf)，核心部分：

```nginx
location ~* \.(iso|img|qcow2|zip|7z|tar|tar\.gz|tar\.xz)$ {
    auth_request /_pow_auth;
    auth_request_set $pow_limit_rate $upstream_http_x_pow_limit_rate;
    limit_rate $pow_limit_rate;
    # ...
}

location = /_pow_auth {
    internal;
    proxy_pass http://127.0.0.1:8080/verify_pow;
    proxy_pass_request_body off;
    proxy_set_header X-Original-URI    $uri;
    proxy_set_header X-Original-Args   $args;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Original-Range  $http_range;
    # ...
}
```

---

## 生成 PoW 下载链接

后端只验证，不签发。用户通过静态页面（`deploy/frontend/`）在浏览器本地计算 PoW 生成 URL。

也可以用脚本生成：

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
    "d": 22, "cnt": "", "salt": "2025-demo-salt",
}
sign = solve_pow(payload, 22)
token = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
print(f"https://mirrors.example.edu/ubuntu.iso?token={token}&sign={sign}")
```

---

## 配置

完整字段见 [`configs/config.example.yaml`](configs/config.example.yaml)。

| 字段 | 默认值 | 说明 |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | 监听地址（不要暴露公网） |
| `pow.dry_run` | `false` | dry-run：记录但放行 |
| `pow.bypass_all` | `false` | 紧急放行开关 |
| `pow.modes.ip_bound` | enabled, d=22, ttl=24h | 绑定 IP 长效模式 |
| `pow.modes.generic` | enabled, d=22, ttl=30m, max_uses=5 | 通用短效模式 |
| `storage.driver` | `memory` | `memory` / `postgres` |
| `storage.counter_driver` | `memory` | `memory` / `redis` |
| `risk_control.enabled` | `true` | 风控规则链 |
| `admin.enabled` | `false` | 管理 API |

环境变量覆盖（前缀 `MIRRORS_WAF_`，分隔符 `__`）：

```bash
MIRRORS_WAF_SERVER__LISTEN=127.0.0.1:8080
MIRRORS_WAF_POW__DRY_RUN=true
MIRRORS_WAF_STORAGE__DRIVER=postgres
```

---

## 项目结构

```
├── cmd/server/               # 入口
├── internal/
│   ├── app/                  # 装配与启动
│   ├── auth/                 # PoW 验证编排
│   ├── pow/                  # token / canonical / sign / difficulty
│   ├── matcher/             # 路径保护规则
│   ├── storage/             # memory / postgres / redis 三实现
│   ├── risk/                # iptables 风格规则链
│   ├── transport/echo/      # HTTP 层
│   ├── admin/               # 管理 API
│   ├── config/              # 配置 + 校验
│   ├── logging/             # zap 包装
│   └── metrics/             # Prometheus
├── configs/                  # 示例配置
├── migrations/               # PostgreSQL DDL
└── deploy/
    ├── nginx/               # Nginx 接入示例
    ├── systemd/             # systemd unit
    ├── frontend/            # PoW 签发静态页
    └── observability/       # 告警 + Grafana
```

---

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

---

## 测试

```bash
make test          # 单元测试
make test-race     # race detector
go test -tags=benchmark -bench=. ./internal/app/...  # 压测
```

基线（i7-14650HX，内存存储）：

| 场景 | QPS |
|---|---|
| 非保护路径 | 209k |
| 保护路径无 token | 114k |
| 非法 token | 98k |

---

## 许可证

MIT
