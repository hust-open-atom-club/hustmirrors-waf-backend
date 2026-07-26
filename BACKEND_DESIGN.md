# 基于 PoW 的镜像站防盗刷流量机制：后端详细设计文档

> 本文档根据用户提供的任务流程图重新调整。  
> 后端实现语言：Golang  
> HTTP 框架：Echo  
> 接入方式：Nginx `auth_request` 内部子请求  
> 第一版存储：内存存储
> 生产存储：PostgreSQL（持久化）+ Redis（计数器/限流）
> 持久化场景：signature 使用记录、审计日志、管理操作日志、风控计数器快照
> 核心 URL 参数：`token` + `sign`  
> 支持两种模式：A. 绑定 IP 长效模式；B. 通用链接短效模式

---

## 1. 文档说明

本设计文档聚焦 PoW 验证后端，不包含完整前端页面设计，也不包含镜像站文件同步系统设计。

本后端服务的定位是：

```text
Nginx 大文件下载鉴权服务
```

也就是说，后端只判断请求是否允许下载，不负责真实文件传输。

真实大文件仍由 Nginx 或其后端文件服务发送。

---

## 2. 参考流程图抽象后的后端模型

用户给出的流程图中核心链路如下：

```text
用户浏览器 / curl / wget
        |
        | GET /ubuntu.iso?token=...&sign=...
        v
      Nginx
        |
        | 内部子请求 /verify_pow
        | X-Original-URI
        | X-Real-IP
        v
   PoW 验证后端
        |
        | 通用链接模式读写 sign 使用次数
        v
      PostgreSQL / 内存
      Redis (计数器/限流)
        |
        v
   返回 200 放行 / 403 拒绝
```

本文档在该流程基础上做如下工程化调整：

1. 流程图中后端写的是 Python 服务；本项目后端改为 **Golang + Echo**；
2. 流程图中使用 `token + sign`；本文档采用该参数形式作为主协议；
3. 流程图中有两种模式：
   - A：绑定 IP，长效；
   - B：通用链接，短效；
4. 通用链接模式需要 PostgreSQL / 内存记录 sign 使用次数；
5. 绑定 IP 模式主要校验请求 IP，不强制记录使用次数，但仍建议记录审计日志；
6. Nginx 使用 `auth_request` 将原始 URI 和真实 IP 传给后端；
7. 后端返回 `HTTP 200` 表示放行，返回 `HTTP 403` 表示拒绝。

---

## 3. 后端目标

### 3.1 核心目标

后端需要完成以下任务：

1. **接收 Nginx 内部鉴权请求**  
   Nginx 在用户请求大文件时发起内部子请求到后端。

2. **判断请求路径是否需要 PoW 验证**  
   根据后缀、路径正则、排除规则判断是否需要验证。

3. **解析 URL 中的 `token` 与 `sign` 参数**  
   对受保护的大文件，请求必须携带 `token` 和 `sign`。

4. **解析 token 中的模式信息**  
   token 中包含 `mode` 字段，用于区分：
   - `ip_bound`：绑定 IP 长效模式；
   - `generic`：通用链接短效模式。

5. **验证 token 中路径与真实请求路径一致**  
   防止一个文件的 PoW 结果被用于另一个文件。

6. **验证时间戳 / 过期时间**  
   防止链接长期有效。

7. **重新计算 SHA-256 并校验 sign**  
   后端必须重新计算哈希，不允许信任客户端提交的 sign。

8. **校验 PoW 难度**  
   sign 对应的哈希结果必须满足前导零 bit 数要求。

9. **根据模式执行额外校验**  
   - 绑定 IP 模式：校验请求 IP 与 token 中 IP 一致；
   - 通用链接模式：校验 sign 使用次数未超过限制。

10. **写入使用记录与审计日志**  
    通用链接模式需要递增使用次数；所有模式都建议记录日志。

11. **返回适配 Nginx 的响应**  
    - 通过：`HTTP 200 OK`；
    - 拒绝：`HTTP 403 Forbidden`；
    - 限流：`HTTP 429 Too Many Requests`；
    - 内部错误：`HTTP 500 Internal Server Error`。

### 3.2 非目标

后端不负责：

1. 传输 ISO / 大文件内容；
2. 维护用户账号体系；
3. 对接第三方验证码；
4. 完全阻止拥有大量算力的攻击者；
5. 替代全站流量监控、防火墙、限速系统；
6. 为每个用户保存长期会话。

---

## 4. 技术栈选型

### 4.1 HTTP 框架

推荐使用：

```text
Echo
```

原因：

1. Echo 足够轻量，适合本项目这种鉴权型 HTTP 服务；
2. 路由、中间件、请求上下文设计清晰，上手成本低；
3. 社区成熟，资料充足，课程项目维护成本更低；
4. 可方便加入日志、风控、panic recovery、metrics 等中间件；
5. 后端只处理鉴权请求，不代理大文件，不需要过重的微服务框架。

### 4.2 依赖推荐

| 类型 | 推荐库 | 说明 |
|---|---|---|
| HTTP 框架 | `github.com/labstack/echo/v4` | 路由、中间件、服务启动 |
| 配置管理 | `github.com/spf13/viper` | YAML 配置、环境变量覆盖 |
| 日志 | `go.uber.org/zap` | 高性能结构化日志 |
| PostgreSQL 驱动 | `github.com/jackc/pgx/v5` | 生产环境持久化存储 |
| SQL 辅助 | `github.com/jmoiron/sqlx` | 手写 SQL + 结构体扫描 |
| Redis | `github.com/redis/go-redis/v9` | 生产环境风控计数器、限流状态 |
| 数据库迁移 | `github.com/pressly/goose/v3` | migration 管理 |
| 风控/限流 | 自研规则链 + `golang.org/x/time/rate` | 类 iptables 规则链 + 简单 token bucket |
| 测试 | `github.com/stretchr/testify` | 单元测试断言 |
| 指标 | `github.com/prometheus/client_golang` | 可选 Prometheus metrics |

### 4.3 是否使用 GORM

第一版不建议使用 GORM。

原因：

1. 核心数据操作是 sign 使用次数的原子递增；
2. Redis（计数器） / PostgreSQL（持久化） / 内存存储可能切换，抽象接口更重要；
3. SQL 很少，手写 SQL 更清晰；
4. GORM 对并发条件更新表达不如手写 SQL 直观。

推荐组合：

```text
Echo + Viper + Zap + sqlx + PostgreSQL + Redis
```

---

## 5. 总体架构

### 5.1 组件关系

```mermaid
graph TD
    Browser["用户浏览器 / curl / wget\n携带 token + sign"]
    Nginx["Nginx\nauth_request 鉴权"]
    Backend["Golang + Echo\nPoW 验证后端"]
    Store[("PostgreSQL (持久化) + Redis (计数器)\n内存 (开发测试)")]
    FS["文件服务 / 镜像目录\nISO / 大文件"]

    Browser -->|HTTPS GET 大文件| Nginx
    Nginx -->|内部子请求 /verify_pow| Backend
    Backend -->|通用链接模式读写计数| Store
    Backend -->|200 放行 / 403 拒绝| Nginx
    Nginx -->|验证通过后读取文件| FS
    FS -->|文件数据流| Browser
```

### 5.2 核心流程

```mermaid
sequenceDiagram
    actor User as 用户
    participant Nginx as Nginx
    participant Auth as Echo PoW 后端
    participant Store as PostgreSQL + Redis
    participant FS as 文件服务

    User->>Nginx: GET /ubuntu.iso?token=...&sign=...
    Nginx->>Auth: GET /verify_pow\nX-Original-URI, X-Real-IP, X-Original-Args
    Auth->>Auth: 判断路径是否需要保护
    Auth->>Auth: 解析 token 与 sign
    Auth->>Auth: 校验路径、时间、难度、哈希

    alt mode = generic
        Auth->>Store: 查询 sign 使用次数
        Store-->>Auth: 返回计数
        Auth->>Auth: 判断是否小于 max_uses
        Auth->>Store: 递增使用次数
    else mode = ip_bound
        Auth->>Auth: 校验请求 IP 是否等于 token.ip
    end

    alt 验证通过
        Auth-->>Nginx: HTTP 200 OK
        Nginx->>FS: 读取/转发文件
        FS-->>User: 文件数据流
    else 验证失败
        Auth-->>Nginx: HTTP 403 Forbidden
        Nginx-->>User: 返回验证引导页
    end
```

---

## 6. 两种链接模式设计

### 6.1 模式 A：绑定 IP 长效模式

模式名：

```text
ip_bound
```

适用场景：

1. 用户在浏览器中生成链接后，直接在同一台机器或同一公网出口下载；
2. 用户希望链接有效期更长；
3. 希望减少 PostgreSQL 使用次数记录压力；
4. 不希望链接被他人复用。

特点：

| 项目 | 说明 |
|---|---|
| 是否绑定 IP | 是 |
| 是否可跨 IP 使用 | 否 |
| 有效期 | 较长，例如 12-24 小时 |
| 是否限制使用次数 | 可不限制，或仅做可选限制 |
| 是否需要 PostgreSQL | 不强制需要 |
| 主要风险 | NAT / 移动网络 IP 变化导致失效 |

验证条件：

1. token 存在；
2. sign 存在；
3. token.mode = `ip_bound`；
4. token.path 与 `X-Original-URI` 一致；
5. token.ip 与请求真实 IP 一致；
6. token 未过期；
7. sign 等于后端重新计算出的 SHA-256；
8. sign 满足 PoW 难度。

### 6.2 模式 B：通用链接短效模式

模式名：

```text
generic
```

适用场景：

1. 用户在浏览器中生成链接，但要复制到远程服务器使用 `wget` / `curl` 下载；
2. 生成链接的浏览器 IP 与实际下载 IP 不一致；
3. 希望兼容无头环境；
4. 链接可以短时间内通用，但不能无限复用。

特点：

| 项目 | 说明 |
|---|---|
| 是否绑定 IP | 否 |
| 是否可跨 IP 使用 | 是 |
| 有效期 | 较短，例如 10-30 分钟 |
| 是否限制使用次数 | 是 |
| 是否需要 PostgreSQL/Redis | 是 |
| 主要风险 | 链接被复制传播，因此必须短效 + 限次数 |

验证条件：

1. token 存在；
2. sign 存在；
3. token.mode = `generic`；
4. token.path 与 `X-Original-URI` 一致；
5. token 未过期；
6. sign 等于后端重新计算出的 SHA-256；
7. sign 满足 PoW 难度；
8. sign 使用次数小于 `max_uses`；
9. 后端成功递增使用次数。

### 6.3 两种模式对比

| 对比项 | 绑定 IP 长效模式 | 通用链接短效模式 |
|---|---|---|
| mode | `ip_bound` | `generic` |
| URL 能否跨机器使用 | 通常不能 | 可以 |
| 是否检查 IP | 是 | 否 |
| 是否记录使用次数 | 可选 | 必须 |
| 推荐 TTL | 12-24 小时 | 10-30 分钟 |
| 推荐 max uses | 可不限制或较大 | 3-10 次 |
| 用户体验 | 稳定网络下较好 | 对无头环境更友好 |
| 防泄漏能力 | 较强 | 依赖短有效期和次数限制 |

---

## 7. URL 参数协议

### 7.1 最终下载 URL 形式

```text
https://mirrors.example.edu/ubuntu.iso?token=<base64url-json>&sign=<sha256-hex>
```

示例：

```text
https://mirrors.example.edu/ubuntu.iso?token=eyJ2IjoxLCJtb2RlIjoiZ2VuZXJpYyIsInBhdGgiOiIvdWJ1bnR1LmlzbyIsInRzIjoxNzM1Njg5NjAwLCJleHAiOjE3MzU2OTE0MDAsImQiOjIyLCJjbnQiOiIwMDAwMDAwMDAwMTJhYmMiLCJhbGciOiJzaGEyNTYiLCJzYWx0IjoiMjAyNS1kZW1vIn0&sign=000000c4a8f5...
```

### 7.2 参数说明

| 参数 | 必填 | 说明 |
|---|---|---|
| `token` | 是 | Base64URL 编码后的 JSON，不加密 |
| `sign` | 是 | SHA-256 十六进制哈希结果 |

### 7.3 为什么采用 token + sign

采用 `token + sign` 的原因：

1. 与参考流程图一致；
2. token 中保存结构化信息，便于后端解析；
3. sign 单独存放，便于 PostgreSQL 按 sign_id 持久化记录；
4. 用户 URL 可读性比单个超长 signature 更好；
5. 后续支持不同 mode 更方便。

### 7.4 token 是否加密

第一版 token 不加密，只做 Base64URL 编码。

注意：Base64URL 不是加密，任何人都可以解码 token。

但这不是安全问题，因为：

1. 后端不会信任 token 本身；
2. 后端会重新计算 sign；
3. 攻击者修改 token 后，必须重新完成 PoW；
4. 后端会限制 TTL、难度、路径、模式和使用次数。

---

## 8. Token Payload 设计

### 8.1 通用字段

所有模式 token 都包含以下字段：

```json
{
  "v": 1,
  "mode": "generic",
  "alg": "sha256",
  "path": "/ubuntu.iso",
  "ts": 1735689600,
  "exp": 1735691400,
  "d": 22,
  "cnt": "000000000012abc",
  "salt": "2025-demo"
}
```

字段说明：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `v` | number | 是 | 协议版本，第一版为 1 |
| `mode` | string | 是 | `ip_bound` 或 `generic` |
| `alg` | string | 是 | 第一版只支持 `sha256` |
| `path` | string | 是 | 目标下载路径 |
| `ts` | number | 是 | token 生成时间，Unix 秒 |
| `exp` | number | 是 | token 过期时间，Unix 秒 |
| `d` | number | 是 | PoW 难度，前导零 bit 数 |
| `cnt` | string | 是 | PoW 计数器 / nonce |
| `salt` | string | 否 | 公开 salt，用于限制长期预计算 |

### 8.2 绑定 IP 模式 token

```json
{
  "v": 1,
  "mode": "ip_bound",
  "alg": "sha256",
  "ip": "203.0.113.10",
  "path": "/ubuntu.iso",
  "ts": 1735689600,
  "exp": 1735776000,
  "d": 22,
  "cnt": "000000000012abc",
  "salt": "2025-demo"
}
```

额外字段：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ip` | string | 是 | 生成 token 时确认的用户公网 IP |

### 8.3 通用链接模式 token

```json
{
  "v": 1,
  "mode": "generic",
  "alg": "sha256",
  "path": "/ubuntu.iso",
  "ts": 1735689600,
  "exp": 1735691400,
  "d": 22,
  "cnt": "000000000012abc",
  "salt": "2025-demo"
}
```

通用链接模式不包含 `ip` 字段。

### 8.4 字段限制

| 字段 | 限制 |
|---|---|
| `v` | 必须为 `1` |
| `mode` | 必须为 `ip_bound` 或 `generic` |
| `alg` | 必须为 `sha256` |
| `path` | 必须以 `/` 开头，长度不超过 4096 |
| `ts` | 不能明显晚于服务器时间 |
| `exp` | 必须大于当前时间，且不能超过模式最大 TTL |
| `d` | 必须在该模式允许范围内 |
| `cnt` | 长度 1-64，只允许十六进制或 Base64URL 安全集 |
| `ip` | 仅 `ip_bound` 必填，必须是合法 IP 字符串 |
| `salt` | 如启用 salt，则必须是当前或上一期允许 salt |

---

## 9. PoW 签名字符串设计

### 9.1 设计原则

前端和后端必须对完全一致的字符串计算 SHA-256。

要求：

1. 字段顺序固定；
2. 换行符固定为 `\n`；
3. 字符编码固定为 UTF-8；
4. 不使用 JSON 字符串本身作为哈希输入，避免字段顺序问题；
5. 不使用 query string 参与 path 字段；
6. path 使用 Nginx 传入的规范化 `$uri`；
7. sign 为 SHA-256 输出的十六进制小写字符串。

### 9.2 绑定 IP 模式 canonical string

```text
mirrors-pow-v1
mode=ip_bound
ip=203.0.113.10
path=/ubuntu.iso
ts=1735689600
exp=1735776000
difficulty=22
cnt=000000000012abc
salt=2025-demo
```

### 9.3 通用链接模式 canonical string

```text
mirrors-pow-v1
mode=generic
ip=
path=/ubuntu.iso
ts=1735689600
exp=1735691400
difficulty=22
cnt=000000000012abc
salt=2025-demo
```

注意：即使是通用链接模式，也保留 `ip=` 空行，保证字段结构固定。

### 9.4 Go 构造函数示例

```go
func BuildCanonicalInput(p TokenPayload) string {
    ip := ""
    if p.Mode == "ip_bound" {
        ip = p.IP
    }

    return fmt.Sprintf(
        "mirrors-pow-v1\n"+
            "mode=%s\n"+
            "ip=%s\n"+
            "path=%s\n"+
            "ts=%d\n"+
            "exp=%d\n"+
            "difficulty=%d\n"+
            "cnt=%s\n"+
            "salt=%s\n",
        p.Mode,
        ip,
        p.Path,
        p.Timestamp,
        p.ExpiresAt,
        p.Difficulty,
        p.Counter,
        p.Salt,
    )
}
```

### 9.5 sign 计算

```text
sign = hex(sha256(canonical_string))
```

前端循环改变 `cnt`，直到：

```text
sign 对应的哈希前 d 个 bit 全为 0
```

后端重新执行同样计算，并验证：

1. 计算出的 hash hex 是否等于 URL 中的 `sign`；
2. hash 是否满足前导零 bit 难度。

---

## 10. 后端验证流程

### 10.1 总流程

```mermaid
flowchart TD
    A[收到 /verify_pow] --> B[读取 X-Original-URI / X-Real-IP / X-Original-Args]
    B --> C{路径是否需要保护}
    C -- 否 --> PASS0[返回 200 not_protected]
    C -- 是 --> D{是否存在 token 和 sign}
    D -- 否 --> DENY1[403 missing_token_or_sign]
    D -- 是 --> E[解析 Base64URL token]
    E --> F{token 字段是否合法}
    F -- 否 --> DENY2[403 malformed_token]
    F -- 是 --> G{token.path 是否等于请求路径}
    G -- 否 --> DENY3[403 path_mismatch]
    G -- 是 --> H{是否过期或 TTL 超限}
    H -- 是 --> DENY4[403 expired_or_ttl_too_long]
    H -- 否 --> I[构造 canonical string]
    I --> J[计算 SHA-256]
    J --> K{计算结果是否等于 sign}
    K -- 否 --> DENY5[403 sign_mismatch]
    K -- 是 --> L{是否满足 PoW 难度}
    L -- 否 --> DENY6[403 difficulty_not_met]
    L -- 是 --> M{mode 是什么}
    M -- ip_bound --> N{请求 IP 是否匹配 token.ip}
    N -- 否 --> DENY7[403 ip_mismatch]
    N -- 是 --> PASS1[返回 200]
    M -- generic --> O{使用次数是否小于上限}
    O -- 否 --> DENY8[403 used_up]
    O -- 是 --> P[递增使用次数]
    P --> PASS2[返回 200]
```

### 10.2 验证伪代码

```go
func VerifyPow(ctx context.Context, req AuthRequest) AuthResult {
    path := req.OriginalURI
    args := req.OriginalArgs
    realIP := req.RealIP

    if !matcher.ShouldProtect(path) {
        return Allow("not_protected")
    }

    tokenRaw, sign := ExtractTokenAndSign(args)
    if tokenRaw == "" || sign == "" {
        return Deny(403, "missing_token_or_sign")
    }

    payload, err := DecodeToken(tokenRaw)
    if err != nil {
        return Deny(403, "malformed_token")
    }

    if err := ValidatePayloadBasic(payload); err != nil {
        return Deny(403, err.Reason)
    }

    if payload.Path != path {
        return Deny(403, "path_mismatch")
    }

    if err := ValidateTimeByMode(payload, config.Pow.Modes); err != nil {
        return Deny(403, err.Reason)
    }

    canonical := BuildCanonicalInput(payload)
    hash := sha256.Sum256([]byte(canonical))
    computedSign := hex.EncodeToString(hash[:])

    if !strings.EqualFold(computedSign, sign) {
        return Deny(403, "sign_mismatch")
    }

    if !HasLeadingZeroBits(hash[:], payload.Difficulty) {
        return Deny(403, "difficulty_not_met")
    }

    switch payload.Mode {
    case "ip_bound":
        if !SameIP(payload.IP, realIP) {
            return Deny(403, "ip_mismatch")
        }
        return Allow("ip_bound_valid")

    case "generic":
        signID := ComputeSignID(tokenRaw, sign, payload.Path, payload.Mode)
        allowed, uses, err := store.Consume(ctx, ConsumeInput{
            ID: signID,
            Mode: payload.Mode,
            Path: payload.Path,
            Sign: sign,
            TokenHash: SHA256Hex(tokenRaw),
            ExpiresAt: payload.ExpiresAt,
            MaxUses: config.Pow.Modes.Generic.MaxUses,
            IP: realIP,
            UserAgent: req.UserAgent,
        })
        if err != nil {
            return Deny(500, "storage_error")
        }
        if !allowed {
            return Deny(403, "used_up")
        }
        return AllowWithUsage("generic_valid", uses)

    default:
        return Deny(403, "unsupported_mode")
    }
}
```

---

## 11. HTTP API 设计

### 11.1 鉴权接口

主接口：

```text
GET /verify_pow
```

### 11.2 请求示例

```http
GET /verify_pow HTTP/1.1
Host: 127.0.0.1:8080
X-Original-URI: /ubuntu.iso
X-Original-Method: GET
X-Original-Args: token=eyJ2IjoxLCJtb2RlIjoiZ2VuZXJpYyJ9&sign=000000abc...
X-Real-IP: 203.0.113.10
X-Forwarded-For: 203.0.113.10
User-Agent: curl/8.5.0
```

### 11.3 响应状态码

| 状态码 | 含义 | Nginx 行为 |
|---:|---|---|
| `200 OK` | 验证通过 | 放行 |
| `204 No Content` | 也可表示通过 | 放行 |
| `403 Forbidden` | 验证失败 | 拒绝 |
| `429 Too Many Requests` | 限流 | 拒绝 |
| `500 Internal Server Error` | 后端错误 | 默认拒绝 |

为了贴合参考流程图，第一版推荐：

```text
通过统一返回 200
拒绝统一返回 403
```

具体错误原因通过响应头传递。

### 11.4 成功响应

```http
HTTP/1.1 200 OK
X-Pow-Result: allow
X-Pow-Reason: generic_valid
X-Pow-Mode: generic
X-Pow-Uses: 1
X-Pow-Max-Uses: 5
```

### 11.5 失败响应

```http
HTTP/1.1 403 Forbidden
X-Pow-Result: deny
X-Pow-Error: path_mismatch
X-Pow-Mode: generic
```

### 11.6 健康检查接口

```text
GET /healthz
```

返回：

```json
{"status":"ok"}
```

### 11.7 就绪检查接口

```text
GET /readyz
```

返回：

```json
{
  "status": "ok",
  "storage": "ok"
}
```

---

## 12. Nginx 接入设计

### 12.1 推荐配置

```nginx
server {
    listen 80;
    server_name mirrors-shadow.example.local;

    root /srv/mirrors;
    autoindex on;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~* \.(iso|img|qcow2|vmdk|vdi|ova|zip|7z|tar|tar\.gz|tar\.xz)$ {
        auth_request /_pow_auth;
        auth_request_set $pow_error $upstream_http_x_pow_error;
        auth_request_set $pow_reason $upstream_http_x_pow_reason;
        auth_request_set $pow_mode $upstream_http_x_pow_mode;

        error_page 403 = @pow_forbidden;
        error_page 429 = @pow_rate_limited;
        error_page 500 502 503 504 = @pow_backend_error;

        try_files $uri =404;
    }

    location = /_pow_auth {
        internal;

        proxy_pass http://127.0.0.1:8080/verify_pow;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Original-URI $uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Original-Args $args;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header User-Agent $http_user_agent;

        proxy_connect_timeout 1s;
        proxy_send_timeout 2s;
        proxy_read_timeout 2s;
    }

    location @pow_forbidden {
        default_type text/html;
        return 403 '<html><body><h1>下载需要 PoW 验证</h1><p>请在镜像站网页中生成带 token 和 sign 的下载链接。</p><p>错误原因：$pow_error</p></body></html>';
    }

    location @pow_rate_limited {
        default_type text/html;
        return 429 '<html><body><h1>请求过于频繁</h1><p>请稍后重试。</p></body></html>';
    }

    location @pow_backend_error {
        default_type text/html;
        return 503 '<html><body><h1>验证服务暂时不可用</h1><p>请稍后重试。</p></body></html>';
    }
}
```

### 12.2 Nginx 必须传递的 Header

| Header | 必填 | 说明 |
|---|---|---|
| `X-Original-URI` | 是 | 原始请求路径，使用 `$uri` |
| `X-Original-Method` | 是 | 原始请求方法 |
| `X-Original-Args` | 是 | 原始请求 query string，包含 token 和 sign |
| `X-Real-IP` | 是 | Nginx 认为的真实客户端 IP |
| `X-Forwarded-For` | 建议 | 代理链 |
| `User-Agent` | 建议 | 客户端 UA |

### 12.3 IP 获取注意事项

如果镜像站前面还有 CDN、负载均衡或反向代理，必须正确配置 Nginx real IP：

```nginx
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 192.168.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

否则绑定 IP 模式可能因为后端拿到的是代理 IP 而无法使用。

---

## 13. 存储设计

### 13.1 哪些模式需要存储

| 模式 | 是否强制存储 | 说明 |
|---|---|---|
| `ip_bound` | 否 | 主要靠 IP 绑定和过期时间控制 |
| `generic` | 是 | 必须限制 sign 使用次数 |

### 13.2 存储接口

```go
type UsageStore interface {
    Consume(ctx context.Context, input ConsumeInput) (ConsumeResult, error)
    Get(ctx context.Context, id string) (*UsageRecord, error)
    CleanupExpired(ctx context.Context, beforeUnix int64) error
    Close() error
}

type ConsumeInput struct {
    ID        string
    Mode      string
    Path      string
    Sign      string
    TokenHash string
    ExpiresAt int64
    MaxUses   int
    IP        string
    UserAgent string
    NowUnix   int64
}

type ConsumeResult struct {
    Allowed bool
    Uses    int
    MaxUses int
    Reason  string
}
```

### 13.3 Sign ID 设计

不要直接用 sign 作为主键，因为不同路径或不同 token 理论上可能产生相同 sign，虽然概率极低。

推荐：

```text
sign_id = sha256(
  "mirrors-pow-sign-id-v1\n" +
  "mode=" + mode + "\n" +
  "path=" + path + "\n" +
  "token_hash=" + sha256(tokenRaw) + "\n" +
  "sign=" + sign + "\n"
)
```

### 13.4 Redis Key 设计

```text
pow:usage:<sign_id>
```

Value 可使用 Hash：

```text
uses        当前使用次数
mode        generic
path        文件路径
first_ip    首次使用 IP
last_ip     最近使用 IP
created_at  创建时间
updated_at  更新时间
expires_at  token 过期时间
```

TTL：

```text
expires_at - now + grace_seconds
```

### 13.5 Redis 原子递增 Lua

```lua
local key = KEYS[1]
local max_uses = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local now = ARGV[3]
local ip = ARGV[4]
local ua = ARGV[5]

local uses = tonumber(redis.call('HGET', key, 'uses') or '0')

if uses >= max_uses then
  return {0, uses}
end

uses = uses + 1

if uses == 1 then
  redis.call('HSET', key,
    'uses', uses,
    'first_ip', ip,
    'last_ip', ip,
    'user_agent', ua,
    'created_at', now,
    'updated_at', now
  )
  redis.call('EXPIRE', key, ttl)
else
  redis.call('HSET', key,
    'uses', uses,
    'last_ip', ip,
    'updated_at', now
  )
end

return {1, uses}
```

### 13.6 持久化存储：PostgreSQL 表设计

PostgreSQL 作为生产环境的持久化存储，用于记录 signature 使用详情和审计日志。

#### 13.6.1 表：pow_usage

记录 generic 模式下 signature 的使用情况。

```sql
CREATE TABLE IF NOT EXISTS pow_usage (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    path TEXT NOT NULL,
    sign TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    max_uses INTEGER NOT NULL,
    first_ip TEXT,
    last_ip TEXT,
    user_agent TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pow_usage_expires_at
    ON pow_usage(expires_at);

CREATE INDEX IF NOT EXISTS idx_pow_usage_path
    ON pow_usage(path);
```

#### 13.6.2 原子递增：UPSERT 语句

使用 `INSERT ... ON CONFLICT` 保证并发安全：

```sql
INSERT INTO pow_usage (
    id, mode, path, sign, token_hash,
    uses, max_uses, first_ip, last_ip, user_agent,
    expires_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $7, $8, $9, $10, $10)
ON CONFLICT (id) DO UPDATE
SET uses = pow_usage.uses + 1,
    last_ip = EXCLUDED.last_ip,
    updated_at = EXCLUDED.updated_at
WHERE pow_usage.uses < pow_usage.max_uses
RETURNING uses, max_uses;
```

如果 `RETURNING` 为空，说明使用次数已耗尽。

### 13.7 内存存储

第一版开发阶段可提供内存存储：

```text
map[sign_id]*UsageRecord + mutex
```

适合：

1. 单机本地测试；
2. 课程演示；
3. 不想安装 PostgreSQL / Redis 时快速运行。

不适合生产：

1. 进程重启后记录丢失；
2. 多实例之间不共享；
3. 无法长期审计。

### 13.8 持久化场景与存储选型总结

系统中有多个地方需要状态或历史记录，存储选型如下：

| 数据 | 特点 | 推荐存储 | 说明 |
|---|---|---|---|
| generic 模式 sign 使用次数 | 高频读写，要求强原子性 | PostgreSQL 或 Redis | 第一版可用内存，生产建议 PostgreSQL |
| 风控计数器 (如 IP 10分钟请求次数) | 高频读写，允许极端情况丢失 | Redis | 内存也可，但分布式建议 Redis |
| 限流状态 (token bucket) | 高频读写 | Redis 或内存 | 单机内存足够 |
| 鉴权访问日志 (谁下载了什么) | 高频写入，需长期审计 | PostgreSQL | 异步写入，可批量 |
| 管理操作审计日志 (谁改了规则) | 低频写入，高安全要求 | PostgreSQL | 必须持久化 |
| 规则配置版本快照 | 低频写入 | PostgreSQL | 便于回滚 |

---

## 14. 配置设计

### 14.1 完整配置示例

```yaml
server:
  listen: "127.0.0.1:8080"
  read_timeout: "2s"
  write_timeout: "2s"
  idle_timeout: "30s"
  shutdown_timeout: "5s"

pow:
  enabled: true
  dry_run: false
  bypass_all: false

  token_param: "token"
  sign_param: "sign"
  max_token_length: 4096
  max_sign_length: 128

  algorithm: "sha256"
  public_salt: "2025-demo-salt"
  allow_empty_salt: true
  allowed_previous_salts: []

  modes:
    ip_bound:
      enabled: true
      min_difficulty: 22
      max_difficulty: 28
      max_ttl_seconds: 86400
      require_ip: true
      count_usage: false
      max_uses: 0

    generic:
      enabled: true
      min_difficulty: 22
      max_difficulty: 28
      max_ttl_seconds: 1800
      max_uses: 5
      count_head_request: false

protection:
  protected_extensions:
    - ".iso"
    - ".img"
    - ".qcow2"
    - ".vmdk"
    - ".vdi"
    - ".ova"
    - ".zip"
    - ".7z"
    - ".tar"
    - ".tar.gz"
    - ".tar.xz"

  protected_paths:
    - "^/ubuntu-releases/.+\\.iso$"
    - "^/debian-cd/.+\\.iso$"
    - "^/archlinux/iso/.+\\.iso$"

  excluded_paths:
    - "^/assets/"
    - "^/static/"
    - "^/\\.well-known/"
    - "^/.+/Packages(\\.gz|\\.xz|\\.zst)?$"
    - "^/.+/Release$"
    - "^/.+/InRelease$"
    - "^/.+/repomd\\.xml$"

storage:
  driver: "memory" # memory / postgres
  counter_driver: "memory" # memory / redis

  postgres:
    dsn: "postgres://user:pass@127.0.0.1:5432/mirrors_pow?sslmode=disable"
    max_open_conns: 20
    max_idle_conns: 5

  redis:
    addr: "127.0.0.1:6379"
    password: ""
    db: 0
    key_prefix: "mirrors-waf"

risk_control:
  enabled: true

  counters:
    ip_protected_requests_10m:
      key: "ip"
      window: "10m"
      when:
        is_protected: true
      storage: "redis"

    ip_missing_pow_1h:
      key: "ip"
      window: "1h"
      when:
        is_protected: true
        pow_status: "missing"
      storage: "redis"

  chains:
    INPUT:
      policy:
        target: RATE_LIMIT
        limit_rate: "512k"
        reason: "default_unverified_slow"
      rules:
        - name: "allow metadata"
          match:
            path_regex: "^/.+/(Packages|Release|InRelease|repomd\\.xml)(\\..+)?$"
          target: ACCEPT
          limit_rate: "0"
          reason: "metadata_full_speed"

        - name: "valid pow full speed"
          match:
            pow_status: "valid"
          target: ACCEPT
          limit_rate: "0"
          reason: "valid_pow_full_speed"

        - name: "invalid pow reject"
          match:
            pow_status_in: ["invalid", "expired", "used_up"]
          target: REJECT
          status: 403
          reason: "invalid_pow"

        - name: "missing pow risk check"
          match:
            is_protected: true
            pow_status: "missing"
          target: JUMP
          chain: RISK_CHECK

    RISK_CHECK:
      policy:
        target: RATE_LIMIT
        limit_rate: "512k"
        reason: "normal_unverified_slow"
      rules:
        - name: "many protected requests"
          match:
            counter:
              name: "ip_protected_requests_10m"
              op: ">="
              value: 5
          target: RATE_LIMIT
          limit_rate: "128k"
          reason: "many_protected_requests"

admin:
  enabled: false
  listen: "127.0.0.1:8081"
  auth:
    type: "token"
    token_file: "/etc/mirrors-waf/admin.token"
  allow_cidrs:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
  audit_log: true

logging:
  level: "info"
  format: "json"
  log_access: true
  log_denied: true
  hash_ip: false

cleanup:
  enabled: true
  interval: "10m"
  expired_grace_period: "24h"
```

### 14.2 模式默认参数建议

| 参数 | ip_bound | generic |
|---|---:|---:|
| TTL | 12-24 小时 | 10-30 分钟 |
| difficulty | 22 | 22 |
| max uses | 不限制或 50 | 3-10 |
| 是否检查 IP | 是 | 否 |
| 是否需要存储 | 否 | 是 |

### 14.3 配置校验

启动时必须校验：

1. 至少启用一种 mode；
2. `min_difficulty <= max_difficulty`；
3. `max_ttl_seconds > 0`；
4. generic 模式启用时 `max_uses > 0`；
5. protected / excluded 正则可编译；
6. storage driver 合法；
7. PostgreSQL 配置可连接，或内存模式开启；
8. token 和 sign 参数名非空；
9. 如果启用 `risk_control`，必须校验 chain、rule、target、counter 配置合法；
10. 如果启用 `admin`，必须校验监听地址、鉴权方式、allow_cidrs 和 token_file。

---

## 15. Go 项目结构设计

```text
backend/
  go.mod
  cmd/
    server/
      main.go
  internal/
    app/
      app.go
      wire.go
    config/
      config.go
      loader.go
      validate.go
    transport/
      echo/
        server.go
        routes.go
        handlers.go
        admin_handlers.go
        middleware.go
        response.go
    auth/
      service.go
      request.go
      result.go
      errors.go
    pow/
      token.go
      canonical.go
      verify.go
      difficulty.go
      sign_id.go
    matcher/
      matcher.go
      extension.go
      regex.go
    storage/
      store.go
      memory/
        memory.go
      postgres/
        postgres.go
        migrations.go
      redis/
        redis.go
        lua.go
    risk/
      engine.go
      chain.go
      rule.go
      matcher.go
      target.go
      counter.go
      config.go
    admin/
      service.go
      dto.go
      audit.go
      auth.go
      validator.go
    logging/
      logger.go
    metrics/
      metrics.go
    clock/
      clock.go
  migrations/
    001_init.sql
  configs/
    config.example.yaml
```

### 15.1 分层原则

```text
transport/echo -> auth / admin -> pow / matcher / risk / storage
```

要求：

1. `transport/echo` 只负责 HTTP 适配；
2. `auth` 编排下载鉴权流程；
3. `admin` 编排 Web 管理 API 动作，不直接操作底层规则文件；
4. `pow` 只负责 token、sign、难度；
5. `matcher` 只负责路径保护判断；
6. `risk` 负责类 iptables 规则链、风控决策、限速决策；
7. `storage` 只负责使用次数和风控计数器存储；
8. 核心模块不依赖 Echo。

---

## 16. 核心数据结构

### 16.1 AuthRequest

```go
type AuthRequest struct {
    OriginalURI    string
    OriginalMethod string
    OriginalArgs   string
    RealIP         string
    ForwardedFor   string
    UserAgent      string
}
```

### 16.2 TokenPayload

```go
type TokenPayload struct {
    Version    int    `json:"v"`
    Mode       string `json:"mode"`
    Algorithm  string `json:"alg"`
    IP         string `json:"ip,omitempty"`
    Path       string `json:"path"`
    Timestamp  int64  `json:"ts"`
    ExpiresAt  int64  `json:"exp"`
    Difficulty int    `json:"d"`
    Counter    string `json:"cnt"`
    Salt       string `json:"salt,omitempty"`
}
```

### 16.3 AuthResult

```go
type AuthResult struct {
    Allowed     bool
    HTTPStatus  int
    Reason      string
    Mode        string
    SignID      string
    Uses        int
    MaxUses     int
    ErrorHeader string
}
```

---

## 17. 错误码设计

| Reason | HTTP 状态 | 说明 |
|---|---:|---|
| `not_protected` | 200 | 路径不需要验证 |
| `ip_bound_valid` | 200 | IP 绑定模式验证通过 |
| `generic_valid` | 200 | 通用链接模式验证通过 |
| `dry_run_allow` | 200 | dry-run 模式放行 |
| `bypass_all` | 200 | 全局绕过 |
| `missing_headers` | 500 | Nginx 未传必要 header |
| `invalid_original_uri` | 403 | 原始路径非法 |
| `missing_token_or_sign` | 403 | 缺少 token 或 sign |
| `token_too_long` | 403 | token 过长 |
| `sign_too_long` | 403 | sign 过长 |
| `malformed_token` | 403 | token 解码或 JSON 解析失败 |
| `unsupported_version` | 403 | 不支持的版本 |
| `unsupported_mode` | 403 | 不支持的模式 |
| `mode_disabled` | 403 | 当前模式被禁用 |
| `unsupported_algorithm` | 403 | 不支持的算法 |
| `path_mismatch` | 403 | token path 与真实请求 path 不一致 |
| `expired` | 403 | 已过期 |
| `ttl_too_long` | 403 | TTL 超过该模式允许上限 |
| `timestamp_from_future` | 403 | token 生成时间明显晚于服务器时间 |
| `difficulty_too_low` | 403 | 难度低于配置 |
| `difficulty_too_high` | 403 | 难度高于配置 |
| `invalid_counter` | 403 | cnt 非法 |
| `invalid_salt` | 403 | salt 非法 |
| `invalid_sign_format` | 403 | sign 不是合法 hex |
| `sign_mismatch` | 403 | sign 与后端计算结果不一致 |
| `difficulty_not_met` | 403 | hash 不满足前导零要求 |
| `ip_mismatch` | 403 | 请求 IP 与 token IP 不一致 |
| `used_up` | 403 | 通用链接使用次数耗尽 |
| `rate_limited` | 429 | 被限流 |
| `storage_error` | 500 | 存储异常 |
| `internal_error` | 500 | 未知错误 |

---

## 18. 风控规则引擎设计

### 18.1 设计动机

如果风控逻辑全部写死在 Go 代码里，后续会遇到几个问题：

1. 不同镜像站保护路径不同；
2. 不同文件类型的风险不同；
3. 不同阶段的策略不同，例如测试期、灰度期、正式期；
4. 风控阈值需要频繁调整；
5. 写死规则会导致每次调策略都要改代码、重新编译、重新发布。

因此，风控模块应设计成可选能力，并支持通过配置文件定义规则。

核心思想参考 `iptables`：

```text
一个请求进入后，按照配置文件定义的规则链从上到下匹配。
匹配到规则后执行对应动作。
动作可以是 ACCEPT、REJECT、RATE_LIMIT、JUMP、RETURN、LOG 等。
```

### 18.2 是否启用风控

风控模块必须可选。

```yaml
risk_control:
  enabled: true
```

如果关闭：

```yaml
risk_control:
  enabled: false
```

则后端只执行基础 PoW 验证逻辑：

1. 非保护路径放行；
2. 合法 token/sign 全速放行；
3. 非法 token/sign 拒绝；
4. 无 token/sign 按默认策略限速或放行。

### 18.3 类 iptables 的规则模型

规则引擎由三部分组成：

```text
Table -> Chain -> Rule -> Target
```

对应关系：

| 概念 | 说明 |
|---|---|
| Table | 一组规则集合，例如 `download_filter` |
| Chain | 规则链，例如 `INPUT`、`POW_CHECK`、`RISK_CHECK` |
| Rule | 一条具体匹配规则 |
| Match | 匹配条件，例如路径、后缀、IP、UA、请求频率 |
| Target | 匹配后的动作，例如 ACCEPT、REJECT、RATE_LIMIT、JUMP |
| Policy | 链没有命中任何规则时的默认动作 |

### 18.4 请求处理总流程

```mermaid
flowchart TD
    A[收到 /verify_pow 请求] --> B[构造 RequestContext]
    B --> C[基础字段解析 path/ip/args/ua/method]
    C --> D[执行 INPUT 规则链]
    D --> E{规则链返回动作}
    E -- ACCEPT --> F[返回 200 全速或指定限速]
    E -- RATE_LIMIT --> G[返回 200 + X-Pow-Limit-Rate]
    E -- REJECT --> H[返回 403]
    E -- DROP/TOO_MANY --> I[返回 429]
    E -- REQUIRE_POW --> J[执行 token/sign 验证]
    J --> K{PoW 是否通过}
    K -- 是 --> L[继续执行 AFTER_POW 链]
    K -- 否 --> H
    L --> M{AFTER_POW 返回动作}
    M -- ACCEPT --> F
    M -- RATE_LIMIT --> G
    M -- REJECT --> H
```

### 18.5 RequestContext

每个请求进入规则引擎前，先构造统一上下文。

```go
type RequestContext struct {
    Path           string
    Method         string
    Args           string
    IP             string
    UserAgent      string
    HasToken       bool
    HasSign        bool
    PowStatus      string // missing / valid / invalid / expired / used_up
    PowMode        string // empty / ip_bound / generic
    FileExt        string
    IsProtected    bool
    IsRangeRequest bool
    RiskScore      int
    Counters       map[string]int64
}
```

### 18.6 支持的匹配条件

第一版规则匹配不需要做成复杂 DSL，建议使用 YAML 中的结构化字段。

| 匹配字段 | 示例 | 说明 |
|---|---|---|
| `path_regex` | `^/ubuntu-releases/.+\.iso$` | 路径正则 |
| `path_prefix` | `/ubuntu-releases/` | 路径前缀 |
| `extension_in` | `[".iso", ".img"]` | 后缀列表 |
| `method_in` | `["GET", "HEAD"]` | 方法列表 |
| `ip_cidr_in` | `["10.0.0.0/8"]` | IP 段匹配 |
| `user_agent_regex` | `(?i)(curl|wget)` | UA 正则 |
| `pow_status` | `missing` | PoW 状态 |
| `pow_mode` | `generic` | PoW 模式 |
| `is_range_request` | `true` | 是否 Range 请求 |
| `counter` | 见下文 | 计数器条件 |
| `risk_score_gte` | `80` | 风险分阈值 |

### 18.7 支持的动作 Target

| Target | 说明 |
|---|---|
| `ACCEPT` | 放行，可指定限速 |
| `REJECT` | 拒绝，返回 403 |
| `RATE_LIMIT` | 放行但限速 |
| `TOO_MANY` | 返回 429 |
| `REQUIRE_POW` | 要求执行 PoW 验证 |
| `JUMP` | 跳转到另一个规则链 |
| `RETURN` | 从当前链返回上一层 |
| `LOG` | 记录日志后继续匹配下一条 |
| `MARK` | 给请求打标，例如 `suspect` |

### 18.8 规则链执行语义

规则链从上到下执行：

```text
rule[0] -> rule[1] -> rule[2] -> ... -> policy
```

每条规则：

1. 先判断 `match` 是否满足；
2. 不满足则继续下一条；
3. 满足则执行 `target`；
4. 如果 target 是终止动作，则直接返回；
5. 如果 target 是 `LOG` 或 `MARK`，则继续下一条；
6. 如果 target 是 `JUMP`，进入子链；
7. 子链 `RETURN` 后回到原链继续执行。

终止动作：

```text
ACCEPT / REJECT / RATE_LIMIT / TOO_MANY / REQUIRE_POW
```

非终止动作：

```text
LOG / MARK
```

### 18.9 配置示例：基础规则链

```yaml
risk_control:
  enabled: true

  chains:
    INPUT:
      policy:
        target: RATE_LIMIT
        limit_rate: "512k"
        reason: "default_unverified_slow"

      rules:
        - name: "allow package metadata"
          match:
            path_regex: "^/.+/(Packages|Release|InRelease|repomd\\.xml)(\\..+)?$"
          target: ACCEPT
          limit_rate: "0"
          reason: "metadata_full_speed"

        - name: "allow non protected path"
          match:
            is_protected: false
          target: ACCEPT
          limit_rate: "0"
          reason: "not_protected"

        - name: "reject invalid pow"
          match:
            pow_status_in: ["invalid", "expired", "used_up"]
          target: REJECT
          status: 403
          reason: "invalid_pow"

        - name: "allow valid pow full speed"
          match:
            pow_status: "valid"
          target: ACCEPT
          limit_rate: "0"
          reason: "valid_pow_full_speed"

        - name: "jump to risk check for missing pow"
          match:
            pow_status: "missing"
            is_protected: true
          target: JUMP
          chain: RISK_CHECK

    RISK_CHECK:
      policy:
        target: RATE_LIMIT
        limit_rate: "512k"
        reason: "normal_unverified_slow"

      rules:
        - name: "too many protected downloads per ip"
          match:
            counter:
              name: "ip_protected_requests_10m"
              op: ">="
              value: 5
          target: RATE_LIMIT
          limit_rate: "128k"
          reason: "too_many_protected_requests"

        - name: "extreme abuse"
          match:
            counter:
              name: "ip_protected_requests_1h"
              op: ">="
              value: 20
          target: TOO_MANY
          status: 429
          reason: "extreme_abuse"
```

### 18.10 计数器设计

风控规则中的很多条件需要历史状态，例如：

1. 某 IP 10 分钟内请求了多少个大文件；
2. 某 IP 1 小时内触发了多少次无 token 请求；
3. 某 IP 同时有多少个 Range 请求；
4. 某 IP 请求了多少个不同 ISO。

因此需要定义计数器。

```yaml
risk_control:
  counters:
    ip_protected_requests_10m:
      key: "ip"
      window: "10m"
      when:
        is_protected: true
      storage: "redis"

    ip_missing_pow_1h:
      key: "ip"
      window: "1h"
      when:
        is_protected: true
        pow_status: "missing"
      storage: "redis"

    ip_range_requests_10m:
      key: "ip"
      window: "10m"
      when:
        is_range_request: true
      storage: "redis"
```

计数器 key 示例：

```text
risk:counter:ip_protected_requests_10m:203.0.113.10:202501010930
```

第一版可以支持：

| 存储 | 适用场景 |
|---|---|
| 内存 | 本地开发、课程演示 |
| PostgreSQL | 生产环境持久化 |
| Redis | 生产环境风控计数器、限流 |

### 18.11 风控结果 Decision

规则引擎最终输出统一 Decision。

```go
type Decision struct {
    Target     string // ACCEPT / REJECT / RATE_LIMIT / TOO_MANY / REQUIRE_POW
    StatusCode int
    LimitRate  string
    Reason     string
    Chain      string
    RuleName   string
    Marks      []string
}
```

映射到 HTTP 响应：

| Target | HTTP 状态 | Header | Nginx 行为 |
|---|---:|---|---|
| `ACCEPT` | 200 | `X-Pow-Limit-Rate: 0` | 全速放行 |
| `RATE_LIMIT` | 200 | `X-Pow-Limit-Rate: 512k` | 限速放行 |
| `REJECT` | 403 | `X-Pow-Error: reason` | 拒绝 |
| `TOO_MANY` | 429 | `X-Pow-Error: reason` | 限流 |

### 18.12 Go 模块设计

建议新增模块：

```text
internal/risk/
  engine.go       # 规则引擎入口
  chain.go        # Chain 执行逻辑
  rule.go         # Rule 定义
  matcher.go      # Match 条件判断
  target.go       # Target 动作
  counter.go      # 计数器接口
  config.go       # YAML 配置结构
```

核心接口：

```go
type Engine interface {
    Evaluate(ctx context.Context, req *RequestContext) (Decision, error)
}

type CounterStore interface {
    Incr(ctx context.Context, name string, key string, window time.Duration) (int64, error)
    Get(ctx context.Context, name string, key string, window time.Duration) (int64, error)
}
```

### 18.13 与 PoW 验证的关系

推荐顺序：

```text
基础解析 -> PoW 轻量解析 -> 规则链判断 -> 必要时执行完整 PoW 验证 -> 再次进入规则链
```

更具体：

1. 先解析请求路径、IP、UA；
2. 判断是否受保护路径；
3. 如果存在 token/sign，先执行 PoW 验证，得到 `pow_status`；
4. 如果不存在 token/sign，则 `pow_status = missing`；
5. 将所有状态放入 `RequestContext`；
6. 执行 `INPUT` 规则链；
7. 输出最终 Decision。

这样规则文件可以统一处理：

```text
missing / valid / invalid / expired / used_up
```

### 18.14 Nginx 限速接入

```nginx
location ~* \.(iso|img|qcow2|zip|7z|tar|tar\.gz|tar\.xz)$ {
    auth_request /_pow_auth;

    auth_request_set $pow_limit_rate $upstream_http_x_pow_limit_rate;
    auth_request_set $pow_decision $upstream_http_x_pow_decision;
    auth_request_set $pow_rule $upstream_http_x_pow_rule;
    auth_request_set $pow_error $upstream_http_x_pow_error;

    limit_rate $pow_limit_rate;

    error_page 403 = @pow_forbidden;
    error_page 429 = @pow_rate_limited;

    try_files $uri =404;
}
```

### 18.15 规则配置校验

启动时必须校验：

1. 所有 chain 名称唯一；
2. `JUMP` 指向的 chain 必须存在；
3. 不允许明显循环跳转；
4. 正则表达式必须可编译；
5. `limit_rate` 格式合法；
6. counter 名称必须存在；
7. policy 必须存在；
8. target 必须是受支持类型。

### 18.16 第一版实现建议

第一版不需要实现完整 iptables 能力，只实现够用子集：

必须实现：

1. Chain 顺序执行；
2. Rule match；
3. `ACCEPT`；
4. `REJECT`；
5. `RATE_LIMIT`；
6. `TOO_MANY`；
7. `JUMP`；
8. `RETURN`；
9. IP 计数器；
10. YAML 配置加载和校验。

可选增强，但第一版不强制实现：

1. 复杂表达式 DSL；
2. 地理位置库；
3. ASN 风险库；
4. 机器学习风险分；
5. Web 管理后台。

这些能力应在架构上预留扩展点，避免后续重构。

### 18.17 高级风控能力预留

高级能力不作为第一版验收必需项，但可以在模块边界上提前预留。

#### 18.17.1 复杂表达式 DSL

结构化 YAML match 足够覆盖第一版需求，但后续可能需要更灵活的表达式，例如：

```text
is_protected && pow_status == "missing" && counter("ip_missing_pow_1h") >= 10
```

建议预留表达式字段：

```yaml
rules:
  - name: "complex condition example"
    expr: "is_protected && pow_status == 'missing' && counter('ip_missing_pow_1h') >= 10"
    target: RATE_LIMIT
    limit_rate: "128k"
```

实现建议：

1. 第一版可以不解析 `expr`，启动时如果发现 `expr` 则报错或忽略；
2. 后续可接入轻量表达式引擎；
3. 表达式必须是沙箱执行，不能允许任意 Go 代码或系统调用；
4. 表达式可访问字段应限制在 `RequestContext` 和已注册 counter 中。

#### 18.17.2 地理位置库

后续可以根据 IP 所属地区做策略调整，例如：

```yaml
match:
  geo_country_in: ["CN", "HK", "MO", "TW"]
```

预留字段：

| 字段 | 说明 |
|---|---|
| `geo_country` | 国家或地区代码 |
| `geo_region` | 省份或区域 |
| `geo_city` | 城市，可选 |

实现建议：

1. GeoIP 数据库本地加载，不在请求路径中调用外部网络服务；
2. 支持配置关闭；
3. 数据库文件路径配置化；
4. 查询失败时不要拒绝请求，只设置 `geo_unknown = true`。

#### 18.17.3 ASN 风险库

后续可识别云厂商、IDC、运营商、教育网等来源。

预留匹配字段：

```yaml
match:
  asn_in: ["AS4134", "AS4837"]
```

或：

```yaml
match:
  asn_type_in: ["idc", "cloud", "residential", "education"]
```

用途：

1. 对 IDC / 云服务器来源的大文件无 token 请求更严格；
2. 对教育网或校园网正常用户更宽松；
3. 对已知 PCDN 高风险 ASN 降速或限流。

#### 18.17.4 机器学习风险分

机器学习风险分不建议第一版实现，但可以预留 `risk_score` 字段。

```go
type RequestContext struct {
    RiskScore int
    RiskTags  []string
}
```

配置示例：

```yaml
rules:
  - name: "high ml risk"
    match:
      risk_score_gte: 80
    target: RATE_LIMIT
    limit_rate: "64k"
    reason: "high_ml_risk"
```

实现建议：

1. 第一版 `risk_score` 可由规则计算得到；
2. 后续可由离线模型、在线模型或外部风险服务写入；
3. 模型不可成为强依赖，异常时应降级到规则引擎；
4. 风险分只作为辅助，不应单独作为永久封禁依据。

### 18.18 Web 管理接口预留

Web 管理后台可以实现，但第一版只建议预留 API，不一定实现完整页面。

根据需求，管理接口不采用 RESTful 风格，而采用 **RPC / Action 风格**。

也就是说，不设计成：

```text
GET    /admin/rules
POST   /admin/rules
PUT    /admin/rules/{id}
DELETE /admin/rules/{id}
```

而设计成：

```text
POST /admin/api/rule.list
POST /admin/api/rule.create
POST /admin/api/rule.update
POST /admin/api/rule.delete
POST /admin/api/rule.validate
POST /admin/api/rule.preview
POST /admin/api/rule.reload
```

#### 18.18.1 管理接口设计原则

1. **默认关闭**  
   管理 API 默认不启用，避免增加攻击面。

2. **只监听本机或内网**  
   推荐单独监听 `127.0.0.1:8081`，或只允许内网访问。

3. **RPC 风格，不使用 RESTful**  
   每个接口名称明确表达动作，便于前端后台直接调用。

4. **全部使用 POST**  
   除健康检查外，管理动作统一使用 POST + JSON body，避免误触发和缓存问题。

5. **配置变更先校验，再生效**  
   所有规则变更必须经过 validate，不能直接写入运行态。

6. **支持 dry-run / preview**  
   可以用一条模拟请求测试规则链会命中哪条规则。

7. **必须有审计日志**  
   所有管理动作记录操作者、时间、变更摘要。

#### 18.18.2 管理接口配置

```yaml
admin:
  enabled: false
  listen: "127.0.0.1:8081"
  auth:
    type: "token" # token / basic / none，仅开发允许 none
    token_file: "/etc/mirrors-waf/admin.token"
  allow_cidrs:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
  audit_log: true
```

生产建议：

1. `enabled` 默认 false；
2. 不直接暴露公网；
3. 如果需要远程访问，通过 SSH tunnel 或内网 VPN；
4. 不建议和 `/verify_pow` 共用公网入口。

#### 18.18.3 管理 API 列表

| 接口 | 方法 | 说明 |
|---|---|---|
| `/admin/api/system.ping` | POST | 管理接口连通性检查 |
| `/admin/api/system.info` | POST | 查看版本、启动时间、配置摘要 |
| `/admin/api/config.get` | POST | 获取当前配置脱敏视图 |
| `/admin/api/config.validate` | POST | 校验一份待应用配置 |
| `/admin/api/config.apply` | POST | 应用新配置，可选择是否热加载 |
| `/admin/api/rule.list` | POST | 查看规则链和规则列表 |
| `/admin/api/rule.get` | POST | 查看单条规则详情 |
| `/admin/api/rule.create` | POST | 新增规则 |
| `/admin/api/rule.update` | POST | 修改规则 |
| `/admin/api/rule.delete` | POST | 删除规则 |
| `/admin/api/rule.move` | POST | 调整规则顺序 |
| `/admin/api/rule.enable` | POST | 启用规则 |
| `/admin/api/rule.disable` | POST | 禁用规则 |
| `/admin/api/rule.validate` | POST | 校验规则合法性 |
| `/admin/api/rule.preview` | POST | 用模拟请求预览规则命中结果 |
| `/admin/api/rule.reload` | POST | 从配置文件重新加载规则 |
| `/admin/api/counter.get` | POST | 查询计数器当前值 |
| `/admin/api/counter.reset` | POST | 重置某个计数器 |
| `/admin/api/decision.test` | POST | 输入请求上下文，测试最终 Decision |
| `/admin/api/audit.list` | POST | 查询管理操作审计日志 |

#### 18.18.4 通用响应格式

所有管理 API 使用统一响应：

```json
{
  "ok": true,
  "code": "OK",
  "message": "success",
  "data": {},
  "request_id": "req_123456"
}
```

失败响应：

```json
{
  "ok": false,
  "code": "VALIDATION_FAILED",
  "message": "rule target is unsupported",
  "data": {
    "field": "target",
    "value": "UNKNOWN"
  },
  "request_id": "req_123456"
}
```

#### 18.18.5 rule.preview 示例

请求：

```http
POST /admin/api/rule.preview HTTP/1.1
Content-Type: application/json
Authorization: Bearer <admin-token>
```

```json
{
  "request": {
    "path": "/ubuntu.iso",
    "method": "GET",
    "ip": "203.0.113.10",
    "user_agent": "wget/1.21",
    "pow_status": "missing",
    "is_protected": true,
    "is_range_request": false
  }
}
```

响应：

```json
{
  "ok": true,
  "code": "OK",
  "message": "success",
  "data": {
    "decision": {
      "target": "RATE_LIMIT",
      "status_code": 200,
      "limit_rate": "512k",
      "reason": "normal_unverified_slow"
    },
    "trace": [
      {
        "chain": "INPUT",
        "rule": "allow metadata",
        "matched": false
      },
      {
        "chain": "INPUT",
        "rule": "missing pow risk check",
        "matched": true,
        "target": "JUMP",
        "jump_to": "RISK_CHECK"
      },
      {
        "chain": "RISK_CHECK",
        "rule": "policy",
        "matched": true,
        "target": "RATE_LIMIT"
      }
    ]
  },
  "request_id": "req_123456"
}
```

#### 18.18.6 rule.move 示例

请求：

```json
{
  "chain": "INPUT",
  "rule_name": "invalid pow reject",
  "position": 1
}
```

说明：

```text
将规则 invalid pow reject 移动到 INPUT 链第 1 位。
```

这比 RESTful 的 `PUT /rules/{id}` 更直接表达后台操作意图。

#### 18.18.7 config.apply 安全策略

`config.apply` 必须分阶段执行：

```text
上传配置 -> 解析 -> 校验 -> 试运行构建 Engine -> 原子替换运行态 -> 写审计日志
```

失败时保持旧配置继续运行。

响应示例：

```json
{
  "ok": true,
  "code": "OK",
  "message": "config applied",
  "data": {
    "version": 12,
    "active_chains": ["INPUT", "RISK_CHECK"],
    "rule_count": 18
  },
  "request_id": "req_123456"
}
```

#### 18.18.8 后端模块预留

建议预留目录：

```text
internal/admin/
  service.go       # 管理动作编排
  dto.go           # 请求/响应结构
  audit.go         # 审计日志
  auth.go          # 管理鉴权
  validator.go     # 配置和规则校验
```

Echo 适配层：

```text
internal/transport/echo/admin_handlers.go
```

#### 18.18.9 第一版建议

第一版如果时间有限，可以只实现以下接口：

1. `/admin/api/system.ping`；
2. `/admin/api/system.info`；
3. `/admin/api/config.validate`；
4. `/admin/api/rule.preview`；
5. `/admin/api/rule.reload`。

完整规则编辑和 Web 页面可作为后续增强。

---

## 19. 日志设计

### 19.1 结构化日志示例

```json
{
  "ts": "2025-01-01T00:00:00Z",
  "level": "info",
  "event": "pow_verify",
  "allowed": true,
  "reason": "generic_valid",
  "mode": "generic",
  "path": "/ubuntu.iso",
  "ip": "203.0.113.10",
  "user_agent": "curl/8.5.0",
  "sign_id": "abc123",
  "difficulty": 22,
  "uses": 1,
  "max_uses": 5,
  "elapsed_ms": 2
}
```

### 19.2 失败日志示例

```json
{
  "ts": "2025-01-01T00:00:00Z",
  "level": "warn",
  "event": "pow_verify",
  "allowed": false,
  "reason": "ip_mismatch",
  "mode": "ip_bound",
  "path": "/ubuntu.iso",
  "ip": "203.0.113.20",
  "token_ip": "203.0.113.10",
  "elapsed_ms": 1
}
```

### 19.3 IP 脱敏

生产环境可配置：

```yaml
logging:
  hash_ip: true
```

记录：

```text
sha256(ip + log_salt)
```

---

## 20. 安全设计

### 20.1 token 可见性

token 是 Base64URL，不是加密。任何人都可以看到 token 中的 path、mode、exp 等字段。

安全性不依赖 token 保密，而依赖：

1. sign 的 PoW 成本；
2. 路径绑定；
3. 过期时间；
4. IP 绑定或次数限制；
5. 后端重新计算和校验。

### 20.2 防止修改 token

攻击者可以修改 token，但修改后必须重新计算满足难度的 sign。

后端还会限制：

1. 最大 TTL；
2. 最低难度；
3. 支持模式；
4. path 必须等于实际请求路径；
5. generic 使用次数。

### 20.3 防止跨路径复用

token 中包含 path，canonical string 中也包含 path。

后端必须检查：

```text
token.path == X-Original-URI
```

否则拒绝。

### 20.4 防止链接无限传播

针对通用链接模式：

1. TTL 短；
2. max uses 小；
3. PostgreSQL / Redis 原子计数；
4. 使用次数达到上限后拒绝。

### 20.5 IP 绑定风险

IP 绑定模式可能受到以下影响：

1. 用户移动网络 IP 变化；
2. 用户处于多出口 NAT；
3. CDN / 代理未正确传真实 IP；
4. IPv6 临时地址变化。

因此前端应提示：

```text
如果你要复制链接到其他机器，请选择“通用链接短效模式”。
```

### 20.6 后端接口不暴露公网

后端应只监听：

```text
127.0.0.1:8080
```

Nginx 内部 location：

```nginx
location = /_pow_auth {
    internal;
    proxy_pass http://127.0.0.1:8080/verify_pow;
}
```

### 20.7 Fail-close 与 bypass

默认策略：fail-close。

即后端异常时，大文件下载失败。

同时提供紧急配置：

```yaml
pow:
  bypass_all: true
```

用于后端故障或误拦截时临时放行。

---

## 21. Dry-run 设计

### 21.1 用途

上线前可以使用 dry-run 观察误拦截情况。

配置：

```yaml
pow:
  dry_run: true
```

行为：

1. 后端完整验证 token 和 sign；
2. 如果本应拒绝，记录日志；
3. 最终仍返回 200 放行。

### 21.2 响应头

```http
HTTP/1.1 200 OK
X-Pow-Result: allow
X-Pow-Reason: dry_run_allow
X-Pow-Dry-Run-Original-Error: missing_token_or_sign
```

---

## 22. HEAD 与 Range 请求

### 22.1 HEAD 请求

下载工具可能先发送 HEAD 获取文件大小。

推荐：

```yaml
pow:
  modes:
    generic:
      count_head_request: false
```

策略：

1. HEAD 仍需验证 token 和 sign；
2. HEAD 不消耗 generic 使用次数；
3. GET 消耗使用次数。

### 22.2 Range 请求

断点续传会产生 Range 请求。

第一版策略：

1. Range 请求仍需 token + sign；
2. Range 请求按 GET 计数；
3. generic 的 `max_uses` 不宜过小，建议 5-10。

后续优化：

1. 同一 IP；
2. 同一 sign；
3. 短时间内多个 Range 请求；
4. 合并计为一次使用。

---

## 23. 测试方案

### 23.1 单元测试

#### token 模块

| 测试项 | 说明 |
|---|---|
| Base64URL 解码 | 合法、非法、空字符串 |
| JSON 解析 | 缺字段、类型错误 |
| mode 校验 | `ip_bound`、`generic`、非法 mode |
| path 校验 | 空 path、非 `/` 开头、超长 path |
| 时间校验 | 过期、TTL 超限、未来时间 |
| difficulty 校验 | 低于最小、高于最大 |
| cnt 校验 | 非法字符、超长 |
| sign 校验 | 非 hex、长度错误 |

#### pow 模块

| 测试项 | 说明 |
|---|---|
| canonical string | ip_bound / generic 输出固定 |
| SHA-256 | 固定输入固定输出 |
| sign compare | 大小写、错误 sign |
| leading zero bits | 0、1、7、8、9、16、22 边界 |

#### auth 模块

| 测试项 | 预期 |
|---|---|
| 小文件无 token | 200 |
| 大文件无 token | 403 |
| token path 不匹配 | 403 |
| sign 不匹配 | 403 |
| PoW 难度不足 | 403 |
| ip_bound IP 匹配 | 200 |
| ip_bound IP 不匹配 | 403 |
| generic 首次使用 | 200 |
| generic 超过次数 | 403 |
| dry-run | 200 并记录原错误 |

### 23.2 集成测试

| 编号 | 场景 | 预期 |
|---|---|---|
| IT-001 | 小文件无 token/sign | 200 |
| IT-002 | 大文件无 token/sign | 403 |
| IT-003 | 大文件非法 token | 403 |
| IT-004 | 大文件 sign mismatch | 403 |
| IT-005 | generic 合法链接 curl 下载 | 200 |
| IT-006 | generic 使用超过 max_uses | 403 |
| IT-007 | ip_bound 同 IP 下载 | 200 |
| IT-008 | ip_bound 不同 IP 下载 | 403 |
| IT-009 | token path 改成另一个文件 | 403 |
| IT-010 | 过期 token | 403 |
| IT-011 | HEAD 不计数 | uses 不增加 |
| IT-012 | Range 下载 | 在次数范围内通过 |

### 23.3 并发测试

配置：

```yaml
generic.max_uses: 3
```

并发请求 20 次同一个 generic 链接。

预期：

```text
最多 3 次返回 200，其余返回 403 used_up
```

---

## 24. 开发里程碑

### 24.1 第一阶段：最小可用版本

必须实现：

1. Echo 服务启动；
2. `/verify_pow`；
3. Nginx header 解析；
4. 路径保护规则；
5. token + sign 解析；
6. canonical string 构造；
7. SHA-256 + 前导零验证；
8. `ip_bound` 模式；
9. `generic` 模式；
10. 内存存储或 PostgreSQL 存储；
11. 基础日志；
12. Nginx 配置示例。

### 24.2 第二阶段：增强版本

实现：

1. PostgreSQL 持久化存储；
2. Redis 计数器与限流；
3. dry-run；
4. bypass；
5. 可选风控规则链；
6. 清理任务；
7. 单元测试；
8. 集成测试脚本。

### 24.3 第三阶段：生产化

实现：

1. Prometheus metrics；
2. IP 脱敏；
3. systemd 部署；
4. 压测报告；
5. 动态难度策略；
6. 与流量监控联动。

---

## 25. 后端验收标准

### 25.1 功能验收

必须满足：

1. 非保护路径不需要 token/sign；
2. 保护路径缺少 token/sign 被拒绝；
3. token 格式错误被拒绝；
4. sign 不匹配被拒绝；
5. PoW 难度不足被拒绝；
6. token path 与请求 path 不一致被拒绝；
7. token 过期被拒绝；
8. `ip_bound` 同 IP 请求通过；
9. `ip_bound` 不同 IP 请求拒绝；
10. `generic` 合法请求通过；
11. `generic` 超过使用次数拒绝；
12. curl/wget 使用合法 generic 链接可下载；
13. Nginx 通过 auth_request 正确放行/拒绝；
14. 后端日志能记录 mode、reason、path、ip、uses。

### 25.2 工程验收

1. Echo 项目结构清晰；
2. 配置文件完整；
3. 存储层有抽象接口；
4. 单元测试覆盖核心验证逻辑；
5. 集成测试覆盖 Nginx + 后端；
6. 提供 Nginx 配置；
7. 提供本地启动说明；
8. 支持 dry-run 和 bypass。

---

## 26. 无头环境兼容与安全权衡方案

### 26.1 问题本质

传统人机验证方案最大的问题是：

```text
验证必须在浏览器里完成，但真正下载经常发生在 wget / curl / 远程服务器 / 无头环境里。
```

如果把验证逻辑设计成“浏览器通过验证后才能在当前浏览器会话里下载”，那么会直接破坏镜像站非常重要的使用场景：

1. 用户在服务器上用 `wget` 下载 ISO；
2. 用户在无 GUI 环境中用 `curl` 下载镜像；
3. 用户把链接复制到远程机器下载；
4. 用户使用自动化脚本下载大文件；
5. 用户使用 aria2、多线程下载工具。

因此，本项目不能采用传统的“浏览器会话验证通过后放行”的方式。

### 26.2 核心权衡原则

本系统的权衡原则是：

```text
PoW 不应该成为 wget/curl 的硬门槛，而应该成为“获得更好下载待遇”的加速通道。
```

换句话说：

1. 没有 token/sign 的 wget/curl 请求不一定直接拒绝；
2. 未验证请求可以被限速、限并发、限额度；
3. 完成 PoW 后获得 token/sign，可以恢复正常速度或更高额度；
4. 浏览器只是生成 token/sign 的一种方式，不应成为唯一方式；
5. Nginx 下载接口仍然是普通静态文件 URL；
6. 后端只做内部验证，不暴露公网签发 API。

最终目标不是“强制用户必须打开浏览器下载”，而是：

```text
让用户为大文件下载支付一次可接受的计算成本，然后得到一个普通 URL。
```

这个普通 URL 可以继续用于：

```bash
wget 'https://mirrors.example.edu/ubuntu.iso?token=...&sign=...'
```

或者：

```bash
curl -L -O 'https://mirrors.example.edu/ubuntu.iso?token=...&sign=...'
```

### 26.3 解决方案一：验证生成与实际下载分离

系统不要求实际下载发生在浏览器中。

推荐流程：

```text
浏览器静态页面负责生成 token + sign
          |
          v
用户得到签名 URL
          |
          v
wget / curl / 浏览器 使用该 URL 全速下载
          |
          v
Nginx + 后端验证 token/sign
          |
          v
Nginx 返回文件

如果用户没有生成 token/sign：
          |
          v
wget / curl 仍可直接请求原始 URL
          |
          v
Nginx + 后端判定为 unverified_slow
          |
          v
Nginx 低速返回文件
```

这样可以避免传统验证码方案的问题：

| 传统验证码 | 本方案 |
|---|---|
| 验证结果绑定浏览器会话 | 验证结果体现在 URL 中 |
| wget/curl 无法继承浏览器状态 | wget/curl 直接使用签名 URL |
| 需要 Cookie / Session | 不需要 Cookie / Session |
| 通常依赖动态页面 | 使用静态页面，且未验证请求可限速放行 |
| 后端需要暴露验证页面/API | 后端只暴露给 Nginx 内部调用 |

### 26.4 解决方案二：无外部工具优先，采用“未验证限速”策略

如果尽可能不提供额外 CLI 工具，那么必须承认一个现实约束：

```text
纯 wget/curl 本身不会执行 JS，也不会自动计算 PoW。
```

因此，如果用户既没有浏览器，也不安装额外工具，那么它无法主动生成 PoW。

在这个前提下，不应该把 PoW 设计成硬性门禁，否则无头环境会被彻底阻断。更合理的方式是：

```text
未验证请求仍允许下载，但降低速度或额度；
完成 PoW 的请求获得正常速度。
```

也就是说，PoW 从“准入门槛”变成“加速凭证”。

#### 26.4.1 下载分级

推荐将大文件下载分为三档：

| 档位 | 条件 | 行为 |
|---|---|---|
| 绿色档 | 不需要保护的小文件 / 包管理器元数据 | 直接全速放行 |
| 黄色档 | 大文件但无 token/sign，且风险不高 | 放行，但限速、限并发 |
| 蓝色档 | 大文件且 token/sign 验证通过 | 全速放行 |
| 红色档 | 明显异常请求或超过阈值 | 429 或 403 |

这样无头用户仍然可以使用：

```bash
wget https://mirrors.example.edu/ubuntu.iso
```

只是未验证情况下可能被限制为较低速度，例如：

```text
256 KB/s ~ 1 MB/s
```

普通用户如果只是偶尔下载一个 ISO，虽然慢一点，但不会被完全阻断。

盗刷者如果想大量刷流量，则会被限速显著提高成本。

#### 26.4.2 已验证链接作为加速通道

如果用户愿意通过浏览器生成 token/sign，则可以获得正常速度：

```text
https://mirrors.example.edu/ubuntu.iso?token=...&sign=...
```

此时后端返回：

```http
HTTP/1.1 200 OK
X-Pow-Decision: verified
X-Pow-Limit-Rate: 0
```

其中 `0` 表示不限速。

无 token/sign 时，后端可以返回：

```http
HTTP/1.1 200 OK
X-Pow-Decision: unverified_slow
X-Pow-Limit-Rate: 512k
```

Nginx 据此对真实文件下载限速。

#### 26.4.3 Nginx 动态限速示例

```nginx
location ~* \.(iso|img|qcow2|vmdk|vdi|ova|zip|7z|tar|tar\.gz|tar\.xz)$ {
    auth_request /_pow_auth;
    auth_request_set $pow_limit_rate $upstream_http_x_pow_limit_rate;
    auth_request_set $pow_decision $upstream_http_x_pow_decision;
    auth_request_set $pow_error $upstream_http_x_pow_error;

    limit_rate $pow_limit_rate;

    error_page 403 = @pow_forbidden;
    error_page 429 = @pow_rate_limited;

    try_files $uri =404;
}
```

后端决策：

| 后端判断 | HTTP 状态 | `X-Pow-Limit-Rate` | Nginx 行为 |
|---|---:|---|---|
| 小文件 / 不保护路径 | 200 | `0` | 全速 |
| 大文件，无 token，低风险 | 200 | `512k` | 限速放行 |
| 大文件，合法 token/sign | 200 | `0` | 全速 |
| 大文件，无 token，高风险 | 200 或 429 | `128k` 或拒绝 | 极低速或拒绝 |
| 非法 token/sign | 403 | - | 拒绝 |

#### 26.4.4 风险分级策略

未验证请求不直接拒绝，而是根据风险等级处理。

可使用以下信号：

1. 同一 IP 短时间大文件请求数；
2. 同一 IP 下载不同 ISO 的数量；
3. 同一 IP 的并发连接数；
4. 是否频繁请求 Range；
5. User-Agent 是否异常；
6. 是否来自已知异常网段；
7. 是否连续触发无 token 请求。

示例策略：

| 条件 | 行为 |
|---|---|
| 第一次无 token 下载大文件 | 中速放行 |
| 1 小时内第 2-3 个大文件 | 低速放行 |
| 1 小时内超过阈值 | 429 或极低速 |
| 合法 token/sign | 全速放行 |

这种策略的好处是：

1. 不需要 CLI；
2. 不强迫所有用户打开浏览器；
3. wget/curl 永远不会因为缺少 JS 能力而完全不可用；
4. 恶意刷流量者无法轻易获得高带宽；
5. PoW 成为“提速”手段，而不是“唯一通行证”。

#### 26.4.5 该方案的本质取舍

该方案不是彻底阻断盗刷，而是将目标调整为：

```text
正常用户可用，恶意流量变贵。
```

它牺牲了一部分强拦截能力，换取：

1. 更好的 wget/curl 兼容性；
2. 更低的用户理解成本；
3. 更小的外部工具依赖；
4. 更符合镜像站开放服务属性。

### 26.5 解决方案三：前端页面尽量静态化

为了降低动态页面和后端暴露带来的安全风险，前端签名生成页面应尽量是静态资源。

推荐：

```text
/static/pow/index.html
/static/pow/pow.js
/static/pow/worker.js
/.well-known/mirrors-pow-config.json
```

其中：

1. HTML 是静态文件；
2. JS 是静态文件；
3. PoW 在浏览器本地计算；
4. 配置通过静态 JSON 提供；
5. 不需要用户登录；
6. 不需要服务端 session；
7. 不需要公开的动态 challenge API。

静态配置示例：

```json
{
  "version": 1,
  "algorithm": "sha256",
  "salt": "2025-01-01-public-salt",
  "modes": {
    "ip_bound": {
      "enabled": true,
      "difficulty": 22,
      "ttl_seconds": 86400
    },
    "generic": {
      "enabled": true,
      "difficulty": 22,
      "ttl_seconds": 1800,
      "max_uses": 5
    }
  },
  "protected_extensions": [".iso", ".img", ".qcow2"]
}
```

这样，公网可访问的只是静态文件，不是敏感后端 API。

### 26.6 解决方案四：后端只作为 Nginx 内部鉴权服务

后端不提供公网签名生成接口。

后端只监听：

```text
127.0.0.1:8080
```

Nginx 配置：

```nginx
location = /_pow_auth {
    internal;
    proxy_pass http://127.0.0.1:8080/verify_pow;
}
```

外部用户不能直接访问：

```text
/verify_pow
```

这种方式可以显著降低攻击面。

安全边界变成：

| 模块 | 是否公网可访问 | 说明 |
|---|---|---|
| 大文件下载 URL | 是 | 静态资源，由 Nginx 服务 |
| PoW 静态页面 | 是 | 只包含 JS/HTML，无服务端状态 |
| `.well-known` 配置 | 是 | 公开配置，不包含密钥 |
| `/verify_pow` 后端接口 | 否 | 仅 Nginx 内部访问 |
| Redis / PostgreSQL | 否 | 仅后端访问 |

### 26.7 解决方案五：保留普通 URL 语义，避免 Cookie/Session

不要把验证结果放在 Cookie 或服务端 Session 中。

原因：

1. wget/curl 默认不继承浏览器 Cookie；
2. 用户复制 URL 到远程机器后 Cookie 失效；
3. Session 会引入后端状态管理；
4. Cookie 会让下载链路和浏览器强绑定；
5. 包管理器和下载器兼容性差。

本方案把验证结果放在 URL 参数中：

```text
?token=...&sign=...
```

这样 URL 本身就是授权凭证。

缺点是 URL 可能被转发或泄漏。

应对方式：

1. `generic` 模式短 TTL；
2. `generic` 模式限制使用次数；
3. `ip_bound` 模式绑定 IP；
4. token 绑定 path；
5. 后端限制最大 TTL；
6. 日志中不要完整打印 token/sign。

### 26.8 解决方案六：只保护真正高风险的大文件

不能全站启用 PoW。

应该只保护：

1. `.iso`；
2. `.img`；
3. `.qcow2`；
4. `.vmdk`；
5. `.ova`；
6. 大型压缩包；
7. 明确被盗刷的路径。

不应保护：

1. `Packages`；
2. `Release`；
3. `InRelease`；
4. `repomd.xml`；
5. 小文件；
6. 网页静态资源；
7. 包管理器元数据。

这样可以保证：

```text
apt / yum / pacman / zypper 等包管理器不受影响。
```

### 26.9 解决方案七：错误页与限速提示友好化

如果采用“未验证限速”策略，未携带 token/sign 的请求不一定进入 403 错误页，而是可能被低速放行。

只有以下情况才建议返回错误页：

1. token/sign 格式错误；
2. token/sign 被篡改；
3. token/sign 已过期；
4. 使用次数耗尽；
5. 请求风险过高；
6. 后端明确要求重新验证。

错误页不应强制推荐 CLI，而应优先推荐浏览器静态验证页面。

示例文案：

```text
该文件较大，为防止自动化盗刷，未验证下载会受到速度限制。

你可以继续使用当前链接低速下载。

如果希望恢复正常速度，请在浏览器中打开验证页面，生成带 token/sign 的下载链接：

https://mirrors.example.edu/static/pow/index.html?url=https%3A%2F%2Fmirrors.example.edu%2Fubuntu.iso

生成后，你可以把该链接复制到 wget 或 curl 中使用。
```

这样用户不安装任何外部工具，也能理解如何获得更好的下载体验。

### 26.10 推荐最终权衡方案

最终建议采用“两入口、两档下载、一验证”的方案。

#### 两个签名生成入口

| 入口 | 面向用户 | 是否需要额外工具 |
|---|---|---|
| 浏览器弹窗 | 普通用户 | 不需要 |
| 静态 PoW 页面 | 普通/进阶用户 | 不需要 |

CLI 工具可以作为未来可选增强，但不作为第一版必需能力。

#### 两档下载体验

| 请求类型 | 行为 |
|---|---|
| 无 token/sign | 不直接阻断，默认限速/限并发 |
| 有合法 token/sign | 全速放行 |

#### 一个验证入口

```text
Nginx internal /_pow_auth -> Echo /verify_pow
```

这个入口不公网暴露。

#### 一个下载入口

```text
普通静态文件 URL + token/sign query
```

也就是：

```text
https://mirrors.example.edu/file.iso?token=...&sign=...
```

用户最终仍然使用普通 URL 下载，wget/curl 不需要理解验证码，也不需要执行 JS。

### 26.11 权衡后的优缺点

优点：

1. wget/curl 不会因为没有浏览器或 CLI 而完全不可用；
2. 无 token/sign 时仍可低速下载；
3. 有 token/sign 时可全速下载；
4. 普通浏览器用户仍有图形化体验；
5. 不强依赖额外 CLI 工具；
6. 后端不需要暴露公网签发接口；
7. 下载仍由 Nginx 处理；
8. 动态后端攻击面较小；
9. 可以对通用链接限制次数；
10. 可以对绑定 IP 链接提供更长有效期。

缺点：

1. 未验证请求仍然可以低速下载，无法做到彻底阻断；
2. 恶意方可以通过大量 IP 聚合低速流量；
3. generic 链接泄漏后短时间内可被复用；
4. ip_bound 模式可能受 IP 变化影响；
5. PoW 只能提高成本，不能完全阻止高算力攻击者。

但相比传统验证码，这个方案更符合镜像站需求：

```text
不破坏 wget/curl，又能提高大文件盗刷成本。
```

## 27. 详细 Mermaid 流程图汇总

本节集中放置详细 Mermaid 流程图，便于后续写汇报 PPT、技术博客或答辩材料时直接复用。

### 27.1 总体架构流程图

```mermaid
graph TD
    User["用户\n浏览器 / wget / curl / aria2"]

    StaticPage["静态 PoW 页面\nHTML + JS + Web Worker\n可选，用于生成 token/sign"]

    Nginx["Nginx\n静态文件服务 + auth_request"]

    Auth["PoW 验证后端\nGolang + Echo\n/verify_pow"]

    Store[("PostgreSQL + Redis + 内存\n通用链接使用次数\n风险计数 / 限流状态")]

    Mirror["镜像文件目录 / 文件服务\nISO / IMG / QCOW2 / 大文件"]

    User -->|"可选：打开静态页面生成 token/sign"| StaticPage
    StaticPage -->|"本地计算 PoW\n生成带 token/sign 的 URL"| User

    User -->|"无 token/sign 请求大文件"| Nginx
    User -->|"携带 token/sign 请求大文件"| Nginx

    Nginx -->|"auth_request 内部子请求\nX-Original-URI\nX-Original-Args\nX-Real-IP"| Auth

    Auth -->|"查询/更新\n使用次数、风险计数"| Store
    Store -->|"返回计数/状态"| Auth

    Auth -->|"verified：200 + X-Pow-Limit-Rate: 0"| Nginx
    Auth -->|"unverified_slow：200 + X-Pow-Limit-Rate: 512k"| Nginx
    Auth -->|"deny/rate_limit：403/429"| Nginx

    Nginx -->|"全速读取文件"| Mirror
    Nginx -->|"限速读取文件"| Mirror
    Mirror -->|"文件数据流"| User
```

### 27.2 未验证请求限速下载时序图

该流程用于解决“不使用 CLI、不使用浏览器也要保证 wget/curl 可用”的场景。

```mermaid
sequenceDiagram
    actor User as 用户 / wget / curl
    participant Nginx as Nginx
    participant Auth as Echo PoW 后端
    participant Store as PostgreSQL + Redis
    participant FS as 文件服务

    User->>Nginx: GET /ubuntu.iso\n无 token/sign
    Nginx->>Auth: auth_request /verify_pow\nX-Original-URI=/ubuntu.iso\nX-Original-Args为空\nX-Real-IP=用户IP

    Auth->>Auth: 判断路径是否为受保护大文件
    Auth->>Auth: 未发现 token/sign
    Auth->>Store: 查询该 IP 的近期大文件请求次数/风险状态
    Store-->>Auth: 返回风险等级

    alt 低风险或普通用户
        Auth-->>Nginx: HTTP 200 OK\nX-Pow-Decision=unverified_slow\nX-Pow-Limit-Rate=512k
        Nginx->>FS: 按 limit_rate 读取文件
        FS-->>User: 低速返回文件数据流
    else 高风险或超过阈值
        Auth-->>Nginx: HTTP 429 Too Many Requests\nX-Pow-Error=rate_limited
        Nginx-->>User: 返回限流提示页
    end
```

### 27.3 浏览器生成 token/sign 后全速下载时序图

```mermaid
sequenceDiagram
    actor User as 用户
    participant Page as 静态 PoW 页面
    participant Worker as Web Worker
    participant Nginx as Nginx
    participant Auth as Echo PoW 后端
    participant Store as PostgreSQL + Redis
    participant FS as 文件服务

    User->>Page: 打开大文件下载页或 PoW 静态页面
    Page-->>User: 展示模式选择\nip_bound 长效 / generic 短效
    User->>Page: 选择模式并确认目标文件

    Page->>Worker: 发送 path、mode、timestamp、difficulty、salt

    loop PoW 计算
        Worker->>Worker: 枚举 cnt\n计算 SHA-256(canonical_string)
        Worker->>Worker: 检查前导零 bit 是否满足难度
    end

    Worker-->>Page: 返回 token + sign
    Page-->>User: 展示签名 URL\n/ubuntu.iso?token=...&sign=...

    User->>Nginx: GET /ubuntu.iso?token=...&sign=...
    Nginx->>Auth: auth_request /verify_pow\nX-Original-URI\nX-Original-Args\nX-Real-IP

    Auth->>Auth: 解析 token/sign
    Auth->>Auth: 校验 path、时间、难度、sign

    alt mode = generic
        Auth->>Store: 查询 sign 使用次数
        Store-->>Auth: 返回当前 uses
        Auth->>Store: uses + 1
    else mode = ip_bound
        Auth->>Auth: 校验 token.ip == X-Real-IP
    end

    Auth-->>Nginx: HTTP 200 OK\nX-Pow-Decision=verified\nX-Pow-Limit-Rate=0
    Nginx->>FS: 全速读取文件
    FS-->>User: 全速返回文件数据流
```

### 27.4 后端详细判定流程图

```mermaid
flowchart TD
    Start["收到 /verify_pow"] --> ReadHeaders["读取 Nginx Header\nX-Original-URI\nX-Original-Args\nX-Real-IP\nUser-Agent"]

    ReadHeaders --> CheckHeader{Header 是否完整?}
    CheckHeader -- 否 --> ErrHeader["500 missing_headers"]
    CheckHeader -- 是 --> Normalize["规范化 path / ip / args"]

    Normalize --> Protected{是否受保护路径?}
    Protected -- 否 --> AllowNormal["200 allow\nX-Pow-Decision=not_protected\nX-Pow-Limit-Rate=0"]

    Protected -- 是 --> Extract{是否存在 token 和 sign?}

    Extract -- 否 --> Risk["计算无 token 风险等级\nIP 频率 / 路径频率 / UA / Range"]
    Risk --> RiskLevel{风险等级}
    RiskLevel -- 低 --> SlowAllow["200 allow\nX-Pow-Decision=unverified_slow\nX-Pow-Limit-Rate=512k"]
    RiskLevel -- 中 --> VerySlowAllow["200 allow\nX-Pow-Decision=unverified_very_slow\nX-Pow-Limit-Rate=128k"]
    RiskLevel -- 高 --> RateLimit["429 rate_limited"]

    Extract -- 是 --> Decode["Base64URL 解码 token\n解析 JSON"]
    Decode --> TokenOK{token 格式合法?}
    TokenOK -- 否 --> DenyMalformed["403 malformed_token"]

    TokenOK -- 是 --> ModeCheck{mode 是否支持且启用?}
    ModeCheck -- 否 --> DenyMode["403 unsupported_mode / mode_disabled"]

    ModeCheck -- 是 --> PathCheck{token.path == X-Original-URI?}
    PathCheck -- 否 --> DenyPath["403 path_mismatch"]

    PathCheck -- 是 --> TimeCheck{ts/exp 是否有效?}
    TimeCheck -- 否 --> DenyTime["403 expired / ttl_too_long"]

    TimeCheck -- 是 --> DiffCheck{difficulty 是否在允许范围?}
    DiffCheck -- 否 --> DenyDiff["403 difficulty_too_low/high"]

    DiffCheck -- 是 --> Canonical["构造 canonical_string"]
    Canonical --> Hash["计算 SHA-256"]
    Hash --> SignCheck{计算结果是否等于 sign?}
    SignCheck -- 否 --> DenySign["403 sign_mismatch"]

    SignCheck -- 是 --> PowCheck{前导零 bit 是否满足?}
    PowCheck -- 否 --> DenyPow["403 difficulty_not_met"]

    PowCheck -- 是 --> ModeRoute{mode}

    ModeRoute -- ip_bound --> IPCheck{token.ip == X-Real-IP?}
    IPCheck -- 否 --> DenyIP["403 ip_mismatch"]
    IPCheck -- 是 --> AllowIP["200 verified\nX-Pow-Decision=ip_bound_valid\nX-Pow-Limit-Rate=0"]

    ModeRoute -- generic --> UseCheck["查询 sign 使用次数"]
    UseCheck --> UsedUp{uses < max_uses?}
    UsedUp -- 否 --> DenyUsed["403 used_up"]
    UsedUp -- 是 --> IncUse["递增 uses"]
    IncUse --> AllowGeneric["200 verified\nX-Pow-Decision=generic_valid\nX-Pow-Limit-Rate=0"]
```

### 27.5 下载决策状态图

```mermaid
stateDiagram-v2
    [*] --> RequestReceived: 收到大文件请求

    RequestReceived --> NotProtected: 非保护路径
    NotProtected --> FullSpeed: 全速放行

    RequestReceived --> Protected: 保护路径

    Protected --> NoToken: 无 token/sign
    NoToken --> LowRisk: 风险低
    NoToken --> MediumRisk: 风险中
    NoToken --> HighRisk: 风险高

    LowRisk --> SlowDownload: 限速下载 512k
    MediumRisk --> VerySlowDownload: 极低速下载 128k
    HighRisk --> Rejected: 429/403

    Protected --> HasToken: 有 token/sign
    HasToken --> InvalidToken: token/sign 无效
    InvalidToken --> Rejected: 403

    HasToken --> ValidPow: PoW 合法
    ValidPow --> IPBound: mode=ip_bound
    ValidPow --> Generic: mode=generic

    IPBound --> IPMismatch: IP 不匹配
    IPMismatch --> Rejected
    IPBound --> IPMatched: IP 匹配
    IPMatched --> FullSpeed

    Generic --> UsesExceeded: 使用次数耗尽
    UsesExceeded --> Rejected
    Generic --> UsesAvailable: 使用次数可用
    UsesAvailable --> FullSpeed

    SlowDownload --> [*]
    VerySlowDownload --> [*]
    FullSpeed --> [*]
    Rejected --> [*]
```

## 28. 总结

根据参考流程图，后端设计调整为以 `token + sign` 为核心协议，并明确支持两种下载模式：

1. **绑定 IP 长效模式 `ip_bound`**  
   适合用户在同一公网 IP 下下载。链接有效期较长，但不能跨 IP 使用。

2. **通用链接短效模式 `generic`**  
   适合用户复制到远程服务器、curl、wget 等无头环境下载。链接不绑定 IP，但必须短效，并通过 PostgreSQL / Redis / 内存记录使用次数。

最终后端采用：

```text
Golang + Echo + token/sign + PostgreSQL/Redis 使用次数记录 + Nginx auth_request
```

该方案兼顾了：

- 浏览器用户体验；
- curl/wget 兼容性；
- 尽量不依赖外部 CLI 工具；
- 未验证请求低速可用；
- 已验证请求全速下载；
- 大文件防盗刷；
- Nginx 静态文件高性能传输；
- 后端验证逻辑简单可靠；
- 后续扩展 Redis、Prometheus、动态难度的能力。
