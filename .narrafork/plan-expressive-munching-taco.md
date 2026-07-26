# mirrors-waf-backend 初始化实施计划

> 目标：按 `BACKEND_DESIGN.md` 初始化一个**成熟、可维护、可扩展**的 Go 后端工程。
> 不是"最小可用版本"——所有分层、接口、扩展点一次性落地，后续只填充实现。

---

## 0. 工程元信息

| 项 | 值 |
|---|---|
| 模块名 | `github.com/hust-open-atom-club/hustmirrors-waf-backend` |
| Go 版本 | 1.24.4 (`C:\Users\Ran\sdk\go1.24.4\bin\go.exe`) |
| 工作目录 | `D:\projects\hust\mirrors-waf-backend` |
| 模块根 | `backend/` 子目录（与设计文档第 15 章一致） |
| 构建 | `go build ./...`，`go vet ./...` 全通过 |
| 依赖策略 |Echo v4 / Viper / Zap / pgx/v5+sqlx / go-redis/v9 / goose/v3 / testify / prometheus client / x/time/rate。**不用 GORM、不用 wire**（第一版手动 DI，保留接口边界以便后续替换） |
| linter | golangci-lint 配置（`.golangci.yml`）启用 govet / staticcheck / ineffassign / unused / gocritic / gosec / revive |

---

## 1. 目录骨架（一次到位）

严格遵循设计文档第 15 章，但补齐工程化辅助文件：

```
mirrors-waf-backend/                       # 仓库根
├─ BACKEND_DESIGN.md                       # 已存在
├─ README.md                               # 新增：架构总览 + 启动说明 + 开发约定
├─ Makefile                                # 新增：build/test/lint/migrate/run
├─ .golangci.yml                           # 新增
├─ .gitignore                              # 新增
├─ .editorconfig                           # 新增
├─ backend/                                # Go 模块根
│  ├─ go.mod
│  ├─ go.sum
│  ├─ cmd/
│  │  └─ pow-auth/main.go                  # 唯一入口：加载配置 → 装配 → 启动
│  ├─ internal/
│  │  ├─ app/
│  │  │  ├─ app.go                         # Application 容器：持有所有组件引用
│  │  │  ├─ wire.go                        # buildEngine()/buildStorage() 等装配函数（手写）
│  │  │  └─ shutdown.go                    # 优雅退出协调器
│  │  ├─ config/
│  │  │  ├─ config.go                      # 顶层 Config 结构（对应 14.1 全部字段）
│  │  │  ├─ loader.go                      # Viper 加载 + 环境变量覆盖
│  │  │  ├─ validate.go                   # 启动时强校验（14.3 全部规则）
│  │  │  └─ defaults.go                   # 合理默认值
│  │  ├─ transport/echo/
│  │  │  ├─ server.go                      # echo.New + 生命周期 + TLS 可选
│  │  │  ├─ routes.go                      # 路由注册（/verify_pow / /healthz / /readyz / /admin/*）
│  │  │  ├─ handlers.go                    # VerifyPowHandler
│  │  │  ├─ admin_handlers.go             # 管理 API handler
│  │  │  ├─ middleware.go                # recover / request_id / structured log / realip
│  │  │  └─ response.go                   # writeAuthResult → X-Pow-* headers；admin 统一 JSON
│  │  ├─ auth/
│  │  │  ├─ service.go                    # Service.Verify(ctx, AuthRequest) (AuthResult, error)
│  │  │  ├─ request.go                    # AuthRequest
│  │  │  ├─ result.go                     # AuthResult / Decision 映射
│  │  │  └─ errors.go                     # typed error + Reason 字符串常量
│  │  ├─ pow/
│  │  │  ├─ token.go                      # TokenPayload + Base64URL 编解码
│  │  │  ├─ canonical.go                  # BuildCanonicalInput（9.4）
│  │  │  ├─ verify.go                     # ComputeSign + CompareSign + HasLeadingZeroBits
│  │  │  ├─ difficulty.go                 # 前导零 bit 校验工具
│  │  │  ├─ sign_id.go                    # ComputeSignID（13.3）
│  │  │  └─ salt.go                       # salt 允许列表校验
│  │  ├─ matcher/
│  │  │  ├─ matcher.go                    # Matcher interface { ShouldProtect(path) bool }
│  │  │  ├─ extension.go                  # 后缀匹配
│  │  │  ├─ regex.go                      # 正则匹配（预编译缓存）
│  │  │  └─ composite.go                  # protected ∩ ~excluded 的组合器
│  │  ├─ storage/
│  │  │  ├─ store.go                      # UsageStore + CounterStore 接口 + DTO
│  │  │  ├─ memory/
│  │  │  │  ├─ usage.go                   # 内存 UsageStore（sync.RWMutex + map）
│  │  │  │  └─ counter.go                 # 内存 CounterStore（滑动窗口）
│  │  │  ├─ postgres/
│  │  │  │  ├─ usage.go                   # pgx 实现，UPSERT 原子递增（13.6.2）
│  │  │  │  ├─ counter.go                 # PG 计数器（可选）
│  │  │  │  └─ client.go                  # 连接池配置
│  │  │  └─ redis/
│  │  │     ├─ usage.go                   # go-redis + Lua（13.5）
│  │  │     ├─ counter.go                 # 滑动窗口计数器
│  │  │     └─ lua.go                     # 内嵌 Lua 脚本
│  │  ├─ risk/
│  │  │  ├─ engine.go                     # Engine.Evaluate(ctx, *RequestContext) (Decision, error)
│  │  │  ├─ chain.go                      # Chain 顺序执行 + JUMP/RETURN 栈
│  │  │  ├─ rule.go                       # Rule 结构
│  │  │  ├─ matcher.go                    # Match 条件编译器（path_regex/ip_cidr/pow_status/counter…）
│  │  │  ├─ target.go                     # ACCEPT/REJECT/RATE_LIMIT/TOO_MANY/JUMP/RETURN/LOG/MARK
│  │  │  ├─ counter.go                    # CounterStore interface（与 storage.CounterStore 对齐）
│  │  │  ├─ decision.go                   # Decision 结构 + HTTP 映射
│  │  │  └─ config.go                     # YAML 风控配置结构 + 编译期校验（18.15）
│  │  ├─ admin/
│  │  │  ├─ service.go                    # 管理 API 业务编排（ping/info/validate/preview/reload）
│  │  │  ├─ dto.go                        # 通用响应 {ok,code,message,data,request_id}
│  │  │  ├─ audit.go                      # 审计日志接口（第一版写文件 + zap，预留 PG）
│  │  │  ├─ auth.go                       # token/basic/none 鉴权
│  │  │  └─ validator.go                 # 配置/规则校验器
│  │  ├─ logging/
│  │  │  ├─ logger.go                    # zap 构造 + IP 脱敏包装（19.3）
│  │  │  └─ context.go                   # 请求级 logger 注入 context
│  │  ├─ metrics/
│  │  │  └─ metrics.go                   # Prometheus：pow_verify_total / pow_latency / decision
│  │  ├─ clock/
│  │  │  └─ clock.go                     # Clock interface（real/fake），便于测试
│  │  └─ version/
│  │     └─ version.go                   # build info（git commit / build time），ldflags 注入
│  ├─ migrations/
│  │  └─ 001_init.sql                     # pow_usage + admin_audit_log + config_snapshot
│  ├─ configs/
│  │  ├─ config.example.yaml             # 照搬 14.1，默认 memory driver
│  │  └─ config.local.yaml               # 本地开发用，便于直接 `go run`
│  └─ testdata/
│     ├─ tokens/                          # 合法/非法 token 样例
│     └─ nginx/mirrors.conf               # 12.1 示例
└─ deploy/
   └─ nginx/mirrors-waf.conf              # 生产 Nginx 片段
```

---

## 2. 分层契约（不可违反）

```
transport/echo  →  auth / admin  →  pow / matcher / risk / storage
                                                    ↓
                                              config / logging / clock / metrics
```

- `transport/echo` 只做 HTTP 适配：解析 header → 构造 `AuthRequest` → 调 `auth.Service` → 写 `X-Pow-*` header。**不写业务**。
- `auth.Service` 是核心编排者，不依赖 Echo，不直接触碰底层存储，通过 `UsageStore`/`CounterStore`/`Engine` 接口操作。
- `pow` 是纯函数库，无外部依赖（除 crypto/sha256 + encoding）。
- `risk` 通过 `CounterStore` 接口访问计数器，不直接 import storage 包，避免循环。
- `storage` 各实现只依赖各自驱动 + 接口；`store.go` 是接口的权威定义点。
- 跨层传 error 用 `auth.errors` 中定义的 typed error（携带 Reason 常量），handler 统一翻译。

---

## 3. 核心数据结构（一次性定义，后续只填充方法）

照搬设计文档第 16 章 + 18.5 + 18.11：

```go
// internal/auth/request.go
type AuthRequest struct {
    OriginalURI, OriginalMethod, OriginalArgs string
    RealIP, ForwardedFor, UserAgent           string
}

// internal/auth/result.go
type AuthResult struct {
    Allowed     bool
    HTTPStatus  int
    Reason      string   // 取 errors.go 常量
    Mode        string
    SignID      string
    Uses, MaxUses int
    LimitRate   string   // 传给 Nginx 的 X-Pow-Limit-Rate
    ErrorHeader string
}

// internal/pow/token.go
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

// internal/risk/decision.go
type Decision struct {
    Target, Reason, Chain, RuleName, LimitRate string
    StatusCode int
    Marks []string
}

// internal/risk/engine.go
type RequestContext struct {
    Path, Method, Args, IP, UserAgent string
    HasToken, HasSign, IsProtected, IsRangeRequest bool
    PowStatus, PowMode, FileExt string
    RiskScore int
    Counters map[string]int64
}
```

---

## 4. 接口边界（扩展点）

这些接口一次性定义，所有实现（含空实现/占位）同时落地，便于后续替换：

```go
// internal/storage/store.go
type UsageStore interface {
    Consume(ctx context.Context, in ConsumeInput) (ConsumeResult, error)
    Get(ctx context.Context, id string) (*UsageRecord, error)
    CleanupExpired(ctx context.Context, beforeUnix int64) error
    Close() error
}

type CounterStore interface {
    Incr(ctx context.Context, name, key string, window time.Duration) (int64, error)
    Get(ctx context.Context, name, key string, window time.Duration) (int64, error)
    Close() error
}

// internal/matcher/matcher.go
type Matcher interface { ShouldProtect(path string) bool }

// internal/risk/engine.go
type Engine interface {
    Evaluate(ctx context.Context, req *RequestContext) (Decision, error)
}

// internal/clock/clock.go
type Clock interface {
    Now() time.Time
}

// internal/logging/logger.go
type Logger interface { /* zap 包装后的最小子集 */ }
```

> **为何一次定义全部接口**：设计文档第 18.16/18.17 明确要求"高级能力在架构上预留扩展点"。接口先行 = 后续接 GeoIP/ASN/ML 风险分/表达式 DSL 时不动核心代码。

---

## 5. 实施顺序（10 个阶段，每阶段独立可编译可测）

### 阶段 1：工程脚手架
- 初始化 `go.mod`（模块名 `github.com/hust-open-atom-club/hustmirrors-waf-backend`，go 1.24）；
- 创建目录骨架（第 1 节全部目录）；
- 写 `Makefile` / `.golangci.yml` / `.gitignore` / `.editorconfig`；
- 写 `backend/internal/version/version.go`（ldflags 占位）；
- 写 `backend/internal/clock/clock.go`（real + fake）。
- **验证**：`go build ./...` 通过（即使包是空的）。

### 阶段 2：基础设施层
- `config/`：完整 `Config` 结构（覆盖 14.1 全字段）+ Viper 加载 + env 覆盖（前缀 `MIRRORS_WAF_`，分隔符 `__`）+ `validate.go`（14.3 全部校验规则）+ `defaults.go`；
- `logging/`：zap 构造（JSON/console）+ `hashIP(ip, salt)` + context-aware logger；
- `metrics/`：prom registry + `pow_verify_total{result,reason,mode}` + `pow_verify_latency_seconds` + `decision_total{target}`。
- **验证**：单元测试 `config_test.go` 覆盖 14.3 校验规则。

### 阶段 3：领域核心层（pow + matcher）
- `pow/token.go`：Base64URL 编解码 + JSON 解析 + 字段强校验（8.4）；
- `pow/canonical.go`：`BuildCanonicalInput`（严格按 9.2/9.3，含空 `ip=` 行）；
- `pow/verify.go`：`ComputeSign = hex(sha256(canonical))` + `CompareSign`（EqualFold）+ `HasLeadingZeroBits`（覆盖 0/1/7/8/9/16/22 边界）；
- `pow/sign_id.go`：`ComputeSignID`（13.3）；
- `pow/salt.go`：当前 + 上一期 salt 校验；
- `matcher/`：`extension.go`（后缀表，大小写不敏感）+ `regex.go`（启动时预编译 + 缓存）+ `composite.go`（protected ∩ ¬excluded）。
- **验证**：单元测试覆盖 23.1 token/pow 模块全部用例。

### 阶段 4：存储抽象层 + 三实现
- `storage/store.go`：定义 `UsageStore`/`CounterStore`/DTO；
- `storage/memory/`：完整可用实现（map + RWMutex + 滑动窗口 counter）；
- `storage/postgres/`：pgx 连接池 + UPSERT 原子递增（13.6.2）+ cleanup；**本阶段先写代码骨架 + 迁移 SQL**，连接验证放手动测试；
- `storage/redis/`：go-redis + 内嵌 Lua（13.5）+ 滑动窗口；**代码完整**，本地无 Redis 时通过 build tag 或运行时配置跳过；
- `migrations/001_init.sql`：`pow_usage` + `admin_audit_log` + `config_snapshot`。
- **验证**：memory 实现完整单测；postgres/redis 编译通过 + 接口契约测试（用 interface mock）。

### 阶段 5：风控规则引擎（risk）
- `risk/config.go`：YAML 结构（chains/counters/policy/rules/match）+ 启动校验（18.15：chain 唯一、JUMP 存在、无环、正则可编译、limit_rate 格式、counter 名存在、policy 存在、target 合法）；
- `risk/matcher.go`：`Match` 编译器（path_regex/path_prefix/extension_in/method_in/ip_cidr_in/user_agent_regex/pow_status/pow_status_in/pow_mode/is_protected/is_range_request/counter/risk_score_gte）；
- `risk/target.go`：Target 常量 + 终止/非终止判定；
- `risk/chain.go`：Chain 顺序执行 + JUMP 栈 + RETURN + policy fallback；
- `risk/engine.go`：`Evaluate` 编排，输出 `Decision`；
- `risk/decision.go`：HTTP 映射表（18.11）。
- **验证**：表驱动单测覆盖 18.9 配置示例的各分支。

### 阶段 6：业务编排层（auth + admin）
- `auth/service.go`：实现设计文档 10.2 伪代码的完整 Go 版本：
  - 路径检查 → token/sign 提取 → decode → validate → path match → time → difficulty → canonical → sha256 → compare → leading-zero → mode 分支（ip_bound 比对 IP / generic 调 UsageStore.Consume）；
  - 整合 `risk.Engine`：在基础解析后构造 `RequestContext`，若 Decision 是 `REQUIRE_POW` 才执行完整 PoW；
  - dry_run / bypass_all 短路（21 / 20.7）；
  - 全程用 `clock.Clock` 取时间，便于测试；
- `auth/errors.go`：31 个 Reason 常量（17 章）+ typed error；
- `admin/service.go`：第一版实现 18.18.9 的 5 个接口（system.ping / system.info / config.validate / rule.preview / rule.reload）；
- `admin/dto.go`：统一响应 `{ok,code,message,data,request_id}`；
- `admin/audit.go`：审计日志接口 + zap 文件实现（预留 PG 实现）；
- `admin/auth.go`：token/basic/none 三种鉴权 + allow_cidrs；
- `admin/validator.go`：复用 config.validate + risk 配置校验。
- **验证**：`auth_test.go` 覆盖 23.1 auth 模块 + 23.2 集成测试场景（用 memory store + fake clock）。

### 阶段 7：传输层（echo）
- `server.go`：echo.New + 中间件链 + ServerTimeout + graceful shutdown；
- `middleware.go`：recover + request_id + structured access log + realip（解析 X-Real-IP/X-Forwarded-For）+ admin auth + admin cidr guard；
- `routes.go`：`GET /verify_pow`、`GET /healthz`、`GET /readyz`、`POST /admin/api/*`；
- `handlers.go`：`VerifyPowHandler` 读 header → 构造 `AuthRequest` → 调 `auth.Service` → 按 `AuthResult` 写 `X-Pow-Result/Reason/Mode/Uses/Max-Uses/Limit-Rate/Error/Decision` + 状态码；
- `admin_handlers.go`：5 个 admin 接口 handler；
- `response.go`：`writeAuthResult`（header-only，无 body，符合 auth_request 语义）+ `writeAdminJSON`。
- **验证**：用 `httptest` 起一个完整 server，跑 23.2 全部集成测试场景。

### 阶段 8：装配与启动
- `app/app.go`：`Application` 结构持有 echo.Server + auth.Service + stores + engine + logger + metrics；
- `app/wire.go`：`Build(cfg) (*Application, error)` 手动装配：
  - 按 `storage.driver` 选 memory/postgres/redis；
  - 按 `risk_control.enabled` 决定是否装配 `risk.Engine`（否则用 no-op engine）；
  - 按 `admin.enabled` 决定是否注册 admin 路由；
  - 注入 clock/logger/metrics；
- `app/shutdown.go`：捕获 SIGINT/SIGTERM，先停 echo 再关 stores，超时强制退出；
- `cmd/pow-auth/main.go`：`func main` 仅加载配置 → `app.Build` → `Run` → 处理退出码。
- **验证**：本地 `make run` 能启动，`curl /healthz` 返回 ok。

### 阶段 9：配置样例 + 迁移 + Nginx 示例
- `configs/config.example.yaml`：照搬 14.1，`storage.driver: memory`；
- `configs/config.local.yaml`：本地开发用，全部默认值；
- `migrations/001_init.sql`：完整建表 + 索引；
- `deploy/nginx/mirrors-waf.conf`：12.1 示例 + 动态限速（18.14）；
- `backend/testdata/tokens/`：合法/非法 token 样例集（供单测 + 集成测试复用）。

### 阶段 10：README + 文档 + CI 雏形
- `README.md`：架构图（mermaid）+ 目录说明 + 启动步骤 + 配置项速查 + 开发约定 + 测试命令；
- `.github/workflows/ci.yml`（可选，先写本地 Makefile）：`make test` + `make lint` + `make build`；
- `Makefile` 目标：`build / run / test / test-race / lint / vet / migrate-up / migrate-down / fmt / tidy`。

---

## 6. 设计文档对齐检查表（交付时逐项打勾）

- [ ] 第 4 章技术栈全部依赖已用；
- [ ] 第 7-9 章 token/sign/canonical 字段顺序与示例逐字一致；
- [ ] 第 10.2 节伪代码在 `auth/service.go` 完整体现；
- [ ] 第 11 章 HTTP API 与响应头全部实现；
- [ ] 第 12 章 Nginx 必传 header 全部解析；
- [ ] 第 13 章存储接口 + memory/pg/redis 三实现 + sign_id 算法一致；
- [ ] 第 14 章配置结构 + 全部校验规则（14.3）；
- [ ] 第 15 章目录结构一致；
- [ ] 第 16 章数据结构字段一致；
- [ ] 第 17 章 31 个 Reason 全部有常量并能在响应头中出现；
- [ ] 第 18 章风控规则链（Chain/Rule/Match/Target/Decision）+ 18.15 校验；
- [ ] 第 18.18 章 admin API 第一版 5 接口；
- [ ] 第 19 章 zap 结构化日志 + IP 脱敏；
- [ ] 第 20 章 fail-close + bypass_all；
- [ ] 第 21 章 dry_run；
- [ ] 第 22 章 HEAD/Range 行为（HEAD 不计数，Range 计数）；
- [ ] 第 23 章测试用例在单测/集成测试中覆盖；
- [ ] 第 24 章里程碑 1 全部、2 大部分、3 预留接口。

---

## 7. 工程化附加项（提升可维护性）

1. **build tag 隔离重型依赖**：`postgres`/`redis` 实现用 `//go:build !no_external_storage` 标签，方便纯内存构建；
2. **context 贯穿**：所有 Store/Engine 方法第一参数 `ctx context.Context`，下游超时可级联；
3. **错误分类**：`auth.errors` 用 `errors.Is` 可判断是否可重试、是否应 fail-close；
4. **观测性**：每个 `/verify_pow` 请求有 `request_id`，日志 + metrics 全部带此 ID；
5. **配置热加载预留**：`admin/api/rule.reload` 接口已预留，底层 `Engine` 设计为可原子替换（`atomic.Pointer[Engine]`）；
6. **可测试性**：所有外部依赖（时钟、随机、存储、HTTP）走接口，单测全用 fake；
7. **安全性**：默认 fail-close；`bypass_all` 需显式配置；admin 默认只监听 127.0.0.1 且鉴权非 none；
8. **lint 严格度**：gosec + revive 默认启用，禁止 `panic` in library、禁止 `fmt.Println` in non-main。

---

## 8. 风险与对策

| 风险 | 对策 |
|---|---|
| Go 不在 PATH | 在 Makefile 和 README 中显式使用 `C:\Users\Ran\sdk\go1.24.4\bin\go.exe`，或建议用户加 PATH |
| Windows + Git Bash 路径转换问题 | Makefile 用正斜杠；避免 cmd 内建命令；脚本用 `.sh` |
| pgx/redis 本地无服务 | 第一版默认 memory；postgres/redis 代码完整但通过 config 切换，CI 不强依赖 |
| 风控规则链复杂度 | 第一版实现 18.16 必须子集，DSL/GeoIP/ASN/ML 在接口层预留 |
| 配置校验遗漏 | 14.3 + 18.15 逐条写测试，启动时 fail-fast |

---

## 9. 交付标志

- `make build` 通过；`make test` 通过；`make lint` 无 error；
- `make run` 可启动，`curl 127.0.0.1:8080/healthz` 返回 200；
- `curl -H "X-Original-URI: /ubuntu.iso" -H "X-Real-IP: 1.2.3.4" 127.0.0.1:8080/verify_pow` 返回 403 + `X-Pow-Error: missing_token_or_sign`；
- 全部 31 个 Reason 常量在代码中存在；
- 风控规则链可加载 18.9 示例配置并产出正确 Decision；
- admin API 5 接口可用（需 token）。

---
