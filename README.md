# Garmr

**English** | [简体中文](README.zh-CN.md)

<img src="docs/garmr.svg" width="96" alt="Garmr" align="right" />

> Anti-abuse gateway for large mirror downloads: unverified requests get
> rate-limited, one PoW buys full speed.
> Runs as an Nginx `auth_request` backend; the token travels in the URL, so
> wget and curl work out of the box — no cookies, no sessions.

[![Go](https://img.shields.io/badge/Go-1.25.7+-00ADD8)](https://go.dev/)
[![Echo](https://img.shields.io/badge/Echo-v4-00ADD8)](https://echo.labstack.com/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## The name

Garmr is the blood-stained hound that guards the gate of Hel in Norse
mythology. A gatekeeper in myth, a gatekeeper here: unverified requests
pass slowly, PoW-verified downloads pass at full speed.

The name nods to [cerberus](https://github.com/sjtug/cerberus) — both are
watchdogs at the gate; the Greek one is Cerberus, the Norse one is Garmr.

## How it works

### Architecture

```mermaid
graph TD
    Browser["Browser / wget / curl"]
    Nginx["Nginx<br/>auth_request"]
    Backend["Garmr<br/>/verify_pow"]
    Storage[("PostgreSQL / Redis / memory<br/>usage counts + risk counters")]
    FS["File service<br/>ISO / large files"]

    Browser -->|"GET /ubuntu.iso<br/>?token=... &sign=..."| Nginx
    Nginx -->|"internal subrequest<br/>X-Original-URI, X-Original-Args,<br/>X-Real-IP"| Backend
    Backend -->|"usage read/write<br/>(generic mode)"| Storage
    Backend -->|"200 + X-Pow-Limit-Rate<br/>or 403 / 429"| Nginx
    Nginx -->|"full speed or rate-limited"| FS
    FS -->|"file stream"| Browser
```

### Verification flow

```mermaid
sequenceDiagram
    actor User
    participant FE as PoW page
    participant Nginx as Nginx
    participant Auth as Garmr
    participant Store as PostgreSQL / Redis
    participant FS as File service

    User->>FE: pick path + mode
    Note over FE: build token (path/mode/exp/difficulty/salt)<br/>enumerate cnt over SHA-256(canonical)<br/>until the hash has d leading zero bits

    loop PoW search (Web Worker)
        FE->>FE: sha256(canonical + cnt)
    end

    FE-->>User: URL with<br/>?token=base64(payload) &sign=hex(hash)

    User->>Nginx: GET /ubuntu.iso?token=... &sign=...
    Nginx->>Auth: auth_request /verify_pow<br/>X-Original-URI, X-Original-Args, X-Real-IP

    Auth->>Auth: 1. normalize path, protected?
    Auth->>Auth: 2. parse token, check fields<br/>(version/mode/algorithm/path/salt)
    Auth->>Auth: 3. token.path == request path?
    Auth->>Auth: 4. not expired? TTL within limits?
    Auth->>Auth: 5. recomputed SHA-256 == sign?
    Auth->>Auth: 6. hash meets leading-zero difficulty?

    alt mode = generic
        Auth->>Store: atomic increment of uses
        Store-->>Auth: current uses
        Auth->>Auth: 7. uses <= max_uses?
    else mode = ip_bound
        Auth->>Auth: 7. token.ip == request IP?
    end

    alt all checks pass
        Auth-->>Nginx: 200 + X-Pow-Decision: verified<br/>X-Pow-Limit-Rate: 0
        Nginx->>FS: forward at full speed
        FS-->>User: file stream
    else no token, low risk
        Auth-->>Nginx: 200 + X-Pow-Decision: unverified_slow<br/>X-Pow-Limit-Rate: 512k
        Nginx->>FS: forward rate-limited
        FS-->>User: rate-limited stream
    else verification failed
        Auth-->>Nginx: 403 + X-Pow-Error
        Nginx-->>User: error page
    end
```

- **No token**: large files are rate-limited (512k/s by default); small files
  and package-manager metadata pass at full speed
- **Valid token**: full-speed download after PoW verification
- **Invalid token**: 403

The proof travels in URL parameters (`?token=...` and `sign=...`); nothing
depends on cookies or sessions, so wget/curl work as-is.

### Risk-control rule chains

With `risk_control.enabled=true`, every request first traverses an
iptables-style rule chain before PoW verification is considered. The entry
chain is `INPUT`; supported targets are `ACCEPT` / `REJECT` / `RATE_LIMIT` /
`TOO_MANY` / `REQUIRE_POW` / `JUMP` / `LOG` / `MARK`.

`pow_status` values seen by rules:

| Value | Meaning |
|---|---|
| `missing` | no token provided |
| `valid` | token is well-formed and passed every check |
| `invalid` | bad signature, difficulty not met, path mismatch, TTL over `max_ttl_seconds`, ... |
| `expired` | past its expiry |
| `mode_disabled` | token itself is fine, but its mode is switched off with `enabled: false` |
| `unverifiable` | token itself is fine, but **cannot be checked** — today that means an `ip_bound` token with `X-Real-IP` missing |

The last three are not forgeries, but they **must not be treated as passes**;
rules have to reject them explicitly (the example config does).

> `pow_status` shares its verification code with the PoW-only path: a token
> the PoW-only path would reject never classifies as `valid` here either.

Denied-by-risk responses carry `X-Pow-Trace`, a comma-separated list of
`chain:rule` with `>` marking a JUMP:

```
X-Pow-Trace: INPUT:missing-pow>RISK_CHECK,RISK_CHECK:too-many-1h
```

Only matched rules are listed; long traces are truncated. The full trace
(including non-matches) comes from `garmr rule preview`.

> `generic` mode's `max_uses` is charged on every allow path
> (`ACCEPT` / `RATE_LIMIT` / `REQUIRE_POW`).
>
> `risk_control.pending` caps concurrent protected auth requests per IP;
> exceeding `max_per_ip` returns 429 and blocks the IP for `block_ttl`.
> The state is per-process; replicas do not share it.

## Quick start

### Build

```bash
make build
# binary: bin/server
```

### Run (development)

```bash
./bin/server --config configs/config.example.yaml
```

### Health checks

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok"}

curl http://127.0.0.1:8080/readyz
# {"status":"ok","storage":"ok"}
```

### Try verification

```bash
# unprotected path: 200
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /index.html" \
  -H "X-Real-IP: 1.2.3.4"
# X-Pow-Reason: not_protected

# protected path, no token: rate-limited
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /ubuntu.iso" \
  -H "X-Real-IP: 1.2.3.4"
# HTTP/1.1 200
# X-Pow-Decision: unverified_slow
# X-Pow-Limit-Rate: 512k

# invalid token: 403
curl -i http://127.0.0.1:8080/verify_pow \
  -H "X-Original-URI: /ubuntu.iso" \
  -H "X-Original-Args: token=invalid&sign=0000...0000" \
  -H "X-Real-IP: 1.2.3.4"
# X-Pow-Error: malformed_token
```

`config.dev.yaml` disables risk control (`risk_control.enabled=false`): a
protected path without a token is denied outright instead of rate-limited.

## Nginx integration

Full example in [`deploy/nginx/mirrors-waf.conf`](deploy/nginx/mirrors-waf.conf);
the core parts:

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

## Management CLI (garmr)

Configuration and rule inspection are handled by a local CLI; the service
does not need to be running:

```bash
garmr -config /etc/mirrors-waf/config.yaml config show   # view config (secrets redacted)
garmr config edit                                        # $EDITOR -> validate -> diff -> confirm -> write
garmr config validate candidate.yaml                     # validate a candidate file
garmr config diff candidate.yaml                         # diff against the active config
garmr config history                                     # revision log
garmr config rollback 3                                  # restore revision 3
garmr rule list                                          # risk chains and rules
garmr rule preview -path /ubuntu.iso -pow missing        # evaluate a hypothetical request
```

`config edit` flow: on save it validates the structure (on failure you drop
back into the editor) → merges secret placeholders → shows a
danger-classified diff (`normal` / `dangerous` / `critical`) → dangerous
changes require the confirmation phrase and a reason → atomically writes the
file and records history. A restart applies the change.

## Minting PoW download links

The backend only verifies; it never issues tokens. Example script:

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

## Configuration

Full field reference in [`configs/config.example.yaml`](configs/config.example.yaml).

| Field | Default | Description |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | listen address |
| `pow.enabled` | `true` | master PoW switch; `false` skips token parsing and verification entirely, leaving decisions to the risk chains |
| `pow.dry_run` | `false` | record but allow |
| `pow.bypass_all` | `false` | emergency bypass of PoW and the normal risk chains |
| `pow.algorithm` | `sha256` | only `sha256` is implemented; anything else fails at startup |
| `pow.modes.ip_bound` | enabled, d=22, ttl=24h | IP-bound long-lived mode, unmetered |
| `pow.modes.generic` | enabled, d=22, ttl=30m, max_uses=5 | short-lived mode metered by `max_uses` |
| `storage.driver` | `memory` | `memory` / `postgres` / `redis` |
| `storage.counter_driver` | `memory` | `memory` / `redis` |
| `risk_control.enabled` | `true` | risk rule chains |
| `risk_control.pending.enabled` | `true` | per-IP concurrency limit with temporary blocks |
| `risk_control.pending.max_per_ip` | `128` | concurrent protected auth requests per IP |
| `risk_control.pending.block_ttl` | `1h` | block duration once the pending limit is exceeded |
| `cleanup.enabled` | `true` | expired-record collection |
| `logging.log_access` | `true` | log allow decisions |
| `logging.log_denied` | `true` | log deny decisions |

> `pow.enabled=false` only skips PoW verification; risk rules still run.
> `bypass_all=true` skips PoW and the normal risk chains.

> Configuration management runs locally through the `garmr` CLI (above);
> history lives next to the config file in `.mirrors-waf-history/`.
> Apply/rollback only write the file and need a restart; secrets appear as
> `${SECRET:KEEP}` placeholders.

> `logging.log_*` affects logs only, never metrics; 5xx is always logged.

> These fields are rejected at startup rather than silently ignored:
> `pow.modes.*.count_usage` (use `max_uses`),
> `risk_control.chains.*.rules[].match.risk_score_gte` (no component produces
> a risk score).

Environment overrides (prefix `MIRRORS_WAF_`, separator `__`):

```bash
MIRRORS_WAF_SERVER__LISTEN=127.0.0.1:8080
MIRRORS_WAF_POW__DRY_RUN=true
MIRRORS_WAF_STORAGE__DRIVER=postgres
```

## Layout

```
├── cmd/server/               # service entry point
├── cmd/garmr/                # local management CLI
├── internal/
│   ├── app/                  # assembly and startup
│   ├── auth/                 # PoW verification orchestration
│   ├── pow/                  # token / canonical / sign / difficulty
│   ├── matcher/             # path normalization + protection rules
│   ├── storage/             # usage: memory/postgres/redis, counter: memory/redis
│   ├── risk/                # iptables-style rule chains
│   ├── transport/echo/      # HTTP layer
│   ├── configctl/            # CLI config workflow (diff/danger/secret merge)
│   ├── config/              # config + validation
│   ├── configstore/         # history dir, atomic writes, rollback
│   ├── logging/             # zap wrapper
│   └── metrics/             # Prometheus
├── configs/                  # example configs
├── migrations/               # PostgreSQL DDL
└── deploy/
    ├── nginx/               # Nginx integration example
    ├── systemd/             # systemd unit
    └── observability/       # alerts + Grafana
```

## Deployment

### systemd

```bash
# Prerequisite: the unit runs as User=mirrors-waf and needs /var/lib/mirrors-waf
# (full checklist in deploy/DEPLOY.md)
sudo useradd -r -s /usr/sbin/nologin mirrors-waf
sudo mkdir -p /etc/mirrors-waf /var/lib/mirrors-waf
sudo chown mirrors-waf:mirrors-waf /var/lib/mirrors-waf

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

## Development

```bash
make build          # build the server
make build-cli      # build the garmr CLI
make test           # unit tests
make test-race      # race detector (needs CGO; gcc on Windows)
make coverage       # coverage summary
make lint           # golangci-lint (falls back to go vet)

# PostgreSQL integration tests (own schema; other tables untouched)
POSTGRES_TEST_DSN='postgres://user:pass@127.0.0.1:5432/mirrors_pow?sslmode=disable' make test-postgres
go test -tags=benchmark -bench=. ./internal/app/...  # benchmarks
```

`make coverage` uses `-coverpkg=./...` so all production code counts.
PostgreSQL integration tests are skipped unless `POSTGRES_TEST_DSN` is set.

Baseline (i7-14650HX, in-memory storage):

| Scenario | QPS |
|---|---|
| unprotected path | 209k |
| protected path, no token | 114k |
| invalid token | 98k |

## License

[MIT](LICENSE)
