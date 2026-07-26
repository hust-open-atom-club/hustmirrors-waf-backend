// pow.js — main page logic for PoW link generation.
//
// Flow:
//   1. Load config from config.json
//   2. User picks path + mode
//   3. Build canonical string with a placeholder for cnt
//   4. Worker brute-forces cnt until sha256(canonical) meets difficulty
//   5. Assemble token (base64url of JSON payload) + sign (hex of hash)
//   6. Show download URL

let config = null;
let selectedMode = "generic";
let worker = null;

async function loadConfig() {
    const resp = await fetch("config.json");
    config = await resp.json();
}

function selectMode(mode) {
    selectedMode = mode;
    document.querySelectorAll(".mode-option").forEach(el => {
        el.classList.toggle("active", el.dataset.mode === mode);
    });
}

function buildPayload(path, mode) {
    const modeConfig = config.modes[mode];
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        v: 1,
        mode: mode,
        alg: "sha256",
        path: path,
        ts: now,
        exp: now + modeConfig.ttl_seconds,
        d: modeConfig.difficulty,
        cnt: "",
        salt: config.salt,
    };
    if (mode === "ip_bound") {
        payload.ip = "";
        // IP is filled by user or detected; left empty here means the
        // server's require_ip check will reject. We ask the user to
        // confirm their IP below.
    }
    return payload;
}

// Canonical string template — must match the backend's BuildCanonicalInput
// exactly. The cnt field is a placeholder replaced by the worker.
function canonicalTemplate(payload) {
    let ip = "";
    if (payload.mode === "ip_bound") {
        ip = payload.ip;
    }
    return (
        "mirrors-pow-v1\n" +
        "mode=" + payload.mode + "\n" +
        "ip=" + ip + "\n" +
        "path=" + payload.path + "\n" +
        "ts=" + payload.ts + "\n" +
        "exp=" + payload.exp + "\n" +
        "difficulty=" + payload.d + "\n" +
        "cnt=__CNT__\n" +
        "salt=" + payload.salt + "\n"
    );
}

async function generate() {
    const path = document.getElementById("path").value.trim();
    if (!path || !path.startsWith("/")) {
        showError("请输入有效的下载路径（以 / 开头）");
        return;
    }

    const modeConfig = config.modes[selectedMode];
    if (!modeConfig || !modeConfig.enabled) {
        showError("模式未启用");
        return;
    }

    let payload = buildPayload(path, selectedMode);

    // For ip_bound mode the token embeds the client's public IP, and the
    // backend denies the request unless it matches the IP it observes. So
    // we ask the backend itself rather than a third-party lookup, which
    // could report a different address (dual-stack, alternate egress) and
    // produce an ip_mismatch that is hard to diagnose.
    if (selectedMode === "ip_bound") {
        try {
            payload.ip = await fetchUserIP();
        } catch (e) {
            // A 500 means the server has no X-Real-IP for us. Typing an
            // address by hand cannot help: /verify_pow reads the same
            // header and will reject whatever we mint. Say so instead of
            // sending the user round a loop that always fails.
            if (e && e.serverMisconfigured) {
                showError(
                    "服务端未收到 X-Real-IP，ip_bound 模式当前不可用。" +
                    "这是站点代理配置问题，请联系管理员；你可以先改用 generic 模式。"
                );
                return;
            }
            const ip = prompt("无法自动获取公网 IP，请手动输入你的公网 IP：");
            if (!ip) {
                showError("ip_bound 模式需要公网 IP");
                return;
            }
            payload.ip = ip;
        }
    }

    document.getElementById("error").textContent = "";
    document.getElementById("generate").disabled = true;
    document.getElementById("progress").style.display = "block";
    document.getElementById("result").style.display = "none";

    const canonical = canonicalTemplate(payload);
    const difficulty = payload.d;

    // Spawn worker
    if (worker) worker.terminate();
    worker = new Worker("pow-worker.js");

    worker.onmessage = function (e) {
        const msg = e.data;
        if (msg.type === "progress") {
            updateProgress(msg.attempts);
        } else if (msg.type === "found") {
            payload.cnt = msg.counter;
            const sign = msg.sign;
            const token = encodeToken(payload);
            showResult(path, token, sign, payload, msg.attempts);
            worker.terminate();
            worker = null;
            document.getElementById("generate").disabled = false;
            document.getElementById("progress").style.display = "none";
        }
    };

    worker.postMessage({ type: "start", payload: { canonical, difficulty } });
}

function updateProgress(attempts) {
    document.getElementById("attempts").textContent = attempts;
    // Difficulty N means ~2^N expected attempts; use that as denominator
    const difficulty = config.modes[selectedMode].difficulty;
    const expected = Math.pow(2, difficulty);
    const pct = Math.min(95, (attempts / expected) * 100);
    document.getElementById("progress-fill").style.width = pct + "%";
}

function encodeToken(payload) {
    const json = JSON.stringify(payload);
    // base64url without padding
    const b64 = btoa(json).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return b64;
}

function showResult(path, token, sign, payload, attempts) {
    const base = window.location.origin;
    const url = base + path + "?token=" + token + "&sign=" + sign;
    document.getElementById("download-url").value = url;
    const meta = document.getElementById("meta");
    const expiry = new Date(payload.exp * 1000).toLocaleString();
    let info = "模式: " + payload.mode + " | 过期: " + expiry;
    if (payload.mode === "generic") {
        info += " | 最多下载 " + config.modes.generic.max_uses + " 次";
    } else if (payload.mode === "ip_bound") {
        info += " | 绑定 IP: " + payload.ip;
    }
    info += " | PoW 耗时 " + attempts + " 次尝试";
    meta.textContent = info;
    document.getElementById("result").style.display = "block";
}

function copyUrl() {
    const url = document.getElementById("download-url").value;
    navigator.clipboard.writeText(url).then(() => {
        const btn = document.querySelector(".copy-btn");
        const orig = btn.textContent;
        btn.textContent = "已复制";
        setTimeout(() => { btn.textContent = orig; }, 1500);
    });
}

// fetchUserIP asks the backend what IP it sees this client as. The answer
// must come from the same header /verify_pow reads, which is why this is
// not a third-party service.
//
// A 500 carrying missing_real_ip means the proxy is not forwarding
// X-Real-IP at all. That is flagged on the error so the caller can tell it
// apart from a transient network failure: retrying or entering an address
// manually cannot fix it.
//
// whoami_url is overridable in config.json for deployments where the PoW
// page is served from a different origin than the API.
async function fetchUserIP() {
    const url = (config && config.whoami_url) || "/whoami";
    const resp = await fetch(url, { cache: "no-store" });
    if (!resp.ok) {
        const err = new Error("whoami failed: " + resp.status);
        if (resp.status === 500) {
            const body = await resp.json().catch(() => ({}));
            err.serverMisconfigured = body.error === "missing_real_ip";
        }
        throw err;
    }
    const data = await resp.json();
    if (!data.ip) {
        throw new Error("whoami returned no ip");
    }
    return data.ip.trim();
}

function showError(msg) {
    document.getElementById("error").textContent = msg;
}

// Init
loadConfig().catch(() => showError("无法加载 config.json"));
