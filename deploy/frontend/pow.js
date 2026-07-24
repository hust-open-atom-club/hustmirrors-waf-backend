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

    // For ip_bound mode, we need the user's public IP. We fetch it from
    // a public service; if that fails, ask the user to enter it.
    if (selectedMode === "ip_bound") {
        try {
            const ip = await fetchUserIP();
            payload.ip = ip;
        } catch (e) {
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

async function fetchUserIP() {
    const resp = await fetch("https://api.ipify.org?format=text");
    return (await resp.text()).trim();
}

function showError(msg) {
    document.getElementById("error").textContent = msg;
}

// Init
loadConfig().catch(() => showError("无法加载 config.json"));
