// pow-worker.js — Web Worker that brute-forces the PoW nonce.
//
// Messages in:
//   { type: "start", payload: {canonical, difficulty} }
//   { type: "cancel" }
// Messages out:
//   { type: "progress", attempts: number }
//   { type: "found", counter: string, sign: string, attempts: number }
//   { type: "done", cancelled: true }
//   { type: "error", message: string }
//
// Uses SubtleCrypto rather than a CDN-hosted sha256. Pulling the hash
// implementation from a third party means whoever controls that origin
// controls every token this page mints — and it was loaded without SRI,
// so a compromised or hijacked CDN would go unnoticed. SubtleCrypto is
// available in every browser that supports Workers, needs no network, and
// runs natively.
//
// It requires a secure context (https or localhost). That is not a new
// constraint in practice, but it is now reported instead of silently
// failing.

let running = false;

self.onmessage = function (e) {
    const msg = e.data;
    if (msg.type === "start") {
        running = true;
        solve(msg.payload.canonical, msg.payload.difficulty).catch(function (err) {
            self.postMessage({ type: "error", message: String(err && err.message || err) });
        });
    } else if (msg.type === "cancel") {
        running = false;
    }
};

const encoder = new TextEncoder();

async function sha256Bytes(str) {
    const buf = await crypto.subtle.digest("SHA-256", encoder.encode(str));
    return new Uint8Array(buf);
}

function toHex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
        out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
}

// Mirrors the backend's HasLeadingZeroBits exactly. An earlier version
// short-circuited on hash[0] !== 0, which silently rejected valid
// solutions whenever difficulty < 8.
function hasLeadingZeroBits(hash, n) {
    if (n <= 0) return true;
    if (n > hash.length * 8) return false;
    const fullBytes = Math.floor(n / 8);
    const remBits = n % 8;
    for (let i = 0; i < fullBytes; i++) {
        if (hash[i] !== 0) return false;
    }
    if (remBits > 0) {
        const mask = (0xFF << (8 - remBits)) & 0xFF;
        if ((hash[fullBytes] & mask) !== 0) return false;
    }
    return true;
}

async function solve(canonical, difficulty) {
    if (!self.crypto || !self.crypto.subtle) {
        throw new Error("SubtleCrypto unavailable — the page must be served over https or from localhost");
    }

    let attempts = 0;
    let lastReport = Date.now();

    for (let i = 0; i < 0x7FFFFFFF && running; i++) {
        const counter = counterToStr(i);
        const input = canonical.replace("__CNT__", counter);
        const hash = await sha256Bytes(input);
        attempts++;

        if (hasLeadingZeroBits(hash, difficulty)) {
            self.postMessage({
                type: "found",
                counter: counter,
                sign: toHex(hash),
                attempts: attempts,
            });
            return;
        }

        if (Date.now() - lastReport > 200) {
            self.postMessage({ type: "progress", attempts: attempts });
            lastReport = Date.now();
        }
    }

    if (!running) {
        self.postMessage({ type: "done", cancelled: true });
    }
}

function counterToStr(n) {
    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = "0" + hex;
    return hex.padStart(16, "0");
}
