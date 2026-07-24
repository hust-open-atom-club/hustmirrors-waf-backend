// pow-worker.js — Web Worker that brute-forces the PoW nonce.
//
// Messages in:
//   { type: "start", payload: {canonical, difficulty} }
// Messages out:
//   { type: "progress", attempts: number }
//   { type: "found", counter: string, sign: string, attempts: number }
//   { type: "done", cancelled: true }

self.importScripts("https://cdnjs.cloudflare.com/ajax/libs/js-sha256/0.11.0/sha256.min.js");

let running = false;

self.onmessage = function (e) {
    const msg = e.data;
    if (msg.type === "start") {
        running = true;
        solve(msg.payload.canonical, msg.payload.difficulty);
    } else if (msg.type === "cancel") {
        running = false;
    }
};

function solve(canonical, difficulty) {
    const fullBytes = Math.floor(difficulty / 8);
    const remBits = difficulty % 8;
    const mask = remBits > 0 ? (0xFF << (8 - remBits)) & 0xFF : 0;

    let attempts = 0;
    let lastReport = Date.now();

    for (let i = 0; i < 0x7FFFFFFF && running; i++) {
        const counter = counterToStr(i);
        const input = canonical.replace("__CNT__", counter);
        const hash = sha256.array(input);

        if (hash[0] !== 0) continue;
        let ok = true;
        for (let b = 0; b < fullBytes; b++) {
            if (hash[b] !== 0) { ok = false; break; }
        }
        if (ok && remBits > 0 && (hash[fullBytes] & mask) !== 0) {
            ok = false;
        }
        if (ok) {
            const sign = sha256(input);
            self.postMessage({ type: "found", counter: counter, sign: sign, attempts: attempts + 1 });
            return;
        }

        attempts++;
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
