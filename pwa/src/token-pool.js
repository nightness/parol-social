// ParolNet PWA — Privacy Pass relay-token pool (H9 commit 2).
//
// The relay's outer frame requires every outbound `message` to carry a
// `token` field (per PNP-001-MUST-048..052 and the in-tree implementation
// shipped in H9 commit 1). The pool keeps a FIFO queue of unblinded token
// hexes ready to spend, refills from `POST /tokens/issue` once per epoch,
// and exposes a tiny state machine used by boot + messaging.
//
// The relay caps issuance at one batch per identity per epoch, so the
// refill strategy MUST wait until the next epoch before asking again. We
// track `currentEpochId` / `currentExpiresAt` for that — a refill fires
// as soon as we cross into a new epoch.
//
// The secret blinding material lives inside `wasm.token_prepare_blind`'s
// hex handle only for the brief window between request + response; once
// `token_unblind` consumes it, the Rust side zeroizes its scalar copy and
// we drop our handle reference.

// `wasm` is looked up lazily from state.js via dynamic import. Keeping
// the import indirect lets the unit tests in `pwa/tests/unit.test.mjs`
// exercise the pool under node without pulling in `state.js` → DOM code.
let _getWasm = null;
async function getWasm() {
    if (_getWasm) return _getWasm();
    try {
        const mod = await import('./state.js');
        _getWasm = () => mod.wasm;
        return mod.wasm;
    } catch (e) {
        return null;
    }
}

// How many tokens to request per batch. The relay's per-epoch budget is
// 8192 (see `TokenConfig::default` in parolnet-relay::tokens). Match that.
const DEFAULT_BATCH_SIZE = 8192;
// When the queue drops below this during an active epoch, trigger a
// fire-and-forget refill. Needs to be lower than the cover-traffic tick
// rate × epoch seconds so we never hit zero in steady state.
const LOW_WATER = 128;
// Epoch budget + grace guard: do not attempt refill if the active epoch
// has less than this many seconds left (we'd hit the "already fetched in
// this epoch" cap). Waiting for the boundary is the refill strategy.
const EPOCH_TAIL_GUARD_SECS = 300;

export const tokenPool = {
    currentEpochId: null,   // hex string (8 chars = 4 bytes)
    currentExpiresAt: 0,    // unix seconds (end of epoch incl. grace)
    queue: [],              // array of hex-encoded Token CBOR
    refilling: false,
    // Injection seam for tests: replaced by tests to observe / stub
    // `requestBatch` without touching the module's real fetch path.
    _requestBatchImpl: null,
};

/** Pop one token hex off the queue FIFO. Throws if empty. */
export function spendOneToken() {
    if (tokenPool.queue.length === 0) {
        throw new Error('relay token pool empty');
    }
    return tokenPool.queue.shift();
}

/** Queue size. */
export function queueSize() {
    return tokenPool.queue.length;
}

/** Clear pool state. Used by tests and by panic-wipe flows. */
export function resetTokenPool() {
    tokenPool.currentEpochId = null;
    tokenPool.currentExpiresAt = 0;
    tokenPool.queue.length = 0;
    tokenPool.refilling = false;
}

// ── CBOR minimal codec ─────────────────────────────────────────
// Handles only the subset the `/tokens/issue` request + response need:
//   - text strings (major type 3)           — keys
//   - byte strings (major type 2)           — `epoch_id`, `evaluated[i]`,
//                                              `blinded_bytes_list[i]`
//   - maps (major type 5) keyed by text     — the top-level shape
//   - arrays (major type 4)                 — the blinded/evaluated lists
//   - unsigned ints (major type 0)          — `activated_at`, `expires_at`,
//                                              `budget`
// This avoids pulling in a JS CBOR dependency for the single call site.

function encodeHead(major, len, out) {
    const mt = major << 5;
    if (len < 24) { out.push(mt | len); return; }
    if (len < 0x100) { out.push(mt | 24, len); return; }
    if (len < 0x10000) { out.push(mt | 25, (len >> 8) & 0xff, len & 0xff); return; }
    if (len < 0x100000000) {
        out.push(mt | 26,
            (len >>> 24) & 0xff, (len >>> 16) & 0xff,
            (len >>> 8) & 0xff, len & 0xff);
        return;
    }
    throw new Error('CBOR length >= 2^32 unsupported');
}

function encodeUint(n, out) { encodeHead(0, n, out); }
function encodeBytes(bytes, out) {
    encodeHead(2, bytes.length, out);
    for (let i = 0; i < bytes.length; i++) out.push(bytes[i]);
}
function encodeText(str, out) {
    const utf = new TextEncoder().encode(str);
    encodeHead(3, utf.length, out);
    for (let i = 0; i < utf.length; i++) out.push(utf[i]);
}
function encodeMap(pairs, out) {
    encodeHead(5, pairs.length, out);
    for (const [k, encV] of pairs) {
        encodeText(k, out);
        encV(out);
    }
}
function encodeArray(items, encItem, out) {
    encodeHead(4, items.length, out);
    for (const it of items) encItem(it, out);
}

function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error('odd-length hex');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}
function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
        s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
}

// Decoder — returns { value, next }.
function decodeAt(buf, off) {
    const first = buf[off]; off++;
    const major = first >> 5;
    const info = first & 0x1f;
    let len;
    if (info < 24) { len = info; }
    else if (info === 24) { len = buf[off]; off += 1; }
    else if (info === 25) { len = (buf[off] << 8) | buf[off + 1]; off += 2; }
    else if (info === 26) {
        len = (buf[off] * 0x1000000) + ((buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]);
        off += 4;
    } else if (info === 27) {
        // 64-bit. We only see this on timestamps; unpack into a Number.
        // (UNIX seconds easily fits in JS Number precision for decades.)
        let hi = (buf[off] * 0x1000000) + ((buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]);
        let lo = (buf[off + 4] * 0x1000000) + ((buf[off + 5] << 16) | (buf[off + 6] << 8) | buf[off + 7]);
        len = hi * 0x100000000 + lo;
        off += 8;
    } else {
        throw new Error('CBOR indefinite-length not supported');
    }
    switch (major) {
        case 0: return { value: len, next: off };
        case 2: {
            const b = buf.slice(off, off + len);
            return { value: b, next: off + len };
        }
        case 3: {
            const s = new TextDecoder().decode(buf.slice(off, off + len));
            return { value: s, next: off + len };
        }
        case 4: {
            const arr = [];
            for (let i = 0; i < len; i++) {
                const r = decodeAt(buf, off); off = r.next; arr.push(r.value);
            }
            return { value: arr, next: off };
        }
        case 5: {
            const obj = {};
            for (let i = 0; i < len; i++) {
                const k = decodeAt(buf, off); off = k.next;
                const v = decodeAt(buf, off); off = v.next;
                obj[k.value] = v.value;
            }
            return { value: obj, next: off };
        }
        default:
            throw new Error('CBOR major type ' + major + ' not supported');
    }
}

function cborDecode(bytes) { return decodeAt(bytes, 0).value; }

// ── Relay URL helper ───────────────────────────────────────────
// `connMgr.relayUrl` is a ws(s):// URL ending in /ws; the issuance
// endpoint lives on the same origin at http(s)://host/tokens/issue.
function toIssueUrl(relayUrl) {
    let base;
    if (relayUrl.startsWith('wss://')) base = 'https://' + relayUrl.slice(6);
    else if (relayUrl.startsWith('ws://')) base = 'http://' + relayUrl.slice(5);
    else base = relayUrl;
    // Strip trailing /ws if present.
    base = base.replace(/\/ws$/, '');
    return base + '/tokens/issue';
}

// ── Challenge-response helpers ─────────────────────────────────
// The relay /tokens/issue endpoint requires Ed25519(challenge_nonce). The
// challenge nonce is fresh random client-side (the server verifies under
// the provided pubkey), so it doubles as a one-shot anti-replay bind.
function randomNonceHex(bytes = 32) {
    const buf = new Uint8Array(bytes);
    (globalThis.crypto || globalThis.msCrypto).getRandomValues(buf);
    return bytesToHex(buf);
}

// ── Batch fetch ────────────────────────────────────────────────
export async function requestBatch(relayUrl, batchSize = DEFAULT_BATCH_SIZE) {
    if (tokenPool._requestBatchImpl) {
        return tokenPool._requestBatchImpl(relayUrl, batchSize);
    }
    if (tokenPool.refilling) {
        return { ok: false, reason: 'already-refilling' };
    }
    const wasm = await getWasm();
    if (!wasm || !wasm.token_prepare_blind || !wasm.token_unblind || !wasm.sign_bytes || !wasm.get_public_key) {
        return { ok: false, reason: 'wasm-not-ready' };
    }
    tokenPool.refilling = true;
    try {
        const prepared = wasm.token_prepare_blind(batchSize);
        const handleHex = prepared.handle_hex;
        const blindedHexList = prepared.blinded_bytes_hex_list;

        const challengeNonceHex = randomNonceHex(32);
        const signatureHex = wasm.sign_bytes(challengeNonceHex);
        const pubkeyHex = wasm.get_public_key();

        // CBOR-encode the request body.
        const blindedBytesList = blindedHexList.map(h => hexToBytes(h));
        const body = [];
        encodeMap([
            ['ed25519_pubkey_hex', (o) => encodeText(pubkeyHex, o)],
            ['ed25519_sig_hex',    (o) => encodeText(signatureHex, o)],
            ['challenge_nonce_hex',(o) => encodeText(challengeNonceHex, o)],
            ['blinded_bytes_list', (o) => encodeArray(blindedBytesList, (it, oo) => encodeBytes(it, oo), o)],
        ], body);

        const resp = await fetch(toIssueUrl(relayUrl), {
            method: 'POST',
            headers: { 'Content-Type': 'application/cbor' },
            body: new Uint8Array(body),
        });
        if (!resp.ok) {
            return { ok: false, reason: 'http-' + resp.status };
        }
        const arr = new Uint8Array(await resp.arrayBuffer());
        const decoded = cborDecode(arr);

        // Validate shape.
        const ciphersuite = decoded.ciphersuite;
        if (ciphersuite !== 'ristretto255-SHA512') {
            return { ok: false, reason: 'unexpected-ciphersuite:' + ciphersuite };
        }
        const epochBytes = decoded.epoch_id;
        if (!epochBytes || epochBytes.length !== 4) {
            return { ok: false, reason: 'bad-epoch-id' };
        }
        const evaluated = decoded.evaluated;
        if (!Array.isArray(evaluated) || evaluated.length !== blindedHexList.length) {
            return { ok: false, reason: 'evaluated-length-mismatch' };
        }

        const epochIdHex = bytesToHex(epochBytes);
        const evaluatedHexes = evaluated.map(b => bytesToHex(b));

        const tokenHexes = wasm.token_unblind(handleHex, evaluatedHexes, epochIdHex);
        if (!Array.isArray(tokenHexes)) {
            return { ok: false, reason: 'unblind-returned-non-array' };
        }

        tokenPool.currentEpochId = epochIdHex;
        tokenPool.currentExpiresAt = Number(decoded.expires_at) || 0;
        for (const th of tokenHexes) tokenPool.queue.push(th);

        return { ok: true, count: tokenHexes.length, epochId: epochIdHex };
    } catch (e) {
        return { ok: false, reason: 'exception:' + (e && e.message || e) };
    } finally {
        tokenPool.refilling = false;
    }
}

// ── Low-water refill ───────────────────────────────────────────
// Fires a fire-and-forget refill when:
//   - queue is below LOW_WATER AND the active epoch has room (>EPOCH_TAIL_GUARD_SECS left); OR
//   - the active epoch has fully crossed `currentExpiresAt` (time to ask again).
// The one-per-identity-per-epoch cap means we can't refill mid-epoch once
// we've already fetched — the server will 429. Crossing the boundary resets it.
export function maybeRefill(relayUrl) {
    if (tokenPool.refilling) return;
    const now = Math.floor(Date.now() / 1000);
    const epochHasRoom = tokenPool.currentExpiresAt > 0
        && now + EPOCH_TAIL_GUARD_SECS < tokenPool.currentExpiresAt;
    const crossedBoundary = tokenPool.currentExpiresAt > 0
        && now >= tokenPool.currentExpiresAt;

    // Case A: we've crossed into a new epoch — always replenish.
    if (crossedBoundary) {
        requestBatch(relayUrl).catch(() => {});
        return;
    }
    // Case B: mid-epoch low-water with room to fetch.
    if (tokenPool.queue.length < LOW_WATER && epochHasRoom) {
        // But we've already fetched once in this epoch by construction — so
        // this branch only fires when currentEpochId is null (cold start
        // failed) or when the queue really did drain in one epoch (budget
        // overrun, unrealistic in practice). We still try; if the server
        // returns 429 we just log and wait out the epoch.
        requestBatch(relayUrl).catch(() => {});
    }
}

// Export constants for tests.
export const TOKEN_POOL_LOW_WATER = LOW_WATER;
export const TOKEN_POOL_DEFAULT_BATCH = DEFAULT_BATCH_SIZE;
export const TOKEN_POOL_EPOCH_TAIL_GUARD_SECS = EPOCH_TAIL_GUARD_SECS;
