// ParolNet PWA — Peer → home-relay lookup cache (H12 Phase 2 Option α).
//
// When the PWA wants to send to a peer that doesn't live on its own home
// relay, it first has to find out which relay the peer *is* connected to.
// The PWA's home relay exposes `GET /peers/lookup?id=<hex>` for exactly
// this purpose (PNP-008-MUST-064). The response is Ed25519-signed by the
// relay that actually hosts the peer — the signature binds
// `(relay_peer_id, peer_id, last_seen)` together, so a compromised
// intermediate relay can't steer traffic to a different URL without
// breaking the signature.
//
// Cache semantics:
//   - Hit within 1 hr (PNP-008-MUST-067): return cached URL immediately.
//   - Miss or expired: fetch /peers/lookup from home relay, verify the
//     signature against the claimed home relay's authority-verified
//     identity key, cache, return.
//   - 404 / network / signature fail: return null. The caller then falls
//     back to the home-relay path (which will either queue the frame for
//     a local peer or bounce with "peer not connected" for an unknown).
//
// Caveat 1 from commit 1: RELAY_PUBLIC_URL may be unset in a deployment,
// so `home_relay_url` in the response can come back as an unreachable
// string like "http://0.0.0.0:9000". If the PWA already knows a
// reachable URL for the same `relay_peer_id` via
// `relayClient.verifiedDirectory`, we prefer that URL. The signature /
// identity binding (to `relay_peer_id`) is preserved regardless — we
// only swap the *transport* URL, never the trust anchor.

// Lazy-load state.js and connection.js to keep the module importable
// from node --test (the state module transitively imports DOM-dependent
// files). Under the browser, the first call resolves synchronously from
// the module registry.
let _stateMod = null;
let _connMod = null;
async function _getState() {
    if (_stateMod) return _stateMod;
    try { _stateMod = await import('./state.js'); } catch (_) { _stateMod = {}; }
    return _stateMod;
}
async function _getConn() {
    if (_connMod) return _connMod;
    try { _connMod = await import('./connection.js'); } catch (_) { _connMod = {}; }
    return _connMod;
}

const TTL_MS = 60 * 60 * 1000; // PNP-008-MUST-067: 1 hr

/** @type {Map<string, {homeRelayUrl: string, lastSeen: number, signature: string, cachedAt: number, relayPeerId: string}>} */
const cache = new Map();

/** Test / debug hook. */
export function _clearCache() {
    cache.clear();
}

/** Test / debug hook — inspect a single entry without going through lookup. */
export function _peekCache(peerIdHex) {
    return cache.get(peerIdHex) || null;
}

function isFresh(entry, nowMs) {
    return entry && (nowMs - entry.cachedAt) < TTL_MS;
}

// Convert the /peers/lookup WebSocket-y URL shape into the HTTP shape we
// need for `fetch`. Mirrors the pattern in `token-pool.js::toIssueUrl`.
function toLookupHttpBase(relayUrl) {
    if (!relayUrl) return null;
    let base = relayUrl;
    if (base.startsWith('wss://')) base = 'https://' + base.slice(6);
    else if (base.startsWith('ws://')) base = 'http://' + base.slice(5);
    return base.replace(/\/ws$/, '').replace(/\/$/, '');
}

// Decode a CBOR blob for the lookup response. The server encodes:
//   { home_relay_url: tstr, last_seen: uint, signature: bstr64 }
// We avoid dragging in a real CBOR lib by reusing the minimal decoder
// pattern already in use elsewhere (relay-client.js) — direct map decode.
function cborDecodeLookup(bytes) {
    let off = 0;
    function hdr() {
        const b = bytes[off++];
        return { major: b >> 5, info: b & 0x1f };
    }
    function readLen(info) {
        if (info < 24) return info;
        if (info === 24) return bytes[off++];
        if (info === 25) { const v = (bytes[off] << 8) | bytes[off + 1]; off += 2; return v; }
        if (info === 26) {
            const v = (bytes[off] * 0x1000000) + ((bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]);
            off += 4; return v;
        }
        if (info === 27) {
            const hi = (bytes[off] * 0x1000000) + ((bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]);
            const lo = (bytes[off + 4] * 0x1000000) + ((bytes[off + 5] << 16) | (bytes[off + 6] << 8) | bytes[off + 7]);
            off += 8; return hi * 0x100000000 + lo;
        }
        throw new Error('unsupported CBOR len');
    }
    function readItem() {
        const { major, info } = hdr();
        const len = readLen(info);
        switch (major) {
            case 0: return len;
            case 2: { const b = bytes.slice(off, off + len); off += len; return b; }
            case 3: { const s = new TextDecoder().decode(bytes.slice(off, off + len)); off += len; return s; }
            case 5: {
                const obj = {};
                for (let i = 0; i < len; i++) {
                    const k = readItem();
                    const v = readItem();
                    obj[String(k)] = v;
                }
                return obj;
            }
            default: throw new Error('CBOR major ' + major + ' not handled');
        }
    }
    return readItem();
}

function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
}

// PNP-008 presence signable-bytes layout (see Rust
// `presence_signable_bytes` in crates/parolnet-relay/src/presence.rs):
//   SHA-256( relay_peer_id (32) || peer_id (32) || last_seen (u64 BE) )
// We verify against that 32-byte digest — the WASM
// `verify_ed25519_signature` helper takes pre-hashed message bytes.
async function presenceSignableHexAsync(relayPeerIdHex, peerIdHex, lastSeen) {
    // Build 72-byte input.
    const input = new Uint8Array(32 + 32 + 8);
    for (let i = 0; i < 32; i++) input[i] = parseInt(relayPeerIdHex.slice(i * 2, i * 2 + 2), 16);
    for (let i = 0; i < 32; i++) input[32 + i] = parseInt(peerIdHex.slice(i * 2, i * 2 + 2), 16);
    // Big-endian u64.
    const hi = Math.floor(lastSeen / 0x100000000);
    const lo = lastSeen >>> 0;
    input[64] = (hi >>> 24) & 0xff;
    input[65] = (hi >>> 16) & 0xff;
    input[66] = (hi >>> 8) & 0xff;
    input[67] = hi & 0xff;
    input[68] = (lo >>> 24) & 0xff;
    input[69] = (lo >>> 16) & 0xff;
    input[70] = (lo >>> 8) & 0xff;
    input[71] = lo & 0xff;
    // Use SubtleCrypto when available, fall back to sync pure-JS SHA-256
    // (mirrors the fallback used by relay-client.js).
    if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
        const out = await crypto.subtle.digest('SHA-256', input);
        return bytesToHex(new Uint8Array(out));
    }
    return bytesToHex(_sha256Sync(input));
}

// Pure-JS SHA-256 fallback — lifted from relay-client.js to avoid a
// cross-module private dep. Kept in lockstep; only used when
// `crypto.subtle` is absent (node --test without a polyfill).
function _sha256Sync(data) {
    const K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);
    const H = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const bitLen = data.length * 8;
    const padLen = ((data.length + 9 + 63) & ~63) - data.length;
    const buf = new Uint8Array(data.length + padLen);
    buf.set(data, 0);
    buf[data.length] = 0x80;
    const end = buf.length;
    buf[end - 4] = (bitLen >>> 24) & 0xff;
    buf[end - 3] = (bitLen >>> 16) & 0xff;
    buf[end - 2] = (bitLen >>> 8) & 0xff;
    buf[end - 1] = bitLen & 0xff;
    const W = new Uint32Array(64);
    function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
    for (let off = 0; off < buf.length; off += 64) {
        for (let i = 0; i < 16; i++) {
            const o = off + i * 4;
            W[i] = ((buf[o] << 24) | (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3]) >>> 0;
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
            const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }
        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const mj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + mj) >>> 0;
            h = g; g = f; f = e;
            e = (d + t1) >>> 0;
            d = c; c = b; b = a;
            a = (t1 + t2) >>> 0;
        }
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
        out[i * 4] = (H[i] >>> 24) & 0xff;
        out[i * 4 + 1] = (H[i] >>> 16) & 0xff;
        out[i * 4 + 2] = (H[i] >>> 8) & 0xff;
        out[i * 4 + 3] = H[i] & 0xff;
    }
    return out;
}

/**
 * Resolve the home-relay URL for `peerIdHex`. See module-level comment
 * for semantics.
 *
 * Overridable injection seams (exposed for tests):
 *   - `_inject({ fetchFn, verifyFn, homeRelayUrl, verifiedDirectory })`
 *
 * @param {string} peerIdHex - 64-char lowercase hex (32-byte PeerId).
 * @returns {Promise<string|null>}
 */
export async function lookupHomeRelay(peerIdHex) {
    if (!peerIdHex || typeof peerIdHex !== 'string') return null;
    const key = peerIdHex.toLowerCase();
    const nowMs = Date.now();
    const hit = cache.get(key);
    if (isFresh(hit, nowMs)) return _preferReachable(hit.homeRelayUrl, hit.relayPeerId);

    const conn = _inj.homeRelayUrl ? null : await _getConn();
    const homeUrl = _inj.homeRelayUrl ? _inj.homeRelayUrl() : (conn && conn.connMgr && conn.connMgr.relayUrl);
    const httpBase = toLookupHttpBase(homeUrl);
    if (!httpBase) return null;
    const url = httpBase + '/peers/lookup?id=' + encodeURIComponent(key);

    let resp;
    try {
        const fetchFn = _inj.fetchFn || fetch;
        resp = await fetchFn(url, { headers: { 'Accept': 'application/cbor' } });
    } catch (_) {
        return null;
    }
    if (!resp || resp.status === 404) return null;
    if (!resp.ok) return null;

    let body;
    try {
        const arr = new Uint8Array(await resp.arrayBuffer());
        body = cborDecodeLookup(arr);
    } catch (_) {
        return null;
    }
    if (!body || typeof body !== 'object') return null;

    const homeRelayUrl = body.home_relay_url;
    const lastSeen = Number(body.last_seen);
    const sigBytes = body.signature;
    if (typeof homeRelayUrl !== 'string' || !Number.isFinite(lastSeen)) return null;
    if (!sigBytes || (sigBytes.length !== 64 && !(sigBytes instanceof Uint8Array && sigBytes.byteLength === 64))) return null;
    const sigHex = bytesToHex(sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes));

    // The signature is by the *home* relay, not by the relay we asked.
    // We resolve the home-relay's Ed25519 identity via the authority-
    // verified directory: `verifiedDirectory` entries carry `peerIdHex`
    // (= SHA-256 of their Ed25519 pubkey, i.e. their PeerId, NOT the
    // pubkey itself). But the PWA needs the pubkey bytes to verify
    // Ed25519. In the H12 Phase 1 directory format the `identity_key`
    // field *is* the 32-byte pubkey, and descriptor `peer_id` is
    // SHA-256(pubkey). We attached `peerIdHex` as fingerprintable id,
    // and the verify path needs the raw identity key. Phase 1 populates
    // verified entries with the `identity_key` first when available.
    //
    // Find the directory entry whose URL matches the server-claimed
    // home_relay_url. If none matches, we can still try the server-
    // claimed URL if its peer_id — via whatever routing — matches a
    // verified entry by `peerIdHex`.
    const state = _inj.verifiedDirectory ? null : await _getState();
    const vDir = (_inj.verifiedDirectory ? _inj.verifiedDirectory() : (state && state.relayClient && state.relayClient.verifiedDirectory)) || [];
    let dirEntry = vDir.find(e => e.url === homeRelayUrl);
    // Caveat 1: operator forgot to set RELAY_PUBLIC_URL. Fall back to
    // any verified entry matching on `identity_key` or `peerIdHex` if
    // we can pick just one.
    if (!dirEntry) {
        // Fuzzy match: if the signature is signed by a relay whose
        // directory entry we already have, use that entry's URL for
        // verification + outbound transport.
        for (const e of vDir) {
            const pubHex = e.identityKey || e.identity_key;
            if (!pubHex) continue;
            // Try verifying the signature using this candidate pubkey.
            const ok = await _verifyPresenceSig(pubHex, peerIdHex, lastSeen, sigHex);
            if (ok) { dirEntry = e; break; }
        }
        if (!dirEntry) return null;
    }

    // Verify: signature is over SHA-256(relay_peer_id || peer_id || last_seen_be).
    const pubkeyHex = dirEntry.identityKey || dirEntry.identity_key;
    const relayPeerId = dirEntry.peerIdHex;
    if (!pubkeyHex || !relayPeerId) return null;
    const okSig = await _verifyPresenceSig(pubkeyHex, peerIdHex, lastSeen, sigHex);
    if (!okSig) return null;

    const verifiedUrl = await _preferReachable(homeRelayUrl, relayPeerId, vDir);
    cache.set(key, {
        homeRelayUrl: verifiedUrl,
        lastSeen,
        signature: sigHex,
        cachedAt: nowMs,
        relayPeerId,
    });
    return verifiedUrl;
}

async function _verifyPresenceSig(pubkeyHex, peerIdHex, lastSeen, sigHex) {
    let verifyFn = _inj.verifyFn;
    if (!verifyFn) {
        const state = await _getState();
        const wasm = state && state.wasm;
        verifyFn = wasm && wasm.verify_ed25519_signature;
    }
    if (!verifyFn) return false;
    // Compute the signable digest. Note we need the relay_peer_id here
    // to construct the digest — but we're using `verifyFn` which only
    // takes the raw bytes, and the signable bytes include relay_peer_id
    // already (derived from the same pubkey). Derive relay_peer_id from
    // pubkey via SHA-256 to match Rust's PeerId = SHA-256(pubkey).
    const relayPeerIdHex = await _peerIdFromPubkey(pubkeyHex);
    const msgHex = await presenceSignableHexAsync(relayPeerIdHex, peerIdHex, lastSeen);
    try {
        return !!verifyFn(pubkeyHex, msgHex, sigHex);
    } catch (_) {
        return false;
    }
}

async function _peerIdFromPubkey(pubkeyHex) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = parseInt(pubkeyHex.slice(i * 2, i * 2 + 2), 16);
    if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
        const d = await crypto.subtle.digest('SHA-256', bytes);
        return bytesToHex(new Uint8Array(d));
    }
    return bytesToHex(_sha256Sync(bytes));
}

// Caveat 1 enforcement. If the server returned `homeRelayUrl` that is
// unreachable (e.g. `http://0.0.0.0:...`) but we have a verified
// directory entry for the same `relayPeerId` with a different URL, use
// the directory's URL instead.
async function _preferReachable(claimedUrl, relayPeerId, vDirArg) {
    if (!relayPeerId) return claimedUrl;
    let vDir = vDirArg;
    if (!vDir) {
        if (_inj.verifiedDirectory) vDir = _inj.verifiedDirectory();
        else {
            const state = await _getState();
            vDir = state && state.relayClient && state.relayClient.verifiedDirectory;
        }
    }
    vDir = vDir || [];
    if (_looksUnreachable(claimedUrl)) {
        const match = vDir.find(e => e.peerIdHex === relayPeerId && !_looksUnreachable(e.url));
        if (match) return match.url;
    }
    return claimedUrl;
}

function _looksUnreachable(url) {
    if (!url) return true;
    // 0.0.0.0, 127.0.0.1, localhost, [::] — all fail from a different machine.
    return /(^|\/\/)0\.0\.0\.0(:|\/|$)/.test(url)
        || /(^|\/\/)127\.0\.0\.1(:|\/|$)/.test(url)
        || /(^|\/\/)localhost(:|\/|$)/i.test(url)
        || /(^|\/\/)\[::\](:|\/|$)/.test(url);
}

// Test injection seam. Kept underscore-prefixed to emphasize "not for
// production wiring" — production always reads from connMgr / relayClient.
const _inj = {
    fetchFn: null,
    verifyFn: null,
    homeRelayUrl: null,
    verifiedDirectory: null,
};
export function _inject(overrides) {
    Object.assign(_inj, overrides || {});
}
export function _resetInject() {
    _inj.fetchFn = null;
    _inj.verifyFn = null;
    _inj.homeRelayUrl = null;
    _inj.verifiedDirectory = null;
}
