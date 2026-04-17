// ParolNet Relay Discovery Client
// Implements fallback chain: cached directory -> bootstrap relays -> fetch from any relay.
// Goal: any single relay alive = entire network reachable.

import { BOOTSTRAP_RELAYS, AUTHORITY_PUBKEYS, AUTHORITY_THRESHOLD } from './network-config.js';

const DIRECTORY_CACHE_KEY = 'parolnet_relay_directory';
const DIRECTORY_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const BRIDGE_RELAYS_DB_KEY = 'bridge_relays';

/**
 * Verify a descriptor against the baked-in authority set.
 *
 * H12 Phase 1 rule (from PNP-008 §3): a relay descriptor is accepted only
 * if ≥ AUTHORITY_THRESHOLD distinct authority pubkeys have signed it with
 * a non-expired endorsement. Unsigned / insufficient / expired entries
 * are dropped silently.
 *
 * Verification uses `wasm.verify_authority_signature(pubkey, msg, sig)`
 * per-endorsement. The signable bytes are SHA-256(peer_id || endorsed_at
 * || expires_at) — matched between `parolnet_relay::authority::AuthorityEndorsement::signable_bytes`
 * and `parolnet_wasm::federation::AuthorityEndorsement::signable_bytes`.
 *
 * @param {Object} desc - Parsed descriptor, possibly endorsed.
 * @param {Object} wasm - WASM module (needs `verify_authority_signature`).
 * @param {number} nowSecs - Current Unix timestamp (seconds).
 * @returns {boolean} true iff authority threshold is met.
 */
export function verifyAuthorityEndorsements(desc, wasm, nowSecs) {
    if (!desc || typeof desc !== 'object') return false;
    if (!wasm || typeof wasm.verify_authority_signature !== 'function') return false;

    const endorsements = Array.isArray(desc.endorsements) ? desc.endorsements : null;
    if (!endorsements || endorsements.length === 0) return false;

    const relayPeerId = desc.descriptor && desc.descriptor.peer_id;
    if (!relayPeerId) return false;
    // peer_id may arrive as Uint8Array (CBOR) or hex string (JSON) — normalize.
    const peerIdBytes = _normalizeBytes(relayPeerId);
    if (!peerIdBytes || peerIdBytes.length !== 32) return false;

    const distinctAuthorities = new Set();
    for (const e of endorsements) {
        if (!e || typeof e !== 'object') continue;
        const pub = _normalizeBytes(e.authority_pubkey);
        const sig = _normalizeBytes(e.signature);
        const endorsedAt = Number(e.endorsed_at);
        const expiresAt = Number(e.expires_at);
        if (!pub || pub.length !== 32) continue;
        if (!sig || sig.length !== 64) continue;
        if (!Number.isFinite(endorsedAt) || !Number.isFinite(expiresAt)) continue;
        if (nowSecs >= expiresAt) continue; // expired

        // Signable bytes = SHA-256(peer_id || endorsed_at_be || expires_at_be)
        const signable = _sha256AuthoritySignable(peerIdBytes, endorsedAt, expiresAt);
        const pubHex = _bytesToHex(pub);
        const sigHex = _bytesToHex(sig);
        const msgHex = _bytesToHex(signable);

        // Authority set membership + signature verify, both inside WASM
        // (verify_authority_signature rejects pubkeys outside the set).
        let ok;
        try {
            ok = wasm.verify_authority_signature(pubHex, msgHex, sigHex);
        } catch (_) {
            ok = false;
        }
        if (ok) distinctAuthorities.add(pubHex);
    }

    return distinctAuthorities.size >= AUTHORITY_THRESHOLD;
}

/**
 * Derive fingerprint suffix from a 32-byte Ed25519 pubkey for display in
 * the Settings → Relay section. Last 16 hex chars — matches the "short
 * fingerprint" rendering pattern used elsewhere in the PWA.
 * @param {Uint8Array|number[]|string} pubkey
 * @returns {string}
 */
export function fingerprintSuffix(pubkey) {
    const bytes = _normalizeBytes(pubkey);
    if (!bytes || bytes.length !== 32) return '????????????????';
    const hex = _bytesToHex(bytes);
    return hex.slice(-16);
}

function _normalizeBytes(v) {
    if (v instanceof Uint8Array) return v;
    if (Array.isArray(v)) return Uint8Array.from(v);
    if (typeof v === 'string') {
        try {
            const out = new Uint8Array(v.length / 2);
            for (let i = 0; i < out.length; i++) {
                out[i] = parseInt(v.slice(i * 2, i * 2 + 2), 16);
            }
            return out;
        } catch (_) { return null; }
    }
    if (v && typeof v === 'object' && typeof v.length === 'number') {
        return Uint8Array.from(v);
    }
    return null;
}

function _bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
        s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
}

// Accepts loose input (hex string / Uint8Array / array of ints) and returns
// a hex string, or the empty string if normalization fails. Public helper
// used by the directory-extraction path to produce peer-id hex.
function _bytesToHexPublic(v) {
    const b = _normalizeBytes(v);
    return b ? _bytesToHex(b) : '';
}

// Precomputed SHA-256 helper using Web Crypto in the browser, node:crypto
// under node --test. Synchronous SubtleCrypto isn't available so we do a
// blocking-looking API via a pure-JS SHA-256 fallback — necessary because
// the verify loop is not async.
function _sha256AuthoritySignable(peerIdBytes, endorsedAt, expiresAt) {
    const buf = new Uint8Array(32 + 8 + 8);
    buf.set(peerIdBytes, 0);
    _writeU64BE(buf, 32, endorsedAt);
    _writeU64BE(buf, 40, expiresAt);
    return _sha256Sync(buf);
}

function _writeU64BE(buf, off, n) {
    // JS numbers are safe to 2^53. Timestamps fit.
    const hi = Math.floor(n / 0x100000000);
    const lo = n >>> 0;
    buf[off] = (hi >>> 24) & 0xff;
    buf[off + 1] = (hi >>> 16) & 0xff;
    buf[off + 2] = (hi >>> 8) & 0xff;
    buf[off + 3] = hi & 0xff;
    buf[off + 4] = (lo >>> 24) & 0xff;
    buf[off + 5] = (lo >>> 16) & 0xff;
    buf[off + 6] = (lo >>> 8) & 0xff;
    buf[off + 7] = lo & 0xff;
}

// Pure-JS SHA-256 for the sync path (authoritative for bits the WASM
// doesn't expose). Small, self-contained, no deps. Returns Uint8Array.
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
    // Write bit length as u64 big-endian into last 8 bytes.
    const end = buf.length;
    buf[end - 4] = (bitLen >>> 24) & 0xff;
    buf[end - 3] = (bitLen >>> 16) & 0xff;
    buf[end - 2] = (bitLen >>> 8) & 0xff;
    buf[end - 1] = bitLen & 0xff;

    const W = new Uint32Array(64);
    for (let off = 0; off < buf.length; off += 64) {
        for (let i = 0; i < 16; i++) {
            const o = off + i * 4;
            W[i] = (buf[o] << 24) | (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3];
            W[i] >>>= 0;
        }
        for (let i = 16; i < 64; i++) {
            const s0 = _rotr(W[i - 15], 7) ^ _rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
            const s1 = _rotr(W[i - 2], 17) ^ _rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }
        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];
        for (let i = 0; i < 64; i++) {
            const S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
            const S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
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

function _rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

/**
 * Relay discovery and connection with fallback chain.
 *
 * Startup order:
 *   1. Load cached directory from localStorage (from last session)
 *   2. Fall back to bundled BOOTSTRAP_RELAYS from network-config.js
 *   3. Try each known relay to fetch the full directory via GET /directory
 *   On success: cache the directory and populate this.relays
 */
export class RelayClient {
    constructor() {
        /** @type {string[]} Known relay WebSocket URLs */
        this.relays = [];
        /** @type {string|null} Currently connected relay URL */
        this.connectedRelay = null;
        /** @type {boolean} */
        this.connected = false;
        /** @type {Object|null} Raw directory data from last fetch */
        this._lastDirectory = null;
        /**
         * Directory entries that passed authority-threshold verification on
         * the last fetch. Each: { url, peerIdHex, fingerprint, verified:true }.
         * Rendered in Settings → Relay. H12 Phase 1.
         * @type {Object[]}
         */
        this.verifiedDirectory = [];
        /**
         * Ed25519 pubkey (hex) of the currently-connected relay, if known
         * via an authority-endorsed directory entry. Null until a verified
         * entry for `connectedRelay` is observed.
         * @type {string|null}
         */
        this.connectedRelayPubkey = null;
        /**
         * Bridge relays for censorship circumvention.
         * Each entry: { host, port, front_domain?, fingerprint?, wsUrl }
         * @type {Object[]}
         */
        this.bridgeRelays = [];
        /** @type {Object|null} Optional WASM module injected by boot.js */
        this._wasm = null;
    }

    /** Inject the WASM module for authority-endorsement verification. */
    setWasm(wasm) { this._wasm = wasm; }

    /**
     * Initialize relay discovery with fallback chain.
     * Populates this.relays with all known relay addresses.
     * Also loads bridge relays from IndexedDB.
     * @returns {Promise<string[]>} List of discovered relay URLs
     */
    async discover() {
        // 0. Load bridge relays from IndexedDB
        await this.loadBridges();

        // 1. Try cached directory from last session
        const cached = this.loadCachedDirectory();
        if (cached && cached.relays && cached.relays.length > 0) {
            console.log('[RelayClient] Loaded', cached.relays.length, 'relays from cache');
            this.relays = cached.relays.slice();
        }

        // 2. Merge in bundled bootstrap relays
        if (BOOTSTRAP_RELAYS && BOOTSTRAP_RELAYS.length > 0) {
            for (const url of BOOTSTRAP_RELAYS) {
                if (!this.relays.includes(url)) {
                    this.relays.push(url);
                }
            }
            console.log('[RelayClient] After bootstrap merge:', this.relays.length, 'relays');
        }

        // 3. If we have no relays at all, use same-origin as fallback
        if (this.relays.length === 0) {
            const origin = location.protocol + '//' + location.host;
            this.relays.push(origin);
            console.log('[RelayClient] Using same-origin fallback:', origin);
        }

        // 4. Try to fetch full directory from any known relay
        await this._fetchFromAnyRelay();

        return this.relays;
    }

    /**
     * Try fetching directory from each known relay until one succeeds.
     * @returns {Promise<boolean>}
     */
    async _fetchFromAnyRelay() {
        // Shuffle for load distribution
        const shuffled = this._shuffle(this.relays.slice());
        for (const relayUrl of shuffled) {
            try {
                const relays = await this.fetchDirectory(relayUrl);
                if (relays && relays.length > 0) {
                    // Merge discovered relays into our list
                    let added = 0;
                    for (const url of relays) {
                        if (!this.relays.includes(url)) {
                            this.relays.push(url);
                            added++;
                        }
                    }
                    if (added > 0) {
                        console.log('[RelayClient] Discovered', added, 'new relays from', relayUrl);
                    }
                    // Cache updated directory
                    this.cacheDirectory({ relays: this.relays, fetchedAt: Date.now() });
                    return true;
                }
            } catch (e) {
                console.debug('[RelayClient] Failed to fetch directory from', relayUrl, e.message);
            }
        }
        return false;
    }

    /**
     * Fetch directory from a specific relay.
     * @param {string} relayUrl - Base URL of the relay (e.g., "https://relay.example.com")
     * @returns {Promise<string[]>} List of relay addresses extracted from directory
     */
    async fetchDirectory(relayUrl) {
        const url = relayUrl.replace(/\/$/, '') + '/directory';
        const resp = await fetch(url, {
            signal: AbortSignal.timeout(10000),
        });
        if (!resp.ok) {
            throw new Error('HTTP ' + resp.status);
        }

        const contentType = resp.headers.get('content-type') || '';
        let descriptors;

        if (contentType.includes('cbor')) {
            // Parse CBOR response — try WASM bindings first, fall back to raw parsing
            const arrayBuf = await resp.arrayBuffer();
            descriptors = await this._parseCborDirectory(new Uint8Array(arrayBuf));
        } else {
            // Fallback: try JSON
            descriptors = await resp.json();
        }

        if (!Array.isArray(descriptors)) {
            return [];
        }

        this._lastDirectory = descriptors;

        // H12 Phase 1: run every directory entry through authority
        // verification. Unsigned / insufficiently-endorsed / expired
        // descriptors are dropped silently (per PNP-008 §3).
        //
        // If the descriptor arrives as an EndorsedDescriptor (has an
        // `endorsements` array), we verify against AUTHORITY_PUBKEYS with
        // the threshold rule. If it arrives as a bare RelayDescriptor
        // (older relays / dev mode), we accept the addr for connection
        // fallback but do NOT surface it as "verified" in the UI.
        const nowSecs = Math.floor(Date.now() / 1000);
        const relayAddrs = [];
        const verified = [];
        for (const desc of descriptors) {
            if (!desc || typeof desc !== 'object') continue;

            // Bare RelayDescriptor (no endorsements) — pick the addr so
            // connection fallback still works, but do not mark verified.
            const innerDesc = desc.descriptor || desc;
            const addr = innerDesc && innerDesc.addr;
            if (addr) {
                const httpUrl = this._socketAddrToUrl(addr);
                if (httpUrl) relayAddrs.push(httpUrl);
            }

            // EndorsedDescriptor shape: authority-verified entries populate
            // the UI's "directory" list.
            if (Array.isArray(desc.endorsements)) {
                const ok = verifyAuthorityEndorsements(desc, this._wasm, nowSecs);
                if (!ok) continue;
                const innerPid = innerDesc.peer_id;
                const innerKey = innerDesc.identity_key;
                const url = addr ? this._socketAddrToUrl(addr) : null;
                if (url) {
                    verified.push({
                        url,
                        peerIdHex: _bytesToHexPublic(innerPid),
                        fingerprint: fingerprintSuffix(innerKey || innerPid),
                        verified: true,
                    });
                }
            }
        }
        this.verifiedDirectory = verified;
        // Refresh connected-relay pubkey if any verified entry matches.
        if (this.connectedRelay) {
            const match = verified.find(v => v.url === this.connectedRelay);
            this.connectedRelayPubkey = match ? match.peerIdHex : this.connectedRelayPubkey;
        }
        return relayAddrs;
    }

    /**
     * Parse CBOR-encoded directory data.
     * Uses WASM bindings if available, otherwise attempts minimal CBOR decode.
     * @param {Uint8Array} data
     * @returns {Promise<Object[]>}
     */
    async _parseCborDirectory(data) {
        // Try WASM CBOR decoder if available
        if (typeof window !== 'undefined' && window._parolnetWasm &&
            typeof window._parolnetWasm.decode_cbor === 'function') {
            try {
                return window._parolnetWasm.decode_cbor(data);
            } catch (e) {
                console.debug('[RelayClient] WASM CBOR decode failed, using fallback:', e.message);
            }
        }

        // Minimal CBOR array-of-maps decoder for relay descriptors.
        // The relay server encodes Vec<RelayDescriptor> as a CBOR array of maps.
        // We only need the "addr" field from each map entry.
        //
        // This is a best-effort decoder — if it fails, we return an empty array
        // and rely on the fallback chain.
        try {
            return this._decodeCborDescriptors(data);
        } catch (e) {
            console.debug('[RelayClient] Fallback CBOR decode failed:', e.message);
            return [];
        }
    }

    /**
     * Minimal CBOR decoder for relay descriptor arrays.
     * Handles the subset of CBOR needed for our directory format.
     * @param {Uint8Array} data
     * @returns {Object[]}
     */
    _decodeCborDescriptors(data) {
        let offset = 0;

        function readByte() {
            if (offset >= data.length) throw new Error('unexpected end');
            return data[offset++];
        }

        function readUint(additionalInfo) {
            if (additionalInfo < 24) return additionalInfo;
            if (additionalInfo === 24) return readByte();
            if (additionalInfo === 25) {
                const hi = readByte(), lo = readByte();
                return (hi << 8) | lo;
            }
            if (additionalInfo === 26) {
                let val = 0;
                for (let i = 0; i < 4; i++) val = (val << 8) | readByte();
                return val;
            }
            if (additionalInfo === 27) {
                // 8-byte integer — JS safe integer limit may apply
                let val = 0;
                for (let i = 0; i < 8; i++) val = val * 256 + readByte();
                return val;
            }
            throw new Error('unsupported additional info: ' + additionalInfo);
        }

        function readItem() {
            const initial = readByte();
            const majorType = initial >> 5;
            const additionalInfo = initial & 0x1f;

            switch (majorType) {
                case 0: // unsigned integer
                    return readUint(additionalInfo);
                case 1: // negative integer
                    return -1 - readUint(additionalInfo);
                case 2: { // byte string
                    const len = readUint(additionalInfo);
                    const bytes = data.slice(offset, offset + len);
                    offset += len;
                    return bytes;
                }
                case 3: { // text string
                    const len = readUint(additionalInfo);
                    const textBytes = data.slice(offset, offset + len);
                    offset += len;
                    return new TextDecoder().decode(textBytes);
                }
                case 4: { // array
                    const len = readUint(additionalInfo);
                    const arr = [];
                    for (let i = 0; i < len; i++) arr.push(readItem());
                    return arr;
                }
                case 5: { // map
                    const len = readUint(additionalInfo);
                    const obj = {};
                    for (let i = 0; i < len; i++) {
                        const key = readItem();
                        const val = readItem();
                        obj[String(key)] = val;
                    }
                    return obj;
                }
                case 6: { // tag (skip tag number, return content)
                    readUint(additionalInfo);
                    return readItem();
                }
                case 7: { // simple values / float
                    if (additionalInfo === 20) return false;
                    if (additionalInfo === 21) return true;
                    if (additionalInfo === 22) return null;
                    if (additionalInfo === 23) return undefined;
                    if (additionalInfo === 25 || additionalInfo === 26 || additionalInfo === 27) {
                        // float — skip bytes
                        const floatLen = additionalInfo === 25 ? 2 : additionalInfo === 26 ? 4 : 8;
                        offset += floatLen;
                        return 0; // simplified: we don't need float precision
                    }
                    return null;
                }
                default:
                    throw new Error('unknown CBOR major type: ' + majorType);
            }
        }

        return readItem();
    }

    /**
     * Convert a SocketAddr string (e.g., "1.2.3.4:9000") to an HTTP URL.
     * @param {string} addr
     * @returns {string|null}
     */
    _socketAddrToUrl(addr) {
        if (!addr || typeof addr !== 'string') return null;
        // Handle IPv6 bracket notation
        if (addr.startsWith('[')) {
            // [::1]:9000 format
            const closeBracket = addr.lastIndexOf(']');
            if (closeBracket < 0) return null;
            const host = addr.slice(0, closeBracket + 1);
            const port = addr.slice(closeBracket + 2);
            return 'http://' + host + ':' + port;
        }
        // IPv4 format: 1.2.3.4:9000
        return 'http://' + addr;
    }

    /**
     * Try connecting to any available relay via WebSocket.
     * Bridge relays are tried first (priority), then regular relays.
     * Shuffles each group for load distribution.
     * @returns {Promise<string|null>} URL of connected relay, or null
     */
    async connect() {
        // Try bridge relays first (priority for censored networks)
        if (this.bridgeRelays.length > 0) {
            const shuffledBridges = this._shuffle(this.bridgeRelays.slice());
            for (const bridge of shuffledBridges) {
                const wsUrl = bridge.wsUrl;
                try {
                    const success = await this._tryConnect(wsUrl);
                    if (success) {
                        this.connectedRelay = wsUrl;
                        this.connected = true;
                        console.log('[RelayClient] Connected via bridge relay:', wsUrl);
                        return wsUrl;
                    }
                } catch (e) {
                    console.debug('[RelayClient] Bridge connection failed to', wsUrl, e.message);
                }
            }
        }

        // H12 Phase 1: try BOOTSTRAP_RELAYS in declared order first (the
        // operator chose that order intentionally — e.g., primary-then-
        // secondary), then fall back to the discovered/shuffled pool for
        // the tail. First successful probe wins.
        const seen = new Set();
        const prioritized = [];
        for (const url of BOOTSTRAP_RELAYS || []) {
            if (url && !seen.has(url)) { prioritized.push(url); seen.add(url); }
        }
        for (const url of this._shuffle(this.relays.slice())) {
            if (url && !seen.has(url)) { prioritized.push(url); seen.add(url); }
        }

        for (const relayUrl of prioritized) {
            const wsUrl = this._toWebSocketUrl(relayUrl);
            try {
                const success = await this._tryConnect(wsUrl);
                if (success) {
                    this.connectedRelay = relayUrl;
                    this.connected = true;
                    // If we already have a verified directory entry for this
                    // URL, propagate its pubkey for UI display.
                    const match = this.verifiedDirectory.find(v => v.url === relayUrl);
                    this.connectedRelayPubkey = match ? match.peerIdHex : null;
                    console.log('[RelayClient] Connected to relay:', relayUrl);
                    return relayUrl;
                }
            } catch (e) {
                console.debug('[RelayClient] Connection failed to', relayUrl, e.message);
            }
        }
        this.connected = false;
        this.connectedRelay = null;
        return null;
    }

    /**
     * Manually add a relay URL subject to authority verification.
     * Used from Settings → Relay. The URL is added to the known-relay pool
     * and its /directory is fetched; only descriptors whose endorsements
     * meet the authority threshold populate `verifiedDirectory`.
     * @param {string} url
     * @returns {Promise<boolean>} whether the URL produced any verified entries
     */
    async addManualRelay(url) {
        if (!url || typeof url !== 'string') return false;
        url = url.trim().replace(/\/$/, '');
        if (!url) return false;
        if (!this.relays.includes(url)) this.relays.push(url);
        try {
            await this.fetchDirectory(url);
        } catch (_) {
            return false;
        }
        // Only report success if the target's own descriptor is verified.
        return this.verifiedDirectory.some(v => v.url === url);
    }

    /**
     * Attempt a WebSocket connection with a timeout.
     * @param {string} wsUrl
     * @returns {Promise<boolean>}
     */
    _tryConnect(wsUrl) {
        return new Promise((resolve) => {
            const timeout = setTimeout(() => {
                try { ws.close(); } catch (_) {}
                resolve(false);
            }, 5000);

            let ws;
            try {
                ws = new WebSocket(wsUrl);
            } catch (_) {
                clearTimeout(timeout);
                resolve(false);
                return;
            }

            ws.onopen = () => {
                clearTimeout(timeout);
                ws.close();
                resolve(true);
            };
            ws.onerror = () => {
                clearTimeout(timeout);
                resolve(false);
            };
            ws.onclose = () => {
                clearTimeout(timeout);
                resolve(false);
            };
        });
    }

    /**
     * Convert an HTTP URL to a WebSocket URL with /ws path.
     * @param {string} httpUrl
     * @returns {string}
     */
    _toWebSocketUrl(httpUrl) {
        let url = httpUrl.replace(/\/$/, '');
        if (url.startsWith('https://')) {
            url = 'wss://' + url.slice(8);
        } else if (url.startsWith('http://')) {
            url = 'ws://' + url.slice(7);
        }
        return url + '/ws';
    }

    /**
     * Cache directory to localStorage.
     * @param {Object} directory - { relays: string[], fetchedAt: number }
     */
    cacheDirectory(directory) {
        try {
            localStorage.setItem(DIRECTORY_CACHE_KEY, JSON.stringify(directory));
        } catch (e) {
            console.debug('[RelayClient] Failed to cache directory:', e.message);
        }
    }

    /**
     * Load cached directory from localStorage.
     * Returns null if cache is missing or expired.
     * @returns {Object|null}
     */
    loadCachedDirectory() {
        try {
            const raw = localStorage.getItem(DIRECTORY_CACHE_KEY);
            if (!raw) return null;
            const parsed = JSON.parse(raw);
            if (!parsed || !parsed.fetchedAt) return null;
            // Check TTL
            if (Date.now() - parsed.fetchedAt > DIRECTORY_CACHE_TTL_MS) {
                localStorage.removeItem(DIRECTORY_CACHE_KEY);
                return null;
            }
            return parsed;
        } catch (e) {
            return null;
        }
    }

    /**
     * Add a bridge relay from a bridge address string.
     * Format: bridge:host:port[;front=domain][;fp=hex_fingerprint]
     * @param {string} bridgeString
     * @returns {Object} The parsed bridge entry
     */
    addBridge(bridgeString) {
        const bridge = this._parseBridgeString(bridgeString);
        // Avoid duplicates
        const existing = this.bridgeRelays.find(
            b => b.host === bridge.host && b.port === bridge.port
        );
        if (!existing) {
            this.bridgeRelays.push(bridge);
            console.log('[RelayClient] Added bridge relay:', bridge.wsUrl);
        }
        return bridge;
    }

    /**
     * Parse a bridge address string into an object.
     * Format: bridge:host:port[;front=domain][;fp=hex_fingerprint]
     * @param {string} s
     * @returns {Object} { host, port, front_domain, fingerprint, wsUrl }
     */
    _parseBridgeString(s) {
        s = s.trim();
        if (!s.startsWith('bridge:')) {
            throw new Error('Bridge string must start with "bridge:"');
        }
        const rest = s.slice('bridge:'.length);
        const parts = rest.split(';');
        const hostPort = parts[0];

        // Find last colon for port separator
        const lastColon = hostPort.lastIndexOf(':');
        if (lastColon < 0) {
            throw new Error('Bridge string missing port');
        }
        const host = hostPort.slice(0, lastColon);
        const port = parseInt(hostPort.slice(lastColon + 1), 10);
        if (!host || isNaN(port)) {
            throw new Error('Invalid bridge host:port');
        }

        let front_domain = null;
        let fingerprint = null;

        for (let i = 1; i < parts.length; i++) {
            const param = parts[i];
            if (param.startsWith('front=')) {
                front_domain = param.slice('front='.length);
            } else if (param.startsWith('fp=')) {
                fingerprint = param.slice('fp='.length);
            }
        }

        // Build WebSocket URL
        let wsUrl;
        if (front_domain) {
            wsUrl = 'wss://' + front_domain + '/ws';
        } else {
            wsUrl = 'wss://' + host + ':' + port + '/ws';
        }

        return { host, port, front_domain, fingerprint, wsUrl };
    }

    /**
     * Load bridge relays from IndexedDB settings.
     * @returns {Promise<void>}
     */
    async loadBridges() {
        try {
            if (typeof window === 'undefined' || !window.indexedDB) return;
            const bridges = await this._idbGet(BRIDGE_RELAYS_DB_KEY);
            if (Array.isArray(bridges) && bridges.length > 0) {
                this.bridgeRelays = bridges;
                console.log('[RelayClient] Loaded', bridges.length, 'bridge relays from IndexedDB');
            }
        } catch (e) {
            console.debug('[RelayClient] Failed to load bridges from IndexedDB:', e.message);
        }
    }

    /**
     * Save bridge relays to IndexedDB settings.
     * @returns {Promise<void>}
     */
    async saveBridges() {
        try {
            if (typeof window === 'undefined' || !window.indexedDB) return;
            await this._idbSet(BRIDGE_RELAYS_DB_KEY, this.bridgeRelays);
        } catch (e) {
            console.debug('[RelayClient] Failed to save bridges to IndexedDB:', e.message);
        }
    }

    /**
     * Read a value from IndexedDB 'parolnet_settings' store.
     * @param {string} key
     * @returns {Promise<any>}
     */
    _idbGet(key) {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open('parolnet_settings', 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings');
                }
            };
            req.onsuccess = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains('settings')) {
                    db.close();
                    resolve(null);
                    return;
                }
                const tx = db.transaction('settings', 'readonly');
                const store = tx.objectStore('settings');
                const getReq = store.get(key);
                getReq.onsuccess = () => resolve(getReq.result);
                getReq.onerror = () => reject(getReq.error);
                tx.oncomplete = () => db.close();
            };
            req.onerror = () => reject(req.error);
        });
    }

    /**
     * Write a value to IndexedDB 'parolnet_settings' store.
     * @param {string} key
     * @param {any} value
     * @returns {Promise<void>}
     */
    _idbSet(key, value) {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open('parolnet_settings', 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings');
                }
            };
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction('settings', 'readwrite');
                const store = tx.objectStore('settings');
                store.put(value, key);
                tx.oncomplete = () => { db.close(); resolve(); };
                tx.onerror = () => { db.close(); reject(tx.error); };
            };
            req.onerror = () => reject(req.error);
        });
    }

    /**
     * Get the number of known relays.
     * @returns {number}
     */
    get knownRelayCount() {
        return this.relays.length;
    }

    /**
     * Fisher-Yates shuffle (in-place).
     * @param {any[]} arr
     * @returns {any[]}
     */
    _shuffle(arr) {
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    }
}
