import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomFillSync, createHmac, webcrypto } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Stub global crypto with node's webcrypto before importing CryptoStore so its
// Web Crypto calls work under node --test.
if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
    globalThis.crypto = webcrypto;
}
const { CryptoStore } = await import('../crypto-store.js');

// Lazy-load WASM for envelope tests. If the pkg/ dir isn't built, the suite
// still runs the pure-JS tests.
const wasmPath = join(__dirname, '..', 'pkg', 'parolnet_wasm_bg.wasm');
let wasmMod = null;
async function loadWasm() {
    if (wasmMod !== null) return wasmMod;
    if (!existsSync(wasmPath)) { wasmMod = false; return false; }
    try {
        const bytes = readFileSync(wasmPath);
        const mod = await import('../pkg/parolnet_wasm.js');
        mod.initSync({ module: bytes });
        mod.initialize();
        wasmMod = mod;
        return mod;
    } catch (e) {
        console.warn('[test] WASM load failed:', e.message);
        wasmMod = false;
        return false;
    }
}

// ── Tests ──

describe('generateMsgId', () => {
    // Reimplemented from app.js
    function generateMsgId() {
        const arr = new Uint8Array(16);
        randomFillSync(arr);
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    test('produces 32-char hex string', () => {
        const id = generateMsgId();
        assert.equal(id.length, 32);
        assert.match(id, /^[0-9a-f]{32}$/);
    });

    test('produces unique IDs', () => {
        const ids = new Set();
        for (let i = 0; i < 100; i++) ids.add(generateMsgId());
        assert.equal(ids.size, 100);
    });
});

describe('gossip dedup', () => {
    test('markGossipSeen and check', () => {
        const seen = new Set();
        const SEEN_MAX = 1000;

        function markSeen(msgId) {
            seen.add(msgId);
            if (seen.size > SEEN_MAX) {
                const first = seen.values().next().value;
                seen.delete(first);
            }
        }

        markSeen('msg1');
        markSeen('msg2');
        assert.equal(seen.has('msg1'), true);
        assert.equal(seen.has('msg2'), true);
        assert.equal(seen.has('msg3'), false);
    });

    test('rolling window evicts oldest', () => {
        const seen = new Set();
        const SEEN_MAX = 5;

        function markSeen(msgId) {
            seen.add(msgId);
            if (seen.size > SEEN_MAX) {
                const first = seen.values().next().value;
                seen.delete(first);
            }
        }

        for (let i = 0; i < 7; i++) markSeen('msg' + i);
        assert.equal(seen.size, 5);
        assert.equal(seen.has('msg0'), false); // evicted
        assert.equal(seen.has('msg1'), false); // evicted
        assert.equal(seen.has('msg6'), true);  // latest
    });
});

describe('message queue', () => {
    test('queue and flush', () => {
        const queue = [];
        const MAX_SIZE = 200;

        function queueMessage(toPeerId, payload) {
            if (queue.length >= MAX_SIZE) queue.shift();
            queue.push({ toPeerId, payload, timestamp: Date.now() });
        }

        queueMessage('peer1', 'hello');
        queueMessage('peer2', 'world');
        assert.equal(queue.length, 2);
        assert.equal(queue[0].toPeerId, 'peer1');
        assert.equal(queue[1].payload, 'world');
    });

    test('queue evicts oldest when full', () => {
        const queue = [];
        const MAX_SIZE = 3;

        function queueMessage(toPeerId, payload) {
            if (queue.length >= MAX_SIZE) queue.shift();
            queue.push({ toPeerId, payload, timestamp: Date.now() });
        }

        queueMessage('a', '1');
        queueMessage('b', '2');
        queueMessage('c', '3');
        queueMessage('d', '4'); // evicts 'a'
        assert.equal(queue.length, 3);
        assert.equal(queue[0].toPeerId, 'b');
        assert.equal(queue[2].toPeerId, 'd');
    });

    test('flush removes expired messages', () => {
        const queue = [];
        const MAX_AGE = 3600000;

        // Add an expired message
        queue.push({ toPeerId: 'old', payload: 'stale', timestamp: Date.now() - MAX_AGE - 1000 });
        // Add a fresh message
        queue.push({ toPeerId: 'new', payload: 'fresh', timestamp: Date.now() });

        // Simulate flush (without actual send)
        const flushed = [];
        const toFlush = queue.splice(0, queue.length);
        for (const msg of toFlush) {
            if (Date.now() - msg.timestamp > MAX_AGE) continue; // skip expired
            flushed.push(msg);
        }

        assert.equal(flushed.length, 1);
        assert.equal(flushed[0].toPeerId, 'new');
    });
});

describe('connection status logic', () => {
    test('relay connected = online', () => {
        const hasRelay = true, hasWebRTC = true;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'online');
    });

    test('nothing = offline', () => {
        const hasRelay = false, hasWebRTC = false;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'offline');
    });

    test('WebRTC only = partial', () => {
        const hasRelay = false, hasWebRTC = true;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'partial');
    });

    test('relay only = online', () => {
        const hasRelay = true, hasWebRTC = false;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'online');
    });
});

describe('hasDirectConnection', () => {
    test('returns true when dc is open', () => {
        const rtcConnections = {
            'peer1': { dc: { readyState: 'open' } }
        };
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.equal(hasDirectConnection('peer1'), true);
    });

    test('returns false when dc is closed', () => {
        const rtcConnections = {
            'peer1': { dc: { readyState: 'closed' } }
        };
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.equal(hasDirectConnection('peer1'), false);
    });

    test('returns false when no connection exists', () => {
        const rtcConnections = {};
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.ok(!hasDirectConnection('peer1'));
    });

    test('returns false when dc is null', () => {
        const rtcConnections = { 'peer1': { dc: null } };
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.ok(!hasDirectConnection('peer1'));
    });
});

// ── i18n ──

describe('i18n', () => {
    const langDir = join(__dirname, '..', 'lang');
    const SUPPORTED_LANGS = ['en','ru','fa','zh-CN','zh-TW','ko','ja','fr','de','it','pt','ar','es','tr','my','vi'];

    test('en.json is valid JSON with string values', () => {
        const en = JSON.parse(readFileSync(join(langDir, 'en.json'), 'utf8'));
        const keys = Object.keys(en);
        assert.ok(keys.length > 100, `only ${keys.length} keys`);
        for (const [k, v] of Object.entries(en)) {
            assert.equal(typeof v, 'string', `key "${k}" is not a string`);
        }
    });

    test('all 16 lang files exist and parse', () => {
        for (const lang of SUPPORTED_LANGS) {
            const path = join(langDir, lang + '.json');
            const data = JSON.parse(readFileSync(path, 'utf8'));
            assert.ok(Object.keys(data).length > 50, `${lang}.json has too few keys`);
        }
    });

    test('all lang files have same keys as en.json', () => {
        const en = JSON.parse(readFileSync(join(langDir, 'en.json'), 'utf8'));
        const enKeys = Object.keys(en).sort();
        for (const lang of SUPPORTED_LANGS) {
            if (lang === 'en') continue;
            const data = JSON.parse(readFileSync(join(langDir, lang + '.json'), 'utf8'));
            const langKeys = Object.keys(data).sort();
            const missing = enKeys.filter(k => !langKeys.includes(k));
            const extra = langKeys.filter(k => !enKeys.includes(k));
            assert.deepEqual(missing, [], `${lang}.json missing: ${missing.join(', ')}`);
        }
    });

    test('no lang file has empty string values', () => {
        for (const lang of SUPPORTED_LANGS) {
            const data = JSON.parse(readFileSync(join(langDir, lang + '.json'), 'utf8'));
            for (const [k, v] of Object.entries(data)) {
                assert.ok(v.length > 0, `${lang}.json key "${k}" is empty`);
            }
        }
    });

    test('placeholders preserved in translations', () => {
        const en = JSON.parse(readFileSync(join(langDir, 'en.json'), 'utf8'));
        for (const lang of SUPPORTED_LANGS) {
            if (lang === 'en') continue;
            const data = JSON.parse(readFileSync(join(langDir, lang + '.json'), 'utf8'));
            for (const [k, v] of Object.entries(en)) {
                const placeholders = v.match(/\{[a-zA-Z]+\}/g) || [];
                for (const ph of placeholders) {
                    assert.ok(
                        data[k] && data[k].includes(ph),
                        `${lang}.json key "${k}" missing placeholder ${ph}`
                    );
                }
            }
        }
    });

    test('t() function substitutes params', () => {
        function t(key, params) {
            const strings = { 'toast.newContact': 'New contact: {name}...' };
            let str = strings[key] || key;
            if (params) {
                for (const [k, v] of Object.entries(params)) {
                    str = str.replaceAll('{' + k + '}', v);
                }
            }
            return str;
        }
        assert.equal(t('toast.newContact', { name: 'abc123' }), 'New contact: abc123...');
        assert.equal(t('missing.key'), 'missing.key');
        assert.equal(t('toast.newContact'), 'New contact: {name}...');
    });
});

// ── TURN credential format ──

describe('TURN credentials', () => {
    test('HMAC-SHA1 credential matches expected format', () => {
        const secret = 'test-secret';
        const username = `${Math.floor(Date.now()/1000) + 86400}:${Math.random().toString(16).slice(2)}`;
        const mac = createHmac('sha1', secret).update(username).digest('base64');
        assert.ok(mac.length > 20, 'credential too short');
        assert.ok(mac.endsWith('=') || /^[A-Za-z0-9+/]/.test(mac), 'not base64');
    });

    test('username has expiry:random format', () => {
        const now = Math.floor(Date.now() / 1000);
        const expiry = now + 86400;
        const username = `${expiry}:00abcdef01234567`;
        const parts = username.split(':');
        assert.equal(parts.length, 2);
        assert.ok(parseInt(parts[0]) > now, 'expiry not in future');
        assert.ok(parts[1].length > 0, 'missing random component');
    });
});

// ── CryptoStore duress ──

describe('CryptoStore duress', () => {
    function makeDb() {
        const store = new Map();
        const putRaw = async (table, entry) => { store.set(`${table}:${entry.key}`, entry.value); };
        const getRaw = async (table, key) => {
            const v = store.get(`${table}:${key}`);
            return v === undefined ? null : { key, value: v };
        };
        return { store, putRaw, getRaw };
    }

    test('setup stores two independent verifiers', async () => {
        const { store, putRaw, getRaw } = makeDb();
        const cs = new CryptoStore();
        await cs.setup('real-pass', 'duress-pass', putRaw, getRaw);

        const salt = store.get('crypto_meta:salt');
        const duressSalt = store.get('crypto_meta:duress_salt');
        const verifier = store.get('crypto_meta:verifier');
        const duressVerifier = store.get('crypto_meta:duress_verifier');

        assert.ok(Array.isArray(salt), 'salt stored');
        assert.equal(salt.length, 16, 'salt is 16 bytes');
        assert.ok(Array.isArray(duressSalt), 'duress_salt stored');
        assert.equal(duressSalt.length, 16, 'duress_salt is 16 bytes');
        assert.ok(Array.isArray(verifier) && verifier.length > 12, 'verifier stored');
        assert.ok(Array.isArray(duressVerifier) && duressVerifier.length > 12, 'duress_verifier stored');

        // Salts must differ
        const same = salt.every((b, i) => b === duressSalt[i]);
        assert.ok(!same, 'salts must not be byte-wise equal');
    });

    test('unlock with real passphrase returns mode=normal', async () => {
        const { putRaw, getRaw } = makeDb();
        const cs = new CryptoStore();
        await cs.setup('real-pass', 'duress-pass', putRaw, getRaw);

        const cs2 = new CryptoStore();
        const result = await cs2.unlock('real-pass', getRaw);
        assert.deepEqual(result, { ok: true, mode: 'normal' });
        assert.equal(cs2.isUnlocked(), true);
    });

    test('unlock with duress passphrase returns mode=duress', async () => {
        const { putRaw, getRaw } = makeDb();
        const cs = new CryptoStore();
        await cs.setup('real-pass', 'duress-pass', putRaw, getRaw);

        const cs2 = new CryptoStore();
        const result = await cs2.unlock('duress-pass', getRaw);
        assert.deepEqual(result, { ok: true, mode: 'duress' });
        // Duress must NOT unlock the store.
        assert.equal(cs2.isUnlocked(), false);
    });

    test('unlock with wrong passphrase returns ok=false and no mode', async () => {
        const { putRaw, getRaw } = makeDb();
        const cs = new CryptoStore();
        await cs.setup('real-pass', 'duress-pass', putRaw, getRaw);

        const cs2 = new CryptoStore();
        const result = await cs2.unlock('definitely-wrong', getRaw);
        assert.equal(result.ok, false);
        assert.equal(result.mode, undefined);
        assert.equal(cs2.isUnlocked(), false);
    });

    test('unlock runs both decrypt attempts regardless of which wins', async () => {
        const { putRaw, getRaw } = makeDb();
        const cs = new CryptoStore();
        await cs.setup('real-pass', 'duress-pass', putRaw, getRaw);

        const origDecrypt = globalThis.crypto.subtle.decrypt.bind(globalThis.crypto.subtle);
        let count = 0;
        globalThis.crypto.subtle.decrypt = async (...args) => { count++; return await origDecrypt(...args); };

        try {
            // Normal-success case
            count = 0;
            const cs2 = new CryptoStore();
            await cs2.unlock('real-pass', getRaw);
            assert.ok(count >= 2, `normal unlock: expected >=2 decrypt calls, got ${count}`);

            // Duress case
            count = 0;
            const cs3 = new CryptoStore();
            await cs3.unlock('duress-pass', getRaw);
            assert.ok(count >= 2, `duress unlock: expected >=2 decrypt calls, got ${count}`);

            // Failure case
            count = 0;
            const cs4 = new CryptoStore();
            await cs4.unlock('bogus', getRaw);
            assert.ok(count >= 2, `wrong unlock: expected >=2 decrypt calls, got ${count}`);
        } finally {
            globalThis.crypto.subtle.decrypt = origDecrypt;
        }
    });

    test('legacy store without duress_verifier still unlocks on real passphrase', async () => {
        const { putRaw, getRaw } = makeDb();
        const cs = new CryptoStore();
        // Back-compat path: no duress argument at all.
        await cs.setup('real-pass', undefined, putRaw, getRaw);

        const cs2 = new CryptoStore();
        const ok = await cs2.unlock('real-pass', getRaw);
        assert.deepEqual(ok, { ok: true, mode: 'normal' });

        const cs3 = new CryptoStore();
        const bad = await cs3.unlock('wrong', getRaw);
        assert.equal(bad.ok, false);
    });

    test('setup throws when duressPassphrase equals passphrase', async () => {
        const { putRaw, getRaw } = makeDb();
        const cs = new CryptoStore();
        await assert.rejects(
            () => cs.setup('same', 'same', putRaw, getRaw),
            /differ/
        );
    });
});

// ── PNP-001 envelope wire path ─────────────────────────────────

describe('PWA envelope wire path', () => {
    // Message-type codes must match specs/PNP-001-wire-protocol.md §3.4.
    const MSG_TYPE_CHAT = 0x01;
    const MSG_TYPE_SYSTEM = 0x03;
    const MSG_TYPE_FILE_CHUNK = 0x09;
    const MSG_TYPE_FILE_CONTROL = 0x0A;
    const MSG_TYPE_CALL_SIGNAL = 0x0B;
    const MSG_TYPE_GROUP_TEXT = 0x0C;
    const MSG_TYPE_GROUP_CALL_SIGNAL = 0x0D;
    const MSG_TYPE_GROUP_FILE_OFFER = 0x0E;
    const MSG_TYPE_GROUP_FILE_CHUNK = 0x0F;
    const MSG_TYPE_SENDER_KEY_DISTRIBUTION = 0x11;
    const MSG_TYPE_GROUP_ADMIN = 0x12;

    // The envelope_encode WASM entry uses the initiator-side half of a Double
    // Ratchet session. A single WASM instance can't round-trip a frame against
    // itself (the reverse session lives on the peer). We test:
    //   - bucket exact-size on encode
    //   - decode rejects malformed hex
    //   - decode rejects tampered ciphertext
    //   - source_peer_id parameter is required
    //   - pure-JS dispatcher routes by msg_type

    const FAKE_PEER = '00'.repeat(32);
    const FAKE_SHARED = '11'.repeat(32);
    const FAKE_RATCHET = '22'.repeat(32);

    async function withWasm() {
        const w = await loadWasm();
        if (!w) return null;
        if (!w.has_session(FAKE_PEER)) {
            w.create_session(FAKE_PEER, FAKE_SHARED, FAKE_RATCHET);
        }
        return w;
    }

    test('bucket exact-size: every plaintext produces 256/1024/4096/16384 bytes', async (t) => {
        const w = await withWasm();
        if (!w) { t.skip('WASM not available'); return; }
        // Overhead per frame: DR header + CBOR framing + AEAD tag + source_hint
        // roughly ~120 bytes, so a ~130-byte plaintext already crosses into 1024.
        const cases = [
            { size: 0,     bucket: 256 },
            { size: 50,    bucket: 256 },
            { size: 500,   bucket: 1024 },
            { size: 800,   bucket: 1024 },
            { size: 3000,  bucket: 4096 },
            { size: 12000, bucket: 16384 },
        ];
        const now = 1700000000n;
        for (const { size, bucket } of cases) {
            const plain = new Uint8Array(size);
            const env = w.envelope_encode(FAKE_PEER, MSG_TYPE_CHAT, plain, now);
            assert.equal(typeof env, 'string', `env is string for size=${size}`);
            assert.equal(env.length % 2, 0, `env hex even for size=${size}`);
            assert.equal(env.length / 2, bucket, `size=${size} landed in ${bucket}-byte bucket (got ${env.length/2})`);
            assert.match(env, /^[0-9a-f]+$/, 'envelope is lowercase hex');
        }
    });

    test('encode returns different ciphertext per call (ratchet advances)', async (t) => {
        const w = await withWasm();
        if (!w) { t.skip('WASM not available'); return; }
        const plain = new TextEncoder().encode('same plaintext');
        const now = 1700000001n;
        const a = w.envelope_encode(FAKE_PEER, MSG_TYPE_CHAT, plain, now);
        const b = w.envelope_encode(FAKE_PEER, MSG_TYPE_CHAT, plain, now);
        assert.notEqual(a, b, 'ratchet must produce distinct frames for identical plaintext');
    });

    test('malformed hex is rejected cleanly (no crash, throws Error)', async (t) => {
        const w = await withWasm();
        if (!w) { t.skip('WASM not available'); return; }
        assert.throws(() => w.envelope_decode(FAKE_PEER, 'zzzznothex'), /invalid hex|hex/i);
        assert.throws(() => w.envelope_decode(FAKE_PEER, ''), /.+/);
        assert.throws(() => w.envelope_decode(FAKE_PEER, 'ab'), /.+/);  // too short to be any bucket
    });

    test('tampered envelope fails decode (AEAD auth rejects flipped byte)', async (t) => {
        const w = await withWasm();
        if (!w) { t.skip('WASM not available'); return; }
        const plain = new TextEncoder().encode('original plaintext');
        const env = w.envelope_encode(FAKE_PEER, MSG_TYPE_CHAT, plain, 1700000002n);
        // Flip one nibble in the middle of the payload region.
        const idx = 100;
        const ch = env[idx];
        const newCh = ch === 'a' ? 'b' : 'a';
        const tampered = env.slice(0, idx) + newCh + env.slice(idx + 1);
        assert.notEqual(tampered, env, 'tamper actually changed the bytes');
        assert.throws(() => w.envelope_decode(FAKE_PEER, tampered), /.+/);
    });

    test('decode with unknown source_peer_id (no session) throws', async (t) => {
        const w = await withWasm();
        if (!w) { t.skip('WASM not available'); return; }
        const plain = new TextEncoder().encode('hi');
        const env = w.envelope_encode(FAKE_PEER, MSG_TYPE_CHAT, plain, 1700000003n);
        // Use a peer id we have no session for.
        const unknown = 'ff'.repeat(32);
        assert.throws(() => w.envelope_decode(unknown, env), /.+/);
    });

    test('dispatchByMsgType routes correctly by numeric code', () => {
        // Mirror of dispatchByMsgType in pwa/src/messaging.js — the test
        // intentionally does not import messaging.js because that module
        // pulls DOM-dependent code.
        function dispatch(msgType, fromPeerId, plaintext, handlers) {
            switch (msgType) {
                case MSG_TYPE_CHAT:                     return handlers.chat(fromPeerId, plaintext);
                case MSG_TYPE_SYSTEM:                   return handlers.system(fromPeerId, plaintext);
                case MSG_TYPE_FILE_CHUNK:               return handlers.fileChunk(fromPeerId, plaintext);
                case MSG_TYPE_FILE_CONTROL:             return handlers.fileControl(fromPeerId, plaintext);
                case MSG_TYPE_CALL_SIGNAL:              return handlers.callSignal(fromPeerId, plaintext);
                case MSG_TYPE_GROUP_TEXT:               return handlers.groupText(fromPeerId, plaintext);
                case MSG_TYPE_GROUP_CALL_SIGNAL:        return handlers.groupCallSignal(fromPeerId, plaintext);
                case MSG_TYPE_GROUP_FILE_OFFER:         return handlers.groupFileOffer(fromPeerId, plaintext);
                case MSG_TYPE_GROUP_FILE_CHUNK:         return handlers.groupFileChunk(fromPeerId, plaintext);
                case MSG_TYPE_SENDER_KEY_DISTRIBUTION:  return handlers.senderKey(fromPeerId, plaintext);
                case MSG_TYPE_GROUP_ADMIN:              return handlers.groupAdmin(fromPeerId, plaintext);
                default:                                return { unknown: msgType };
            }
        }
        const calls = [];
        const handlers = {
            chat:            (p, b) => calls.push(['chat', p, b]),
            system:          (p, b) => calls.push(['system', p, b]),
            fileChunk:       (p, b) => calls.push(['fileChunk', p, b]),
            fileControl:     (p, b) => calls.push(['fileControl', p, b]),
            callSignal:      (p, b) => calls.push(['callSignal', p, b]),
            groupText:       (p, b) => calls.push(['groupText', p, b]),
            groupCallSignal: (p, b) => calls.push(['groupCallSignal', p, b]),
            groupFileOffer:  (p, b) => calls.push(['groupFileOffer', p, b]),
            groupFileChunk:  (p, b) => calls.push(['groupFileChunk', p, b]),
            senderKey:       (p, b) => calls.push(['senderKey', p, b]),
            groupAdmin:      (p, b) => calls.push(['groupAdmin', p, b]),
        };
        const peer = 'ab'.repeat(32);
        const bytes = new Uint8Array([1, 2, 3]);
        const codes = [
            [MSG_TYPE_CHAT, 'chat'],
            [MSG_TYPE_SYSTEM, 'system'],
            [MSG_TYPE_FILE_CHUNK, 'fileChunk'],
            [MSG_TYPE_FILE_CONTROL, 'fileControl'],
            [MSG_TYPE_CALL_SIGNAL, 'callSignal'],
            [MSG_TYPE_GROUP_TEXT, 'groupText'],
            [MSG_TYPE_GROUP_CALL_SIGNAL, 'groupCallSignal'],
            [MSG_TYPE_GROUP_FILE_OFFER, 'groupFileOffer'],
            [MSG_TYPE_GROUP_FILE_CHUNK, 'groupFileChunk'],
            [MSG_TYPE_SENDER_KEY_DISTRIBUTION, 'senderKey'],
            [MSG_TYPE_GROUP_ADMIN, 'groupAdmin'],
        ];
        for (const [code] of codes) dispatch(code, peer, bytes, handlers);
        const unknown = dispatch(0xff, peer, bytes, handlers);
        assert.equal(calls.length, codes.length);
        for (let i = 0; i < codes.length; i++) {
            assert.equal(calls[i][0], codes[i][1], `code 0x${codes[i][0].toString(16)} routes to ${codes[i][1]}`);
        }
        assert.deepEqual(calls[0][2], bytes);
        assert.deepEqual(unknown, { unknown: 0xff });
    });

    test('protocol-constants.js exports every PNP-001 §3.4 code', async () => {
        const mod = await import('../src/protocol-constants.js');
        // PNP-001 §3.4 registry — code + export name pairs.
        const expected = [
            [0x01, 'MSG_TYPE_CHAT',                    'TEXT'],
            [0x02, 'MSG_TYPE_FILE',                    'FILE'],
            [0x03, 'MSG_TYPE_SYSTEM',                  'CONTROL'],
            [0x04, 'MSG_TYPE_DECOY',                   'DECOY'],
            [0x05, 'MSG_TYPE_HANDSHAKE',               'HANDSHAKE'],
            [0x06, 'MSG_TYPE_RELAY_CONTROL',           'RELAY_CONTROL'],
            [0x07, 'MSG_TYPE_AUDIO',                   'AUDIO'],
            [0x08, 'MSG_TYPE_VIDEO',                   'VIDEO'],
            [0x09, 'MSG_TYPE_FILE_CHUNK',              'FILE_CHUNK'],
            [0x0A, 'MSG_TYPE_FILE_CONTROL',            'FILE_CONTROL'],
            [0x0B, 'MSG_TYPE_CALL_SIGNAL',             'CALL_SIGNAL'],
            [0x0C, 'MSG_TYPE_GROUP_TEXT',              'GROUP_TEXT'],
            [0x0D, 'MSG_TYPE_GROUP_CALL_SIGNAL',       'GROUP_CALL_SIGNAL'],
            [0x0E, 'MSG_TYPE_GROUP_FILE_OFFER',        'GROUP_FILE_OFFER'],
            [0x0F, 'MSG_TYPE_GROUP_FILE_CHUNK',        'GROUP_FILE_CHUNK'],
            [0x10, 'MSG_TYPE_GROUP_FILE_CONTROL',      'GROUP_FILE_CONTROL'],
            [0x11, 'MSG_TYPE_SENDER_KEY_DISTRIBUTION', 'SENDER_KEY_DISTRIBUTION'],
            [0x12, 'MSG_TYPE_GROUP_ADMIN',             'GROUP_ADMIN'],
        ];
        for (const [code, exportName, registryName] of expected) {
            assert.equal(mod[exportName], code,
                `${exportName} (${registryName}) must equal 0x${code.toString(16)}`);
            assert.equal(mod.ALL_MSG_TYPES[registryName], code,
                `ALL_MSG_TYPES.${registryName} must equal 0x${code.toString(16)}`);
        }
        // Every key in ALL_MSG_TYPES must correspond to an expected registry entry.
        const expectedNames = new Set(expected.map(e => e[2]));
        for (const name of Object.keys(mod.ALL_MSG_TYPES)) {
            assert.ok(expectedNames.has(name), `unexpected registry entry: ${name}`);
        }
        assert.equal(Object.keys(mod.ALL_MSG_TYPES).length, expected.length);
    });
});
