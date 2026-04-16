// ParolNet PWA — Main Application
// Zero-dependency vanilla JS messaging app with calculator decoy mode.

import { CryptoStore } from './crypto-store.js';
import { exportData, importData, validateExport } from './data-export.js';
import { RelayClient } from './relay-client.js';
const cryptoStore = new CryptoStore();
const relayClient = new RelayClient();

// ── State ───────────────────────────────────────────────────
let wasm = null;
let currentView = 'loading';
let currentPeerId = null;
let currentCallId = null;
let currentGroupId = null;
let currentGroupCallId = null;
let incomingCallInfo = null; // { from, callId }
let localStream = null;
let platform = detectPlatform();
window._knownPeers = [];
// File receive tracking: fileId -> { name, size, chunksReceived, totalChunks, msgEl }
const pendingFileReceives = {};
// Group call participant poll interval
let groupCallPollInterval = null;

// ── Safe Math Parser (replaces eval/new Function) ──────────
function safeEval(expr) {
    // Remove anything that's not a number, operator, parenthesis, or decimal point
    const sanitized = expr.replace(/[^0-9+\-*/().]/g, '');
    if (!sanitized) return NaN;

    let pos = 0;

    function parseExpression() {
        let result = parseTerm();
        while (pos < sanitized.length && (sanitized[pos] === '+' || sanitized[pos] === '-')) {
            const op = sanitized[pos++];
            const term = parseTerm();
            result = op === '+' ? result + term : result - term;
        }
        return result;
    }

    function parseTerm() {
        let result = parseFactor();
        while (pos < sanitized.length && (sanitized[pos] === '*' || sanitized[pos] === '/')) {
            const op = sanitized[pos++];
            const factor = parseFactor();
            result = op === '*' ? result * factor : result / factor;
        }
        return result;
    }

    function parseFactor() {
        if (sanitized[pos] === '(') {
            pos++; // skip '('
            const result = parseExpression();
            pos++; // skip ')'
            return result;
        }
        // Handle negative numbers
        let negative = false;
        if (sanitized[pos] === '-') {
            negative = true;
            pos++;
        }
        let numStr = '';
        while (pos < sanitized.length && (sanitized[pos] >= '0' && sanitized[pos] <= '9' || sanitized[pos] === '.')) {
            numStr += sanitized[pos++];
        }
        const num = parseFloat(numStr);
        return negative ? -num : num;
    }

    try {
        const result = parseExpression();
        return isFinite(result) ? result : NaN;
    } catch {
        return NaN;
    }
}

// ── Platform Detection ──────────────────────────────────────
function detectPlatform() {
    const ua = navigator.userAgent;
    if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
    if (/Android/.test(ua)) return 'android';
    if (/Windows/.test(ua)) return 'windows';
    if (/Mac/.test(ua)) return 'macos';
    return 'default';
}

// ── Toast Notifications ─────────────────────────────────────
function showToast(message, duration = 3000) {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:12px 24px;border-radius:8px;font-size:14px;z-index:9999;pointer-events:none;max-width:80%;text-align:center;display:none;';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.display = 'block';
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => { toast.style.display = 'none'; }, duration);
}

// ── View Management ─────────────────────────────────────────
function showView(viewName) {
    // Stop camera when leaving add-contact view
    if (currentView === 'add-contact' && viewName !== 'add-contact') {
        stopQRScanner();
    }
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    const target = document.getElementById(`view-${viewName}`);
    if (target) {
        target.classList.remove('hidden');
    }
    currentView = viewName;

    // Render QR when entering add-contact view
    if (viewName === 'add-contact') {
        renderBootstrapQR();
    }

    // Refresh contact list when entering contacts view
    if (viewName === 'contacts') {
        loadContacts();
        loadGroups();
    }
}

// ── Calculator ──────────────────────────────────────────────
let calcDisplay = '0';
let calcExpression = '';
let calcBuffer = '';

// Configurable panic (kill) code — defaults to 999999.
// Users can change this in settings; stored in IndexedDB.
const DEFAULT_PANIC_CODE = '999999';
let panicCode = DEFAULT_PANIC_CODE;

async function loadPanicCode() {
    try {
        const saved = await dbGet('settings', 'panic_code');
        if (saved && saved.value && /^\d{4,10}$/.test(saved.value)) {
            panicCode = saved.value;
        }
    } catch (e) {
        console.warn('[Panic] Failed to load custom panic code:', e);
    }
}

async function setPanicCode(code) {
    if (!/^\d{4,10}$/.test(code)) {
        showToast('Panic code must be 4-10 digits');
        return false;
    }
    panicCode = code;
    await dbPut('settings', { key: 'panic_code', value: code });
    showToast('Panic code updated');
    return true;
}

async function resetPanicCode() {
    panicCode = DEFAULT_PANIC_CODE;
    try { await dbDelete('settings', 'panic_code'); } catch(e) {}
    showToast('Panic code reset to default');
}

async function calcPress(key) {
    if (key === 'C') {
        calcDisplay = '0';
        calcExpression = '';
        calcBuffer = '';
    } else if (key === '=') {
        // Check unlock code BEFORE showing result
        if (calcBuffer === panicCode) {
            // PANIC WIPE — immediate, no confirmation
            executePanicWipe();
            return;
        }
        if (wasm && wasm.is_decoy_enabled && wasm.is_decoy_enabled() &&
            wasm.verify_unlock_code && wasm.verify_unlock_code(calcBuffer)) {
            // Also unlock encrypted storage with the same code
            if (cryptoStore.isEnabled() && !cryptoStore.isUnlocked()) {
                try {
                    await cryptoStore.unlock(calcBuffer, dbGetRaw);
                } catch (e) {
                    console.warn('[Decoy] Crypto unlock failed:', e);
                }
            }
            showView('contacts');
            calcBuffer = '';
            return;
        }
        // Default unlock code check (no WASM fallback)
        if (!wasm && calcBuffer === '00000') {
            showView('contacts');
            calcBuffer = '';
            return;
        }
        // Normal calculation
        try {
            const result = safeEval(calcExpression);
            calcDisplay = String(!isNaN(result) ? result : 'Error');
        } catch {
            calcDisplay = 'Error';
        }
        calcExpression = '';
        calcBuffer = '';
    } else if ('0123456789'.includes(key)) {
        if (calcDisplay === '0' && calcExpression === '') {
            calcDisplay = key;
        } else {
            calcDisplay += key;
        }
        calcExpression += key;
        calcBuffer += key;
    } else if (key === '.') {
        calcDisplay += '.';
        calcExpression += '.';
    } else if ('+-\u00d7\u00f7'.includes(key)) {
        const op = key === '\u00d7' ? '*' : key === '\u00f7' ? '/' : key;
        calcExpression += op;
        calcDisplay += key;
        calcBuffer = ''; // reset buffer on operator
    } else if (key === '\u00b1') {
        if (calcDisplay.startsWith('-')) {
            calcDisplay = calcDisplay.slice(1);
        } else if (calcDisplay !== '0') {
            calcDisplay = '-' + calcDisplay;
        }
    } else if (key === '%') {
        calcExpression += '/100';
        try {
            const result = safeEval(calcExpression);
            if (!isNaN(result)) calcDisplay = String(result);
        } catch {
            // keep display as-is
        }
    }
    updateCalcDisplay();
}

function updateCalcDisplay() {
    const el = document.getElementById('calc-display');
    if (el) {
        // Truncate long displays
        let text = calcDisplay;
        if (text.length > 12) {
            const num = parseFloat(text);
            if (!isNaN(num)) {
                text = num.toPrecision(10);
            }
        }
        el.textContent = text;
    }
}

// ── IndexedDB Storage ──────────────────────────────────────
const DB_NAME = 'parolnet';
const DB_VERSION = 4;

function openDB() {
    return new Promise((resolve, reject) => {
        let resolved = false;
        const timeout = setTimeout(() => {
            if (!resolved) {
                resolved = true;
                reject(new Error('IndexedDB open timeout'));
            }
        }, 5000);

        try {
            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('contacts')) {
                    db.createObjectStore('contacts', { keyPath: 'peerId' });
                }
                if (!db.objectStoreNames.contains('messages')) {
                    const store = db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
                    store.createIndex('peerId', 'peerId', { unique: false });
                    store.createIndex('timestamp', 'timestamp', { unique: false });
                }
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings', { keyPath: 'key' });
                }
                if (!db.objectStoreNames.contains('crypto_meta')) {
                    db.createObjectStore('crypto_meta', { keyPath: 'key' });
                }
                if (!db.objectStoreNames.contains('groups')) {
                    db.createObjectStore('groups', { keyPath: 'groupId' });
                }
                if (!db.objectStoreNames.contains('group_messages')) {
                    const gmStore = db.createObjectStore('group_messages', { keyPath: 'id', autoIncrement: true });
                    gmStore.createIndex('groupId', 'groupId', { unique: false });
                    gmStore.createIndex('timestamp', 'timestamp', { unique: false });
                }
            };
            req.onsuccess = () => { if (!resolved) { resolved = true; clearTimeout(timeout); resolve(req.result); } };
            req.onerror = () => { if (!resolved) { resolved = true; clearTimeout(timeout); reject(req.error); } };
            req.onblocked = () => { if (!resolved) { resolved = true; clearTimeout(timeout); reject(new Error('IndexedDB blocked')); } };
        } catch(e) {
            if (!resolved) { resolved = true; clearTimeout(timeout); reject(e); }
        }
    });
}

async function dbGetAllRaw(storeName) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function dbPutRaw(storeName, item) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        const req = store.put(item);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function dbGetRaw(storeName, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const req = store.get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

// Stores that should be encrypted when crypto is active
const ENCRYPTED_STORES = new Set(['contacts', 'messages', 'settings', 'groups', 'group_messages']);

function getKeyField(storeName) {
    if (storeName === 'contacts') return 'peerId';
    if (storeName === 'messages') return 'id';
    if (storeName === 'settings') return 'key';
    if (storeName === 'crypto_meta') return 'key';
    if (storeName === 'groups') return 'groupId';
    if (storeName === 'group_messages') return 'id';
    return 'id';
}

// Encrypted wrappers
async function dbPut(storeName, item) {
    if (cryptoStore.isUnlocked() && ENCRYPTED_STORES.has(storeName)) {
        const keyField = getKeyField(storeName);
        const keyValue = item[keyField];
        const encrypted = await cryptoStore.encrypt(item);
        return dbPutRaw(storeName, { [keyField]: keyValue, _enc: Array.from(encrypted) });
    }
    return dbPutRaw(storeName, item);
}

async function dbGet(storeName, key) {
    const raw = await dbGetRaw(storeName, key);
    if (raw && raw._enc && cryptoStore.isUnlocked()) {
        return await cryptoStore.decrypt(new Uint8Array(raw._enc));
    }
    return raw;
}

async function dbGetAll(storeName) {
    const items = await dbGetAllRaw(storeName);
    if (!cryptoStore.isUnlocked() || !ENCRYPTED_STORES.has(storeName)) return items;
    const decrypted = [];
    for (const item of items) {
        if (item._enc) {
            try {
                decrypted.push(await cryptoStore.decrypt(new Uint8Array(item._enc)));
            } catch {
                // Skip items that fail to decrypt (corrupted or from different key)
                console.warn('Failed to decrypt item in', storeName);
            }
        } else {
            decrypted.push(item); // Plaintext item (pre-encryption or not encrypted)
        }
    }
    return decrypted;
}

async function dbGetByIndex(storeName, indexName, value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const index = store.index(indexName);
        const req = index.getAll(value);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function dbDelete(storeName, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        const req = store.delete(key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

async function dbClear(storeName) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        const req = store.clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

// ── Telemetry ──────────────────────────────────────────────
function isDevMode() {
    return !!(window.BUILD_INFO && window.BUILD_INFO.dev);
}

const telemetry = {
    sid: Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join(''),
    events: [],
    MAX_EVENTS: 500,

    track(type, meta) {
        if (!isDevMode()) return;
        if (this.events.length >= this.MAX_EVENTS) this.events.shift();
        this.events.push({ type, ts: Date.now(), meta: meta || null });
    },

    async flush() {
        if (!isDevMode()) return;
        if (this.events.length === 0) return;
        // Skip telemetry if no relay server is configured/connected
        const relayUrl = connMgr && connMgr.relayUrl;
        if (!relayUrl) return;
        // Convert WebSocket URL to HTTP base URL for telemetry endpoint
        const httpBase = relayUrl.replace(/^ws(s?):/, 'http$1:').replace(/\/ws\/?$/, '');
        const batch = {
            sid: this.sid,
            ts: Date.now(),
            events: this.events.splice(0, this.events.length)
        };
        try {
            const resp = await fetch(httpBase + '/telemetry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(batch)
            });
            if (!resp.ok) {
                // Put events back
                this.events.unshift(...batch.events);
                if (this.events.length > this.MAX_EVENTS) {
                    this.events.length = this.MAX_EVENTS;
                }
            }
        } catch(e) {
            // Network error — put events back
            this.events.unshift(...batch.events);
            if (this.events.length > this.MAX_EVENTS) {
                this.events.length = this.MAX_EVENTS;
            }
        }
    }
};

// Flush telemetry every 60 seconds
setInterval(() => telemetry.flush(), 60000);

// Flush on page hide (user navigating away)
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
        telemetry.flush();
    }
    telemetry.track(document.visibilityState === 'visible' ? 'app_visible' : 'app_hidden');
});

// ── WASM Loading ────────────────────────────────────────────
async function loadWasm() {
    const statusEl = document.getElementById('loading-status');
    try {
        if (statusEl) statusEl.textContent = 'Loading crypto module...';
        wasm = await import('./pkg/parolnet_wasm.js');
        if (statusEl) statusEl.textContent = 'Initializing...';
        // Cache-bust the WASM binary to prevent stale cached versions
        const wasmUrl = './pkg/parolnet_wasm_bg.wasm?v=' + Date.now();
        await wasm.default({ module_or_path: wasmUrl });
        if (statusEl) statusEl.textContent = 'Restoring identity...';
        telemetry.track('wasm_load_success');
        await onWasmReady();
    } catch (e) {
        console.warn('WASM not available:', e.message);
        telemetry.track('wasm_load_fail', { error: e.message });
        showToast('WASM load failed: ' + e.message);
        if (statusEl) statusEl.textContent = 'Running without crypto (' + e.message + ')';
        onWasmUnavailable();
    }
}

async function onWasmReady() {
    // Check if encryption is enabled
    const encEnabled = await cryptoStore.checkEnabled(dbGetRaw);
    if (encEnabled && !cryptoStore.isUnlocked()) {
        // Need to unlock before proceeding
        // If decoy mode is active, the calculator keypad handles unlock
        // Otherwise show the unlock view
        const decoyEnabled = wasm && wasm.is_decoy_enabled && wasm.is_decoy_enabled();
        if (!decoyEnabled) {
            showView('unlock');
            document.getElementById('loading-status').textContent = 'Encrypted — enter passphrase';
        }
        // Don't proceed with identity restore until unlocked
        return;
    }

    // Try to restore saved identity — with timeout so iOS IndexedDB hangs don't block
    let peerId = null;
    try {
        const saved = await Promise.race([
            dbGet('settings', 'identity_secret'),
            new Promise((_, reject) => setTimeout(() => reject(new Error('IndexedDB timeout')), 3000))
        ]);
        if (saved && saved.value && wasm.initialize_from_key) {
            peerId = wasm.initialize_from_key(saved.value);
            console.log('Identity restored:', peerId.slice(0, 16) + '...');
        }
    } catch(e) {
        console.warn('Identity restore skipped:', e.message);
    }

    // If no saved identity, generate new one and try to save it
    if (!peerId) {
        if (wasm.initialize) {
            peerId = wasm.initialize();
            console.log('New identity generated:', peerId.slice(0, 16) + '...');

            // Try to save — but don't block if IndexedDB is broken
            if (wasm.export_secret_key) {
                try {
                    const secretHex = wasm.export_secret_key();
                    await Promise.race([
                        dbPut('settings', { key: 'identity_secret', value: secretHex }),
                        new Promise(resolve => setTimeout(resolve, 2000))
                    ]);
                    console.log('Identity saved');
                } catch(e) {
                    console.warn('Identity save failed (non-fatal):', e.message);
                }
            }
        }
    }
    window._peerId = peerId || null;

    // Display peer ID in settings
    if (wasm.get_peer_id) {
        const peerId = wasm.get_peer_id();
        window._peerId = peerId || window._peerId;
        const el = document.getElementById('settings-peer-id');
        if (el) el.textContent = peerId || '-';
    }
    // Ensure SW relay knows the peer ID (covers the case where SW was
    // already connected before WASM finished loading)
    if (window._peerId) connMgr.registerPeer(window._peerId);

    if (wasm.version) {
        const el = document.getElementById('settings-version');
        if (el) el.textContent = wasm.version();
    }

    // Check if decoy mode is enabled
    if (wasm.is_decoy_enabled && wasm.is_decoy_enabled()) {
        showView('calculator');
        // Swap manifest so home screen shows calculator
        const manifestLink = document.getElementById('manifest-link');
        if (manifestLink) manifestLink.href = 'manifest-calculator.json';
    } else {
        showView('contacts');
    }
    loadContacts();
    // Pre-render QR code so it's ready when user opens Add Contact
    renderBootstrapQR();

    // Discover relays first, then start connection manager
    relayClient.discover().then(relays => {
        console.log('[App] Discovered', relays.length, 'relays');
        connMgr.start();
        updateConnectionStatus();
    }).catch(e => {
        console.warn('[App] Relay discovery failed, using defaults:', e.message);
        connMgr.start();
    });
}

async function attemptUnlock() {
    const input = document.getElementById('unlock-input');
    const passphrase = input ? input.value : '';
    if (!passphrase) return;

    try {
        await cryptoStore.unlock(passphrase, dbGetRaw);
        if (input) input.value = ''; // Clear passphrase from input
        showView('loading');
        document.getElementById('loading-status').textContent = 'Decrypting...';
        await onWasmReady(); // Re-run startup now that we're unlocked
    } catch (e) {
        showToast('Wrong passphrase');
        if (input) { input.value = ''; input.focus(); }
    }
}

function onWasmUnavailable() {
    // Show contacts view — calculator only shown when decoy mode is explicitly enabled
    showView('contacts');
    const el = document.getElementById('settings-version');
    if (el) el.textContent = 'dev (no WASM)';

    // Discover relays then start connection manager even without WASM
    relayClient.discover().then(() => {
        connMgr.start();
        updateConnectionStatus();
    }).catch(() => {
        connMgr.start();
    });
}

// ── Connection Status ─────────────────────────────────────
function updateConnectionStatus() {
    const dot = document.getElementById('connection-dot');
    if (!dot) return;

    const hasRelay = connMgr.isRelayConnected();
    const hasAnyWebRTC = Object.values(rtcConnections).some(c => c.dc && c.dc.readyState === 'open');

    if (hasRelay) {
        dot.className = 'connection-dot online';
        dot.title = 'Relay connected';
    } else if (hasAnyWebRTC) {
        dot.className = 'connection-dot partial';
        dot.title = 'Direct only';
    } else {
        dot.className = 'connection-dot offline';
        dot.title = 'Offline — messages will be queued';
    }
    updateNetworkSettings();
}

// ── Peer Discovery ─────────────────────────────────────────
let discoveryInterval = null;

async function discoverPeers() {
    try {
        const exclude = window._peerId || '';
        const resp = await fetch('/bootstrap?exclude=' + encodeURIComponent(exclude));
        if (!resp.ok) return;
        const peerIds = await resp.json();
        console.log('[Discovery]', peerIds.length, 'peers online');
        window._knownPeers = peerIds;

        // Attempt WebRTC to contacts who are online
        if (typeof RTCPeerConnection === 'undefined') return;
        let contacts;
        try { contacts = await dbGetAll('contacts'); } catch(e) { return; }
        const contactIds = new Set(contacts.map(c => c.peerId));

        for (const pid of peerIds) {
            if (contactIds.has(pid) && !hasDirectConnection(pid)) {
                initWebRTC(pid, true).catch(() => {});
            }
        }
    } catch(e) {
        console.warn('[Discovery] Failed:', e.message);
    }
}

function handleRelayMessage(msg) {
    switch (msg.type) {
        case 'registered':
            console.log('Registered with relay. Online peers:', msg.online_peers);
            discoverPeers();
            if (!discoveryInterval) discoveryInterval = setInterval(discoverPeers, 300000);
            break;

        case 'message':
            // Incoming message from another peer — check for structured payloads
            if (msg.payload && typeof msg.payload === 'string') {
                try {
                    const parsed = JSON.parse(msg.payload);
                    if (parsed && parsed._pn_type) {
                        handleStructuredMessage(msg.from, parsed);
                        break;
                    }
                } catch(e) {
                    // Not JSON — pass through to regular handler
                }
            }
            onIncomingMessage(msg.from, msg.payload);
            break;

        case 'queued':
            console.log('Message queued (peer offline)');
            showToast('Peer offline — message will be delivered when they connect');
            break;

        case 'rtc_offer':
            handleRTCOffer(msg.from, msg.payload).catch(e => console.warn('[WebRTC] offer error:', e));
            break;
        case 'rtc_answer':
            handleRTCAnswer(msg.from, msg.payload).catch(e => console.warn('[WebRTC] answer error:', e));
            break;
        case 'rtc_ice':
            handleRTCIce(msg.from, msg.payload).catch(e => console.warn('[WebRTC] ICE error:', e));
            break;

        case 'error':
            console.warn('Relay error:', msg.message);
            if (msg.message === 'peer not connected') {
                showToast('Peer is not online');
            }
            break;
    }
}

function handleStructuredMessage(fromPeerId, msg) {
    switch (msg._pn_type) {
        case 'file_offer':
            handleFileOffer({ ...msg, from: fromPeerId });
            break;
        case 'file_chunk':
            handleFileChunk(msg);
            break;
        case 'file_accept':
            handleFileAccept(msg);
            break;
        case 'call_offer':
            handleIncomingCall({ ...msg, from: fromPeerId });
            break;
        case 'call_reject':
            showToast('Call declined');
            break;
        case 'group_message':
            handleIncomingGroupMessage(msg);
            break;
        case 'group_invite':
            handleGroupInvite({ ...msg, from: fromPeerId });
            break;
        case 'group_call_invite':
            handleGroupCallInvite({ ...msg, from: fromPeerId });
            break;
        case 'group_file_offer':
            handleGroupFileOffer(msg);
            break;
        case 'group_file_chunk':
            handleGroupFileChunk(msg);
            break;
        case 'sender_key':
            handleSenderKey(msg, fromPeerId);
            break;
        default:
            console.warn('[Structured] Unknown message type:', msg._pn_type);
    }
}

// ── Group Management ───────────────────────────────────────

function switchListTab(tab) {
    document.querySelectorAll('.list-tab').forEach(t => t.classList.remove('active'));
    const btn = document.querySelector(`.list-tab[data-list="${tab}"]`);
    if (btn) btn.classList.add('active');
    const contactList = document.getElementById('contact-list');
    const groupList = document.getElementById('group-list');
    const addressBookList = document.getElementById('address-book-list');
    const createGroupBtn = document.getElementById('create-group-btn');
    // Hide all lists
    if (contactList) contactList.classList.add('hidden');
    if (groupList) groupList.classList.add('hidden');
    if (addressBookList) addressBookList.classList.add('hidden');
    if (createGroupBtn) createGroupBtn.classList.add('hidden');
    if (tab === 'groups') {
        if (groupList) groupList.classList.remove('hidden');
        if (createGroupBtn) createGroupBtn.classList.remove('hidden');
        loadGroups();
    } else if (tab === 'address-book') {
        if (addressBookList) addressBookList.classList.remove('hidden');
        loadAddressBook();
    } else {
        if (contactList) contactList.classList.remove('hidden');
        loadContacts();
    }
}

async function loadGroups() {
    try {
        const groups = await dbGetAll('groups');
        renderGroupList(groups);
    } catch (e) {
        console.warn('Failed to load groups:', e);
        renderGroupList([]);
    }
}

function renderGroupList(groups) {
    const list = document.getElementById('group-list');
    if (!list) return;
    if (!groups || groups.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No groups yet</p><p>Create or join a group</p></div>';
        return;
    }
    list.innerHTML = groups.map(g => `
        <div class="contact-item" onclick="openGroupChat('${escapeAttr(g.groupId)}')">
            <div class="contact-avatar">${escapeHtml((g.name || 'G')[0].toUpperCase())}</div>
            <div class="contact-info">
                <div class="contact-name" dir="auto">${escapeHtml(g.name || 'Unnamed Group')}</div>
                <div class="contact-last-msg" dir="auto">${escapeHtml(g.lastMessage || 'No messages yet')}</div>
            </div>
            <div class="contact-meta">
                <div class="contact-time">${escapeHtml(g.lastTime || '')}</div>
            </div>
        </div>
    `).join('');
}

function showCreateGroupDialog() {
    showView('create-group');
    const nameInput = document.getElementById('create-group-name');
    if (nameInput) { nameInput.value = ''; nameInput.focus(); }
}

async function createGroup() {
    const nameInput = document.getElementById('create-group-name');
    if (!nameInput) return;
    const name = nameInput.value.trim();
    if (!name) { showToast('Enter a group name'); return; }
    const groupId = 'grp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    const myPeerId = window._peerId || '';
    const group = {
        groupId,
        name,
        members: [myPeerId],
        createdBy: myPeerId,
        createdAt: Date.now(),
        lastMessage: '',
        lastTime: ''
    };
    try {
        await dbPut('groups', group);
        // Distribute sender key to self (initializes group encryption)
        if (wasm && wasm.create_sender_key) {
            try { wasm.create_sender_key(groupId); } catch(e) { console.warn('[Group] Sender key init:', e); }
        }
        showToast('Group created');
        openGroupChat(groupId);
    } catch (e) {
        showToast('Failed to create group');
        console.error('[Group] Create failed:', e);
    }
}

async function openGroupChat(groupId) {
    currentGroupId = groupId;
    showView('group-chat');
    const group = await dbGet('groups', groupId);
    const nameEl = document.getElementById('group-chat-name');
    if (nameEl) nameEl.textContent = group ? group.name : groupId.slice(0, 12);
    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl && group) badgeEl.textContent = (group.members || []).length;
    await loadGroupMessages(groupId);
}

async function loadGroupMessages(groupId) {
    const container = document.getElementById('group-message-list');
    if (!container) return;
    try {
        const messages = await dbGetByIndex('group_messages', 'groupId', groupId);
        messages.sort((a, b) => a.timestamp - b.timestamp);
        container.innerHTML = '';
        for (const m of messages) {
            appendGroupMessage(m);
        }
        container.scrollTop = container.scrollHeight;
    } catch (e) {
        console.warn('Failed to load group messages:', e);
        container.innerHTML = '';
    }
}

function appendGroupMessage(msg) {
    const container = document.getElementById('group-message-list');
    if (!container) return;
    const myPeerId = window._peerId || '';
    const isMine = msg.sender === myPeerId;
    const div = document.createElement('div');
    div.className = `message ${isMine ? 'sent' : 'received'}`;
    if (!isMine) {
        const senderLabel = document.createElement('div');
        senderLabel.className = 'group-msg-sender';
        senderLabel.textContent = (msg.sender || '').slice(0, 8) + '...';
        div.appendChild(senderLabel);
    }
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    if (msg.domContent) {
        bubble.appendChild(msg.domContent);
    } else {
        bubble.setAttribute('dir', 'auto');
        bubble.textContent = msg.content || '';
    }
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(msg.timestamp);
    div.appendChild(bubble);
    div.appendChild(time);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

async function sendGroupMessage() {
    const input = document.getElementById('group-message-input');
    if (!input) return;
    const text = input.value.trim();
    if (!text || !currentGroupId) return;

    const myPeerId = window._peerId || '';
    const msg = {
        groupId: currentGroupId,
        sender: myPeerId,
        content: text,
        timestamp: Date.now()
    };

    try { await dbPut('group_messages', msg); } catch(e) { console.warn(e); }
    appendGroupMessage(msg);
    input.value = '';

    // Send to all group members
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const payload = JSON.stringify({
        _pn_type: 'group_message',
        groupId: currentGroupId,
        sender: myPeerId,
        content: text,
        timestamp: msg.timestamp
    });
    for (const memberId of (group.members || [])) {
        if (memberId === myPeerId) continue;
        if (hasDirectConnection(memberId)) {
            sendViaWebRTC(memberId, payload);
        } else {
            sendToRelay(memberId, payload);
        }
    }

    // Update group last message
    group.lastMessage = text.slice(0, 50);
    group.lastTime = formatTime(Date.now());
    try { await dbPut('groups', group); } catch(e) {}
}

async function handleIncomingGroupMessage(msg) {
    if (!msg.groupId) return;
    const stored = {
        groupId: msg.groupId,
        sender: msg.sender || '',
        content: msg.content || '',
        timestamp: msg.timestamp || Date.now()
    };
    try { await dbPut('group_messages', stored); } catch(e) { console.warn(e); }

    // Update group last message
    try {
        const group = await dbGet('groups', msg.groupId);
        if (group) {
            group.lastMessage = (msg.content || '').slice(0, 50);
            group.lastTime = formatTime(Date.now());
            await dbPut('groups', group);
        }
    } catch(e) {}

    // If viewing this group, append to chat
    if (currentView === 'group-chat' && currentGroupId === msg.groupId) {
        appendGroupMessage(stored);
    } else {
        showToast('New group message');
        showLocalNotification('Group Message', (msg.content || '').slice(0, 100), msg.groupId);
    }
}

async function showGroupMembers() {
    const modal = document.getElementById('group-members-modal');
    if (!modal || !currentGroupId) return;
    modal.classList.remove('hidden');

    const group = await dbGet('groups', currentGroupId);
    const memberList = document.getElementById('group-members-list');
    if (!memberList || !group) return;
    const myPeerId = window._peerId || '';
    const isCreator = group.createdBy === myPeerId;

    memberList.innerHTML = (group.members || []).map(memberId => {
        const isMe = memberId === myPeerId;
        const shortId = memberId.slice(0, 12) + '...';
        const role = memberId === group.createdBy ? 'Creator' : 'Member';
        const removeBtn = isCreator && !isMe
            ? `<button class="group-member-remove" onclick="removeMemberFromGroup('${escapeAttr(memberId)}')">Remove</button>`
            : '';
        return `
            <div class="group-member-item">
                <div>
                    <div class="group-member-name">${escapeHtml(shortId)}${isMe ? ' (You)' : ''}</div>
                    <div class="group-member-role">${role}</div>
                </div>
                ${removeBtn}
            </div>
        `;
    }).join('');
}

function closeGroupMembers() {
    const modal = document.getElementById('group-members-modal');
    if (modal) modal.classList.add('hidden');
}

async function addMemberFromInput() {
    const input = document.getElementById('add-member-input');
    if (!input) return;
    const peerId = input.value.trim();
    if (!peerId) { showToast('Enter a peer ID'); return; }
    await addMemberToGroup(peerId);
    input.value = '';
}

async function addMemberToGroup(peerId) {
    if (!currentGroupId || !peerId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    if (group.members.includes(peerId)) { showToast('Already a member'); return; }
    group.members.push(peerId);
    await dbPut('groups', group);

    // Update member count badge
    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl) badgeEl.textContent = group.members.length;

    // Send invite to the new member
    const payload = JSON.stringify({
        _pn_type: 'group_invite',
        groupId: group.groupId,
        groupName: group.name,
        members: group.members
    });
    sendToRelay(peerId, payload);

    // Distribute sender key to new member
    if (wasm && wasm.create_sender_key) {
        try {
            const keyData = wasm.create_sender_key(currentGroupId);
            if (keyData) {
                const skPayload = JSON.stringify({
                    _pn_type: 'sender_key',
                    groupId: currentGroupId,
                    keyData: Array.from(new Uint8Array(keyData))
                });
                sendToRelay(peerId, skPayload);
            }
        } catch(e) { console.warn('[Group] Sender key distribution:', e); }
    }

    showToast('Member added');
    showGroupMembers(); // Refresh list
}

async function removeMemberFromGroup(peerId) {
    if (!currentGroupId || !peerId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    group.members = group.members.filter(m => m !== peerId);
    await dbPut('groups', group);

    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl) badgeEl.textContent = group.members.length;

    showToast('Member removed');
    showGroupMembers(); // Refresh list
}

async function leaveCurrentGroup() {
    if (!currentGroupId) return;
    try { await dbDelete('groups', currentGroupId); } catch(e) {}
    currentGroupId = null;
    closeGroupMembers();
    showView('contacts');
    switchListTab('groups');
    showToast('Left group');
}

async function handleGroupInvite(msg) {
    if (!msg.groupId || !msg.groupName) return;
    const myPeerId = window._peerId || '';
    const group = {
        groupId: msg.groupId,
        name: msg.groupName,
        members: msg.members || [msg.from, myPeerId],
        createdBy: msg.from,
        createdAt: Date.now(),
        lastMessage: '',
        lastTime: ''
    };
    try {
        await dbPut('groups', group);
        showToast('Invited to group: ' + msg.groupName);
        if (currentView === 'contacts') loadGroups();
    } catch(e) {
        console.warn('[Group] Invite save failed:', e);
    }
}

function handleSenderKey(msg, fromPeerId) {
    if (!msg.groupId || !msg.keyData) return;
    if (wasm && wasm.receive_sender_key) {
        try {
            const keyBytes = new Uint8Array(msg.keyData);
            wasm.receive_sender_key(msg.groupId, fromPeerId, keyBytes);
            console.log('[Group] Received sender key for', msg.groupId, 'from', fromPeerId.slice(0, 8));
        } catch(e) {
            console.warn('[Group] Sender key receive failed:', e);
        }
    }
}

// ── File Receive Flow ──────────────────────────────────────

function handleFileOffer(msg) {
    // msg: { from, fileId, fileName, fileSize, totalChunks }
    if (!msg.from || !msg.fileId) return;
    pendingFileReceives[msg.fileId] = {
        from: msg.from,
        name: msg.fileName || 'file',
        size: msg.fileSize || 0,
        totalChunks: msg.totalChunks || 1,
        chunksReceived: 0,
        chunks: [],
        accepted: false
    };
    // Show in chat if viewing this peer
    if (currentView === 'chat' && currentPeerId === msg.from) {
        showFileOfferInChat(msg);
    } else {
        showToast('File offered: ' + (msg.fileName || 'file'));
        showLocalNotification('File Offer', msg.fileName || 'file', msg.from);
    }
}

function showFileOfferInChat(msg) {
    const container = document.getElementById('message-list');
    if (!container) return;
    const div = document.createElement('div');
    div.className = 'message received';
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    const offer = document.createElement('div');
    offer.className = 'file-offer';
    offer.id = 'file-offer-' + msg.fileId;
    const nameEl = document.createElement('div');
    nameEl.className = 'file-offer-name';
    nameEl.textContent = msg.fileName || 'file';
    const sizeEl = document.createElement('div');
    sizeEl.className = 'file-offer-size';
    sizeEl.textContent = formatSize(msg.fileSize || 0);
    const actions = document.createElement('div');
    actions.className = 'file-offer-actions';
    const acceptBtn = document.createElement('button');
    acceptBtn.textContent = 'Accept';
    acceptBtn.className = 'call-action-btn accept';
    acceptBtn.onclick = () => acceptFileOffer(msg.fileId);
    const declineBtn = document.createElement('button');
    declineBtn.textContent = 'Decline';
    declineBtn.className = 'call-action-btn decline';
    declineBtn.onclick = () => declineFileOffer(msg.fileId);
    actions.appendChild(acceptBtn);
    actions.appendChild(declineBtn);
    offer.appendChild(nameEl);
    offer.appendChild(sizeEl);
    offer.appendChild(actions);
    bubble.appendChild(offer);
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(Date.now());
    div.appendChild(bubble);
    div.appendChild(time);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function acceptFileOffer(fileId) {
    const pending = pendingFileReceives[fileId];
    if (!pending) return;
    pending.accepted = true;
    // Update UI
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        const actions = offerEl.querySelector('.file-offer-actions');
        if (actions) actions.innerHTML = '<div class="file-status">Receiving... 0%</div>';
    }
    // Tell sender to start sending
    const payload = JSON.stringify({ _pn_type: 'file_accept', fileId });
    sendToRelay(pending.from, payload);
}

function declineFileOffer(fileId) {
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        const actions = offerEl.querySelector('.file-offer-actions');
        if (actions) actions.innerHTML = '<div class="file-status">Declined</div>';
    }
    delete pendingFileReceives[fileId];
}

function handleFileAccept(msg) {
    // Sender side: remote accepted, start chunked send
    if (!msg.fileId) return;
    console.log('[File] Peer accepted file:', msg.fileId);
    // The file data should have been stored when we initiated the transfer
    // Start sending chunks via sendFileChunked
    if (wasm && wasm.get_next_chunk) {
        sendFileChunked(msg.fileId, msg.from || currentPeerId);
    }
}

function handleFileChunk(msg) {
    // msg: { fileId, chunkIndex, totalChunks, data }
    const pending = pendingFileReceives[msg.fileId];
    if (!pending || !pending.accepted) return;
    pending.chunks[msg.chunkIndex] = msg.data;
    pending.chunksReceived++;
    const pct = Math.round((pending.chunksReceived / pending.totalChunks) * 100);
    // Update progress
    const offerEl = document.getElementById('file-offer-' + msg.fileId);
    if (offerEl) {
        const status = offerEl.querySelector('.file-status');
        if (status) status.textContent = 'Receiving... ' + pct + '%';
    }
    // Check if complete
    if (pending.chunksReceived >= pending.totalChunks) {
        offerDownload(msg.fileId);
    }
}

function offerDownload(fileId) {
    const pending = pendingFileReceives[fileId];
    if (!pending) return;
    // Combine chunks into a single blob
    const parts = [];
    for (let i = 0; i < pending.totalChunks; i++) {
        if (pending.chunks[i]) {
            // Data arrives as array of numbers (from JSON)
            const bytes = new Uint8Array(pending.chunks[i]);
            parts.push(bytes);
        }
    }
    const blob = new Blob(parts);
    const url = URL.createObjectURL(blob);
    // Replace progress with download link
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        offerEl.innerHTML = '';
        const nameEl = document.createElement('div');
        nameEl.className = 'file-offer-name';
        nameEl.textContent = pending.name;
        const link = document.createElement('a');
        link.className = 'file-download-link';
        link.href = url;
        link.download = pending.name;
        link.textContent = 'Download (' + formatSize(pending.size) + ')';
        offerEl.appendChild(nameEl);
        offerEl.appendChild(link);
    }
    delete pendingFileReceives[fileId];
}

async function sendFileChunked(fileId, toPeerId) {
    if (!toPeerId) return;
    const CHUNK_SIZE = 16384; // 16 KB chunks
    let chunkIndex = 0;
    if (wasm && wasm.get_next_chunk) {
        // Use WASM chunked API
        while (true) {
            try {
                const chunk = wasm.get_next_chunk(fileId);
                if (!chunk || chunk.length === 0) break;
                const payload = JSON.stringify({
                    _pn_type: 'file_chunk',
                    fileId,
                    chunkIndex,
                    totalChunks: -1, // Unknown until done
                    data: Array.from(chunk)
                });
                if (hasDirectConnection(toPeerId)) {
                    sendViaWebRTC(toPeerId, payload);
                } else {
                    sendToRelay(toPeerId, payload);
                }
                chunkIndex++;
                // Yield to event loop every 10 chunks
                if (chunkIndex % 10 === 0) {
                    await new Promise(r => setTimeout(r, 0));
                }
            } catch(e) {
                console.warn('[File] Chunk send error:', e);
                break;
            }
        }
    }
}

// ── Incoming Call Notification ──────────────────────────────

function handleIncomingCall(msg) {
    // msg: { from, callId }
    incomingCallInfo = { from: msg.from, callId: msg.callId };
    showIncomingCallNotification(msg.from, msg.callId);
}

function showIncomingCallNotification(fromPeerId, callId) {
    const notif = document.getElementById('incoming-call-notification');
    if (!notif) return;
    const nameEl = document.getElementById('incoming-call-name');
    if (nameEl) nameEl.textContent = fromPeerId.slice(0, 12) + '...';
    notif.classList.remove('hidden');
    showLocalNotification('Incoming Call', 'Call from ' + fromPeerId.slice(0, 12), fromPeerId);
}

function acceptIncomingCall() {
    if (!incomingCallInfo) return;
    if (incomingCallInfo.isGroup) {
        joinGroupCall();
        return;
    }
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    currentPeerId = incomingCallInfo.from;
    window.currentPeerId = incomingCallInfo.from;
    currentCallId = incomingCallInfo.callId;
    answerIncomingCall(incomingCallInfo.callId);
    showView('call');
    const nameEl = document.getElementById('call-peer-name');
    if (nameEl) nameEl.textContent = incomingCallInfo.from.slice(0, 16) + '...';
    incomingCallInfo = null;
}

function declineIncomingCall() {
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    if (!incomingCallInfo) return;
    // Notify caller
    const payload = JSON.stringify({ _pn_type: 'call_reject', callId: incomingCallInfo.callId });
    sendToRelay(incomingCallInfo.from, payload);
    incomingCallInfo = null;
}

// ── Group Calls ────────────────────────────────────────────

async function startGroupCall() {
    if (!currentGroupId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const callId = 'gcall-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
    currentGroupCallId = callId;

    // Request media
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch(e) {
        showToast('Could not access microphone: ' + e.message);
        return;
    }

    showGroupCallView(group.name, group.members);

    // Notify all group members
    const myPeerId = window._peerId || '';
    const payload = JSON.stringify({
        _pn_type: 'group_call_invite',
        groupId: currentGroupId,
        callId,
        groupName: group.name
    });
    for (const memberId of (group.members || [])) {
        if (memberId === myPeerId) continue;
        sendToRelay(memberId, payload);
    }
}

function showGroupCallView(groupName, members) {
    showView('group-call');
    const nameEl = document.getElementById('group-call-name');
    if (nameEl) nameEl.textContent = groupName || 'Group Call';

    const grid = document.getElementById('group-call-grid');
    if (!grid) return;
    grid.innerHTML = '';
    const myPeerId = window._peerId || '';

    // Add self tile
    const selfTile = document.createElement('div');
    selfTile.className = 'group-call-tile';
    selfTile.id = 'gcall-tile-self';
    const selfName = document.createElement('div');
    selfName.className = 'group-call-tile-name';
    selfName.textContent = 'You';
    selfTile.appendChild(selfName);
    grid.appendChild(selfTile);

    // Add tiles for other members (up to 7 others for 8 total)
    for (const memberId of (members || [])) {
        if (memberId === myPeerId) continue;
        if (grid.children.length >= 8) break;
        const tile = document.createElement('div');
        tile.className = 'group-call-tile';
        tile.id = 'gcall-tile-' + memberId.slice(0, 12);
        const tileName = document.createElement('div');
        tileName.className = 'group-call-tile-name';
        tileName.textContent = memberId.slice(0, 8) + '...';
        tile.appendChild(tileName);
        grid.appendChild(tile);
    }
}

function handleGroupCallInvite(msg) {
    if (!msg.groupId || !msg.callId) return;
    // Show incoming call notification for group call
    incomingCallInfo = { from: msg.from, callId: msg.callId, isGroup: true, groupId: msg.groupId, groupName: msg.groupName };
    const notif = document.getElementById('incoming-call-notification');
    if (!notif) return;
    const nameEl = document.getElementById('incoming-call-name');
    if (nameEl) nameEl.textContent = (msg.groupName || 'Group') + ' call';
    const labelEl = document.getElementById('incoming-call-label');
    if (labelEl) labelEl.textContent = 'Group call invitation';
    notif.classList.remove('hidden');
    showLocalNotification('Group Call', (msg.groupName || 'Group') + ' call', msg.from);
}

async function joinGroupCall() {
    if (!incomingCallInfo || !incomingCallInfo.isGroup) return;
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    currentGroupCallId = incomingCallInfo.callId;
    currentGroupId = incomingCallInfo.groupId;

    try {
        localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch(e) {
        showToast('Could not access microphone: ' + e.message);
        incomingCallInfo = null;
        return;
    }

    const group = await dbGet('groups', incomingCallInfo.groupId);
    showGroupCallView(incomingCallInfo.groupName || (group ? group.name : 'Group'), group ? group.members : [incomingCallInfo.from]);
    incomingCallInfo = null;
}

function leaveGroupCallUI() {
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        localStream = null;
    }
    if (groupCallPollInterval) {
        clearInterval(groupCallPollInterval);
        groupCallPollInterval = null;
    }
    currentGroupCallId = null;
    showView(currentGroupId ? 'group-chat' : 'contacts');
}

function toggleGroupMute() {
    if (!localStream) return;
    const audioTrack = localStream.getAudioTracks()[0];
    if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        const btn = document.querySelector('.group-call-controls .call-control-btn:first-child');
        if (btn) btn.textContent = audioTrack.enabled ? 'Mute' : 'Unmute';
    }
}

// ── Group File Transfer ────────────────────────────────────

function attachGroupFile() {
    const input = document.getElementById('group-file-input');
    if (input) input.click();
}

async function onGroupFileSelected(event) {
    const file = event.target.files[0];
    if (!file || !currentGroupId) return;
    event.target.value = ''; // Reset for re-select

    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const myPeerId = window._peerId || '';
    const fileId = 'gf-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);

    // Show sending status
    const msgEl = document.createElement('div');
    msgEl.className = 'file-transfer';
    msgEl.id = 'gfile-' + fileId;
    const nameEl = document.createElement('div');
    nameEl.className = 'file-name';
    nameEl.textContent = '\uD83D\uDCCE ' + file.name;
    const sizeEl = document.createElement('div');
    sizeEl.className = 'file-size';
    sizeEl.textContent = formatSize(file.size);
    const statusEl = document.createElement('div');
    statusEl.className = 'file-status';
    statusEl.textContent = 'Sending to group...';
    msgEl.appendChild(nameEl);
    msgEl.appendChild(sizeEl);
    msgEl.appendChild(statusEl);
    appendGroupMessage({ sender: myPeerId, domContent: msgEl, timestamp: Date.now(), groupId: currentGroupId });

    // Read and send as offer + chunks to each member
    try {
        const buffer = await file.arrayBuffer();
        const data = new Uint8Array(buffer);
        const CHUNK_SIZE = 16384;
        const totalChunks = Math.ceil(data.length / CHUNK_SIZE);

        for (const memberId of (group.members || [])) {
            if (memberId === myPeerId) continue;
            // Send offer
            const offerPayload = JSON.stringify({
                _pn_type: 'group_file_offer',
                groupId: currentGroupId,
                fileId,
                fileName: file.name,
                fileSize: file.size,
                totalChunks,
                sender: myPeerId
            });
            sendToRelay(memberId, offerPayload);

            // Send chunks
            for (let i = 0; i < totalChunks; i++) {
                const chunk = data.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
                const chunkPayload = JSON.stringify({
                    _pn_type: 'group_file_chunk',
                    groupId: currentGroupId,
                    fileId,
                    chunkIndex: i,
                    totalChunks,
                    data: Array.from(chunk)
                });
                if (hasDirectConnection(memberId)) {
                    sendViaWebRTC(memberId, chunkPayload);
                } else {
                    sendToRelay(memberId, chunkPayload);
                }
                // Yield periodically
                if (i % 10 === 0 && i > 0) {
                    await new Promise(r => setTimeout(r, 0));
                }
            }
        }
        statusEl.textContent = 'Sent';
    } catch(e) {
        statusEl.textContent = 'Failed: ' + e.message;
        console.error('[GroupFile] Send failed:', e);
    }
}

function handleGroupFileOffer(msg) {
    if (!msg.fileId || !msg.groupId) return;
    pendingFileReceives[msg.fileId] = {
        from: msg.sender || '',
        name: msg.fileName || 'file',
        size: msg.fileSize || 0,
        totalChunks: msg.totalChunks || 1,
        chunksReceived: 0,
        chunks: [],
        accepted: true, // Auto-accept group files
        isGroup: true,
        groupId: msg.groupId
    };
    // Show in group chat if viewing
    if (currentView === 'group-chat' && currentGroupId === msg.groupId) {
        const offerDiv = document.createElement('div');
        offerDiv.className = 'file-offer';
        offerDiv.id = 'file-offer-' + msg.fileId;
        const nameEl = document.createElement('div');
        nameEl.className = 'file-offer-name';
        nameEl.textContent = msg.fileName || 'file';
        const sizeEl = document.createElement('div');
        sizeEl.className = 'file-offer-size';
        sizeEl.textContent = formatSize(msg.fileSize || 0);
        const statusEl = document.createElement('div');
        statusEl.className = 'file-status';
        statusEl.textContent = 'Receiving... 0%';
        offerDiv.appendChild(nameEl);
        offerDiv.appendChild(sizeEl);
        offerDiv.appendChild(statusEl);
        appendGroupMessage({
            sender: msg.sender || '',
            domContent: offerDiv,
            timestamp: Date.now(),
            groupId: msg.groupId
        });
    }
}

function handleGroupFileChunk(msg) {
    // Reuse same logic as 1:1 file chunk
    const pending = pendingFileReceives[msg.fileId];
    if (!pending) return;
    pending.chunks[msg.chunkIndex] = msg.data;
    pending.chunksReceived++;
    const pct = Math.round((pending.chunksReceived / pending.totalChunks) * 100);
    const offerEl = document.getElementById('file-offer-' + msg.fileId);
    if (offerEl) {
        const status = offerEl.querySelector('.file-status');
        if (status) status.textContent = 'Receiving... ' + pct + '%';
    }
    if (pending.chunksReceived >= pending.totalChunks) {
        offerDownload(msg.fileId);
    }
}

function onIncomingMessage(fromPeerId, payload) {
    if (!fromPeerId || !payload) return;

    // Dedup: create a hash of the message to avoid duplicate display
    const dedupKey = fromPeerId + ':' + (typeof payload === 'string' ? payload.slice(0, 64) : '');
    if (seenGossipMessages.has(dedupKey)) return;
    markGossipSeen(dedupKey);

    // Handle system events (not displayed as chat messages)
    if (typeof payload === 'string' && payload.startsWith('__system:')) {
        console.log('[System]', fromPeerId.slice(0, 8), payload);
        if (payload === '__system:contact_added') {
            // Someone added us as a contact — add them back
            dbPut('contacts', {
                peerId: fromPeerId,
                name: fromPeerId.slice(0, 8) + '...',
                lastMessage: '',
                lastTime: formatTime(Date.now()),
                unread: 0
            }).then(() => {
                showToast('New contact: ' + fromPeerId.slice(0, 8) + '...');
                loadContacts();
            }).catch(() => {});
        } else if (payload.startsWith('__system:bootstrap:')) {
            // Bootstrap handshake from a scanner — contains their identity key
            const theirIkHex = payload.slice('__system:bootstrap:'.length);
            if (wasm && wasm.complete_bootstrap_as_presenter && theirIkHex.length === 64) {
                try {
                    const result = wasm.complete_bootstrap_as_presenter(theirIkHex);
                    console.log('[Bootstrap] Responder session established for:', result.peer_id);
                    // Add scanner as contact (using their PeerId from the result)
                    dbPut('contacts', {
                        peerId: result.peer_id,
                        name: result.peer_id.slice(0, 8) + '...',
                        lastMessage: 'Encrypted session established',
                        lastTime: formatTime(Date.now()),
                        unread: 0
                    }).then(async () => {
                        showToast('Secure contact: ' + result.peer_id.slice(0, 8) + '...');
                        loadContacts();
                    }).catch(() => {});
                } catch(e) {
                    console.warn('[Bootstrap] Failed to complete presenter bootstrap:', e);
                }
            }
        }
        return;
    }

    // Privacy: message_received telemetry removed — leaks activity metadata

    // Attempt decryption if payload is encrypted
    let messageText = payload;
    if (typeof payload === 'string' && payload.startsWith('enc:')) {
        if (wasm && wasm.decrypt_message) {
            try {
                const hexCiphertext = payload.slice(4);
                const cipherBytes = new Uint8Array(hexCiphertext.match(/.{1,2}/g).map(b => parseInt(b, 16)));
                const plainBytes = wasm.decrypt_message(fromPeerId, cipherBytes);
                const decoder = new TextDecoder();
                messageText = decoder.decode(plainBytes);
            } catch (e) {
                console.error('[Decrypt] Failed to decrypt from', fromPeerId.slice(0, 8), e);
                messageText = '[Encrypted message — decryption failed]';
            }
        } else {
            messageText = '[Encrypted message — WASM not available]';
        }
    }

    // Store the message
    const msg = {
        peerId: fromPeerId,
        direction: 'received',
        content: messageText,
        timestamp: Date.now()
    };

    dbPut('messages', msg).catch(e => console.warn('Failed to store message:', e));

    // Update or create contact
    dbPut('contacts', {
        peerId: fromPeerId,
        name: fromPeerId.slice(0, 8) + '...',
        lastMessage: messageText.slice(0, 50),
        lastTime: formatTime(Date.now()),
        unread: 1
    }).catch(() => {});

    // If we're viewing this peer's chat, show the message immediately
    if (currentView === 'chat' && currentPeerId === fromPeerId) {
        appendMessage(msg);
    } else {
        // Show notification
        showLocalNotification('New Message', messageText.slice(0, 100), fromPeerId);
        showToast('Message from ' + fromPeerId.slice(0, 8) + '...');
        // Refresh contact list if visible
        if (currentView === 'contacts') {
            loadContacts();
        }
    }
}

function sendToRelay(toPeerId, payload) {
    return connMgr.sendRelay(toPeerId, payload);
}

// ── WebRTC Peer Connections ────────────────────────────────
const rtcConnections = {}; // peerId -> { pc: RTCPeerConnection, dc: RTCDataChannel, status: 'connecting'|'open'|'closed' }

// WARNING: Public STUN servers leak your real IP address to the STUN provider.
// In high-threat environments, consider using a self-hosted STUN/TURN server
// or disabling WebRTC entirely and relying on relay-only connectivity.
// STUN requests reveal your public IP even behind a VPN if WebRTC is active.
const DEFAULT_STUN_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
];

// Configurable STUN/TURN servers. Loaded from IndexedDB at startup.
// Users can override these in settings to use self-hosted servers.
let customIceServers = null;

// Privacy mode: when enabled, only relay (TURN) candidates are used.
// This prevents IP leakage via WebRTC ICE but requires a TURN server.
let webrtcPrivacyMode = true; // Default ON for censorship-resistance threat model

function getRtcConfig() {
    const config = {
        iceServers: customIceServers || DEFAULT_STUN_SERVERS
    };
    if (webrtcPrivacyMode) {
        config.iceTransportPolicy = 'relay';
    }
    return config;
}

async function loadCustomStunServers() {
    try {
        const saved = await dbGet('settings', 'custom_stun_servers');
        if (saved && saved.value) {
            customIceServers = JSON.parse(saved.value);
        }
    } catch (e) {
        console.warn('[WebRTC] Failed to load custom STUN servers:', e);
    }
    // Load privacy mode setting
    try {
        const privacySetting = await dbGet('settings', 'webrtc_privacy_mode');
        if (privacySetting) {
            webrtcPrivacyMode = privacySetting.value !== 'false';
        }
    } catch (e) {
        console.warn('[WebRTC] Failed to load privacy mode setting:', e);
    }
    // Auto-fetch TURN credentials from relay
    fetchTurnCredentials().catch(() => {});
}

async function setCustomStunServers(serversJson) {
    try {
        const servers = JSON.parse(serversJson);
        if (!Array.isArray(servers) || servers.length === 0) {
            throw new Error('Expected a non-empty array of ICE servers');
        }
        // Basic validation: each entry should have a urls property
        for (const s of servers) {
            if (!s.urls && !s.url) {
                throw new Error('Each ICE server entry must have a "urls" property');
            }
        }
        customIceServers = servers;
        await dbPut('settings', { key: 'custom_stun_servers', value: JSON.stringify(servers) });
        showToast('Custom STUN/TURN servers saved');
    } catch (e) {
        showToast('Invalid ICE server config: ' + e.message);
    }
}

async function clearCustomStunServers() {
    customIceServers = null;
    try { await dbDelete('settings', 'custom_stun_servers'); } catch(e) {}
    showToast('STUN/TURN servers reset to defaults');
}

async function setWebRTCPrivacyMode(enabled) {
    webrtcPrivacyMode = enabled;
    await dbPut('settings', { key: 'webrtc_privacy_mode', value: String(enabled) });
    // Close existing connections so new ones use updated config
    Object.keys(rtcConnections).forEach(cleanupRTC);
    updateWebRTCPrivacyUI();
}

function updateWebRTCPrivacyUI() {
    const toggle = document.getElementById('webrtc-privacy-toggle');
    if (toggle) toggle.checked = webrtcPrivacyMode;
    const warning = document.getElementById('webrtc-privacy-warning');
    if (warning) {
        const hasTurn = customIceServers && customIceServers.some(s => {
            const u = s.urls || s.url || '';
            return u.startsWith('turn:') || u.startsWith('turns:');
        });
        if (webrtcPrivacyMode && !hasTurn) {
            warning.textContent = 'WebRTC disabled \u2014 no TURN servers configured. Configure TURN servers or disable privacy mode to enable peer-to-peer connections.';
            warning.style.display = 'block';
        } else {
            warning.style.display = 'none';
        }
    }
}

async function fetchTurnCredentials() {
    try {
        const relayUrl = connMgr && connMgr.relayUrl;
        if (!relayUrl) return;
        const httpUrl = relayUrl.replace(/^ws(s?):/, 'http$1:').replace(/\/ws\/?$/, '');
        const resp = await fetch(httpUrl + '/turn-credentials');
        if (resp.ok) {
            const creds = await resp.json();
            if (creds.uris && creds.uris.length > 0) {
                const turnServers = creds.uris.map(uri => ({
                    urls: uri,
                    username: creds.username,
                    credential: creds.credential
                }));
                // Merge TURN servers with existing ICE servers if none manually configured
                if (!customIceServers) {
                    customIceServers = [...DEFAULT_STUN_SERVERS, ...turnServers];
                }
                console.log('[WebRTC] Fetched TURN credentials, TTL:', creds.ttl);
            }
        }
    } catch (e) {
        console.warn('[WebRTC] Could not fetch TURN credentials:', e);
    }
}

async function initWebRTC(peerId, isInitiator) {
    if (rtcConnections[peerId] && rtcConnections[peerId].status === 'open') return;

    const pc = new RTCPeerConnection(getRtcConfig());
    rtcConnections[peerId] = { pc, dc: null, status: 'connecting' };

    // ICE candidate handling — filter candidates in privacy mode
    pc.onicecandidate = (event) => {
        if (event.candidate) {
            if (webrtcPrivacyMode) {
                const candidateStr = event.candidate.candidate || '';
                if (candidateStr.includes('typ host') || candidateStr.includes('typ srflx')) {
                    console.debug('[WebRTC] Privacy mode: filtered non-relay candidate:', candidateStr);
                    return;
                }
            }
            connMgr.sendSignaling('rtc_ice', peerId, JSON.stringify(event.candidate));
        }
    };

    pc.onconnectionstatechange = () => {
        console.log('[WebRTC]', peerId.slice(0,8), 'state:', pc.connectionState);
        if (pc.connectionState === 'failed') {
            telemetry.track('webrtc_connect_fail');
        }
        if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
            cleanupRTC(peerId);
            // Auto-reconnect after backoff (only if we were the initiator)
            if (isInitiator) {
                const delay = 2000 + Math.random() * 3000; // 2-5s jitter
                setTimeout(() => {
                    console.log('[WebRTC] Auto-reconnecting to', peerId.slice(0,8));
                    initWebRTC(peerId, true).catch(e =>
                        console.warn('[WebRTC] Reconnect failed:', e)
                    );
                }, delay);
            }
        } else if (pc.connectionState === 'closed') {
            cleanupRTC(peerId);
            // no reconnect — intentional close
        }
    };

    if (isInitiator) {
        // Create data channel
        const dc = pc.createDataChannel('parolnet', { ordered: true });
        setupDataChannel(peerId, dc);

        // Create and send offer
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        connMgr.sendSignaling('rtc_offer', peerId, JSON.stringify(offer));
    } else {
        // Wait for data channel from remote
        pc.ondatachannel = (event) => {
            setupDataChannel(peerId, event.channel);
        };
    }
}

function setupDataChannel(peerId, dc) {
    rtcConnections[peerId].dc = dc;

    dc.onopen = () => {
        console.log('[WebRTC] Data channel open with', peerId.slice(0,8));
        // Send identity for WebRTC connections
        try {
            dc.send(JSON.stringify({ type: 'identity', peerId: window._peerId }));
        } catch(e) {}
        // Privacy: webrtc_connect_success telemetry removed — leaks activity metadata
        rtcConnections[peerId].status = 'open';
        updatePeerConnectionUI(peerId, 'direct');
        flushMessageQueue();
    };

    dc.onclose = () => {
        console.log('[WebRTC] Data channel closed with', peerId.slice(0,8));
        cleanupRTC(peerId);
        updatePeerConnectionUI(peerId, 'relay');
    };

    dc.onmessage = (event) => {
        // Received message via WebRTC data channel
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'identity' && msg.peerId) {
                // Map temporary ID to full PeerId
                const fullPeerId = msg.peerId;
                if (peerId !== fullPeerId && (peerId.startsWith('pending_') || fullPeerId.startsWith(peerId.slice(0, 40)))) {
                    // Remap the connection from temporary/truncated ID to full PeerId
                    const conn = rtcConnections[peerId];
                    if (conn) {
                        delete rtcConnections[peerId];
                        rtcConnections[fullPeerId] = conn;
                        console.log('[Identity] Mapped', peerId.slice(0,8), '\u2192', fullPeerId.slice(0,8));
                    }
                }
            } else if (msg.type === 'chat') {
                onIncomingMessage(peerId, msg.payload);
            } else if (msg.type === 'gossip') {
                // Gossip message — check if for us, forward if not seen
                if (!msg.msgId || !msg.payload || seenGossipMessages.has(msg.msgId)) return;

                const isForUs = !msg.to || msg.to === window._peerId;
                if (isForUs) {
                    onIncomingMessage(msg.from || peerId, msg.payload);
                }

                // Forward if TTL allows
                if (msg.ttl > 0) {
                    gossipForward(peerId, msg.msgId, msg.to, msg.payload, msg.ttl - 1);
                }
            }
        } catch(e) {
            // Raw string message
            onIncomingMessage(peerId, event.data);
        }
    };
}

async function handleRTCOffer(fromPeerId, offerJson) {
    await initWebRTC(fromPeerId, false);
    const pc = rtcConnections[fromPeerId]?.pc;
    if (!pc) return;

    const offer = JSON.parse(offerJson);
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    connMgr.sendSignaling('rtc_answer', fromPeerId, JSON.stringify(answer));
}

async function handleRTCAnswer(fromPeerId, answerJson) {
    const pc = rtcConnections[fromPeerId]?.pc;
    if (!pc) return;
    const answer = JSON.parse(answerJson);
    await pc.setRemoteDescription(new RTCSessionDescription(answer));
}

async function handleRTCIce(fromPeerId, candidateJson) {
    const pc = rtcConnections[fromPeerId]?.pc;
    if (!pc) return;
    const candidate = JSON.parse(candidateJson);
    await pc.addIceCandidate(new RTCIceCandidate(candidate));
}

function sendViaWebRTC(peerId, payload) {
    const conn = rtcConnections[peerId];
    if (conn && conn.dc && conn.dc.readyState === 'open') {
        conn.dc.send(JSON.stringify({ type: 'chat', payload: payload }));
        return true;
    }
    return false;
}

function cleanupRTC(peerId) {
    const conn = rtcConnections[peerId];
    if (conn) {
        if (conn.dc) try { conn.dc.close(); } catch(e) {}
        if (conn.pc) try { conn.pc.close(); } catch(e) {}
        conn.status = 'closed';
    }
    delete rtcConnections[peerId];
}

function updatePeerConnectionUI(peerId, type) {
    // Update UI to show connection type — find the connection dot if in chat with this peer
    if (currentView === 'chat' && currentPeerId === peerId) {
        const dot = document.getElementById('connection-dot');
        if (dot) {
            dot.className = 'connection-dot online';
            dot.title = type === 'direct' ? 'Direct (WebRTC)' : 'Relay';
        }
    }
}

function hasDirectConnection(peerId) {
    const conn = rtcConnections[peerId];
    return conn && conn.dc && conn.dc.readyState === 'open';
}

// ── Connection Manager ─────────────────────────────────────
// WebSocket lives in the Service Worker so it persists when
// the page is backgrounded. connMgr delegates all WS ops via
// postMessage to the SW; status comes back via relay_status.
const connMgr = {
    relayUrl: null,
    _swRelayConnected: false,
    _discoveredRelays: [],
    _currentRelayIndex: 0,

    _swPost(msg) {
        const sw = navigator.serviceWorker && navigator.serviceWorker.controller;
        if (sw) {
            sw.postMessage(msg);
        } else if (navigator.serviceWorker) {
            // SW not yet controlling this page (first install) — send once it's ready
            navigator.serviceWorker.ready.then(reg => {
                if (reg.active) reg.active.postMessage(msg);
            });
        }
    },

    async start() {
        // Load custom relay URL from IndexedDB
        let customRelayUrl = null;
        try {
            const saved = await dbGet('settings', 'custom_relay_url');
            if (saved && saved.value) customRelayUrl = saved.value;
        } catch(e) {}

        this.relayUrl = customRelayUrl ||
            (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/ws';

        this._discoveredRelays = relayClient.relays.map(url => {
            let u = url.replace(/\/$/, '');
            if (u.startsWith('https://')) return 'wss://' + u.slice(8) + '/ws';
            if (u.startsWith('http://')) return 'ws://' + u.slice(7) + '/ws';
            return u;
        });
        this._currentRelayIndex = 0;

        // Tell SW to open the relay WebSocket
        this._swPost({ type: 'relay_connect', url: this.relayUrl, peerId: window._peerId || null });
    },

    // Register peer_id with relay (called after WASM loads and peerId is known)
    registerPeer(peerId) {
        this._swPost({ type: 'relay_register', peerId });
    },

    // Send signaling through relay
    sendSignaling(type, toPeerId, payload) {
        if (!this._swRelayConnected) return false;
        this._swPost({ type: 'relay_signaling', msgType: type, to: toPeerId, payload });
        return true;
    },

    // Send a message through relay
    sendRelay(toPeerId, payload) {
        if (!this._swRelayConnected) return false;
        this._swPost({ type: 'relay_send', to: toPeerId, payload });
        return true;
    },

    isRelayConnected() {
        return this._swRelayConnected;
    },

    isConnected() {
        return this._swRelayConnected;
    }
};

// ── Message Queue (offline resilience) ─────────────────────
const messageQueue = [];
const MAX_QUEUE_SIZE = 200;
const MAX_QUEUE_AGE_MS = 3600000; // 1 hour

function queueMessage(toPeerId, payload) {
    if (messageQueue.length >= MAX_QUEUE_SIZE) messageQueue.shift();
    messageQueue.push({ toPeerId, payload, timestamp: Date.now() });
    console.log('[Queue] Message queued for', toPeerId.slice(0, 8), '- queue size:', messageQueue.length);
}

function flushMessageQueue() {
    if (messageQueue.length === 0) return;
    console.log('[Queue] Flushing', messageQueue.length, 'queued messages');
    const toFlush = messageQueue.splice(0, messageQueue.length);
    for (const msg of toFlush) {
        if (Date.now() - msg.timestamp > MAX_QUEUE_AGE_MS) continue; // expired
        let sent = false;
        if (hasDirectConnection(msg.toPeerId)) {
            sent = sendViaWebRTC(msg.toPeerId, msg.payload);
        }
        if (!sent) {
            sent = sendToRelay(msg.toPeerId, msg.payload);
        }
        if (!sent) {
            messageQueue.push(msg); // re-queue
        }
    }
    if (messageQueue.length > 0) {
        console.log('[Queue]', messageQueue.length, 'messages still queued');
    }
}

// ── WebRTC Gossip Mesh ─────────────────────────────────────
const seenGossipMessages = new Set();
const SEEN_GOSSIP_MAX = 1000;
let gossipForwardCount = 0;
let gossipForwardResetTime = Date.now();
const GOSSIP_RATE_LIMIT = 10; // max forwards per second

function generateMsgId() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function markGossipSeen(msgId) {
    seenGossipMessages.add(msgId);
    if (seenGossipMessages.size > SEEN_GOSSIP_MAX) {
        const first = seenGossipMessages.values().next().value;
        seenGossipMessages.delete(first);
    }
}

function gossipForward(originPeerId, msgId, to, payload, ttl) {
    if (seenGossipMessages.has(msgId)) return;
    markGossipSeen(msgId);

    // Rate limiting
    const now = Date.now();
    if (now - gossipForwardResetTime > 1000) {
        gossipForwardCount = 0;
        gossipForwardResetTime = now;
    }
    if (gossipForwardCount >= GOSSIP_RATE_LIMIT) return;

    const gossipMsg = JSON.stringify({
        type: 'gossip',
        msgId: msgId,
        from: originPeerId,
        to: to,
        payload: payload,
        ttl: ttl
    });

    for (const [peerId, conn] of Object.entries(rtcConnections)) {
        if (peerId === originPeerId) continue; // don't send back to origin
        if (conn.dc && conn.dc.readyState === 'open') {
            try {
                conn.dc.send(gossipMsg);
                gossipForwardCount++;
            } catch(e) {
                console.warn('[Gossip] Forward to', peerId.slice(0,8), 'failed:', e.message);
            }
        }
    }
}

// ── Contact List ────────────────────────────────────────────
async function loadContacts() {
    try {
        const contacts = await dbGetAll('contacts');
        renderContactList(contacts);
    } catch (e) {
        console.warn('Failed to load contacts:', e);
        renderContactList([]);
    }
}

function renderContactList(contacts) {
    const list = document.getElementById('contact-list');
    if (!list) return;

    if (contacts.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No contacts yet</p><p>Tap + to add someone</p></div>';
        return;
    }
    list.innerHTML = contacts.map(c => `
        <div class="contact-item" onclick="openChat('${escapeAttr(c.peerId)}')">
            <div class="contact-avatar">${escapeHtml(c.name[0]?.toUpperCase() || '?')}</div>
            <div class="contact-info">
                <div class="contact-name" dir="auto">${escapeHtml(c.name)}</div>
                <div class="contact-last-msg" dir="auto">${escapeHtml(c.lastMessage || 'No messages yet')}</div>
            </div>
            <div class="contact-meta">
                <div class="contact-time">${escapeHtml(c.lastTime || '')}</div>
                ${c.unread ? `<div class="unread-badge">${c.unread}</div>` : ''}
            </div>
        </div>
    `).join('');
}

// ── Address Book (Contacts Tab) ─────────────────────────────
async function loadAddressBook() {
    try {
        const contacts = await dbGetAll('contacts');
        contacts.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
        renderAddressBook(contacts);
    } catch (e) {
        console.warn('Failed to load address book:', e);
        renderAddressBook([]);
    }
}

function renderAddressBook(contacts) {
    const list = document.getElementById('address-book-list');
    if (!list) return;

    if (!contacts || contacts.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No contacts yet</p><p>Tap + to add someone</p></div>';
        return;
    }
    list.innerHTML = contacts.map(c => `
        <div class="contact-item address-book-item" data-peerid="${escapeAttr(c.peerId)}">
            <div class="contact-avatar">${escapeHtml(c.name[0]?.toUpperCase() || '?')}</div>
            <div class="contact-info" onclick="openChat('${escapeAttr(c.peerId)}')">
                <div class="contact-name" dir="auto">${escapeHtml(c.name)}</div>
                <div class="contact-peer-id">${escapeHtml(c.peerId.slice(0, 16) + '...')}</div>
            </div>
            <button class="contact-edit-btn" onclick="renameContact('${escapeAttr(c.peerId)}')" title="Rename contact">&#9998;</button>
        </div>
    `).join('');
}

async function renameContact(peerId) {
    let contacts;
    try {
        contacts = await dbGetAll('contacts');
    } catch (e) {
        showToast('Failed to load contact');
        return;
    }
    const contact = contacts.find(c => c.peerId === peerId);
    if (!contact) { showToast('Contact not found'); return; }

    const newName = prompt('Set name for this contact:', contact.name || '');
    if (newName === null) return; // cancelled
    const trimmed = newName.trim();
    if (!trimmed) { showToast('Name cannot be empty'); return; }

    contact.name = trimmed;
    try {
        await dbPut('contacts', contact);
        showToast('Contact renamed');
        loadAddressBook();
        // Update chat header if this contact's chat is open
        if (window.currentPeerId === peerId) {
            const nameEl = document.getElementById('chat-peer-name');
            if (nameEl) nameEl.textContent = trimmed;
        }
    } catch (e) {
        showToast('Failed to rename: ' + e.message);
    }
}

// ── Chat View ───────────────────────────────────────────────
function openChat(peerId) {
    currentPeerId = peerId;
    window.currentPeerId = peerId;
    showView('chat');

    const nameEl = document.getElementById('chat-peer-name');
    if (nameEl) {
        // Show truncated peerId immediately, then resolve contact name
        nameEl.textContent = peerId.length > 20 ? peerId.slice(0, 16) + '...' : peerId;
        dbGetAll('contacts').then(contacts => {
            const c = contacts.find(x => x.peerId === peerId);
            if (c && c.name && nameEl) nameEl.textContent = c.name;
        }).catch(() => {});
    }
    loadMessages(peerId);

    // Try to establish direct WebRTC connection
    if (typeof RTCPeerConnection !== 'undefined') {
        initWebRTC(peerId, true).catch(e => console.log('[WebRTC] Init failed:', e));
    }
}

async function loadMessages(peerId) {
    try {
        const messages = await dbGetByIndex('messages', 'peerId', peerId);
        messages.sort((a, b) => a.timestamp - b.timestamp);
        renderMessages(messages);
    } catch (e) {
        console.warn('Failed to load messages:', e);
        renderMessages([]);
    }
}

function renderMessages(messages) {
    const container = document.getElementById('message-list');
    if (!container) return;

    container.innerHTML = messages.map(m => `
        <div class="message ${m.direction}">
            <div class="message-bubble" dir="auto">${escapeHtml(m.content)}</div>
            <div class="message-time">${formatTime(m.timestamp)}</div>
        </div>
    `).join('');
    container.scrollTop = container.scrollHeight;
}

async function sendMessage() {
    const input = document.getElementById('message-input');
    if (!input) return;
    const text = input.value.trim();
    if (!text || !currentPeerId) return;

    const msg = {
        peerId: currentPeerId,
        direction: 'sent',
        content: text,
        timestamp: Date.now()
    };

    // Store locally
    try { await dbPut('messages', msg); } catch(e) { console.warn(e); }

    appendMessage(msg);

    // Encrypt and send — require encryption, never send plaintext
    let sent = false;
    let relayPayload = null;
    if (!wasm || !wasm.encrypt_message || !wasm.has_session || !wasm.has_session(currentPeerId)) {
        showToast('Cannot send: secure session not established with this contact');
        return;
    }
    try {
        const encoder = new TextEncoder();
        const plainBytes = encoder.encode(text);
        const encrypted = wasm.encrypt_message(currentPeerId, plainBytes);
        // Convert Uint8Array to hex for JSON transport
        const hexPayload = Array.from(encrypted).map(b => b.toString(16).padStart(2, '0')).join('');
        const encPayload = 'enc:' + hexPayload;
        relayPayload = encPayload;
        // Try WebRTC first, fall back to relay
        if (hasDirectConnection(currentPeerId)) {
            sent = sendViaWebRTC(currentPeerId, encPayload);
        }
        if (!sent) {
            sent = sendToRelay(currentPeerId, encPayload);
        }
    } catch (e) {
        console.error('Encryption failed:', e);
        showToast('Encryption failed — message not sent');
        return;
    }
    if (!sent) {
        queueMessage(currentPeerId, relayPayload);
        showToast('Message queued — will send when connected');
    }

    // Also broadcast via gossip mesh for redundancy
    const msgId = generateMsgId();
    markGossipSeen(msgId);
    const gossipPayload = relayPayload;
    for (const [pid, conn] of Object.entries(rtcConnections)) {
        if (conn.dc && conn.dc.readyState === 'open') {
            try {
                conn.dc.send(JSON.stringify({
                    type: 'gossip',
                    msgId: msgId,
                    from: window._peerId,
                    to: currentPeerId,
                    payload: gossipPayload,
                    ttl: 3
                }));
            } catch(e) {}
        }
    }

    // Privacy: message_sent telemetry removed — leaks activity metadata
    input.value = '';
    input.focus();

    // Update contact's last message
    try {
        await dbPut('contacts', {
            peerId: currentPeerId,
            name: currentPeerId.slice(0, 8) + '...',
            lastMessage: text,
            lastTime: formatTime(Date.now()),
            unread: 0
        });
    } catch(e) { console.warn(e); }

    // Request notification permission after first message sent (user interaction)
    if ('Notification' in window && Notification.permission === 'default') {
        requestNotificationPermission();
    }
}

function appendMessage(msg) {
    const container = document.getElementById('message-list');
    if (!container) return;

    const div = document.createElement('div');
    div.className = `message ${msg.direction}`;
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    if (msg.domContent) {
        // Pre-built DOM node (e.g. file transfer UI)
        bubble.appendChild(msg.domContent);
    } else {
        bubble.setAttribute('dir', 'auto');
        bubble.textContent = msg.content;
    }
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(msg.timestamp);
    div.appendChild(bubble);
    div.appendChild(time);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

// ── Call UI ─────────────────────────────────────────────────
let callTimerInterval = null;
let callStartTime = null;

async function initiateCall(peerId, withVideo) {
    if (!peerId) peerId = currentPeerId;
    if (!peerId) return;
    currentCallId = null;

    // Request media
    try {
        const constraints = { audio: true };
        if (withVideo) constraints.video = { width: 320, height: 240 };
        localStream = await navigator.mediaDevices.getUserMedia(constraints);

        // Show local video if video call
        if (withVideo) {
            const localVideo = document.getElementById('local-video');
            if (localVideo) {
                localVideo.srcObject = localStream;
                localVideo.classList.remove('hidden');
            }
        }
    } catch (e) {
        showToast('Could not access microphone/camera: ' + e.message);
        return;
    }

    // Start call via WASM
    if (wasm && wasm.start_call) {
        try {
            currentCallId = wasm.start_call(peerId);
        } catch (e) {
            showToast('Call failed: ' + e.message);
            stopLocalMedia();
            return;
        }
    }

    showView('call');
    const nameEl = document.getElementById('call-peer-name');
    if (nameEl) nameEl.textContent = peerId.length > 20 ? peerId.slice(0, 16) + '...' : peerId;

    const statusEl = document.getElementById('call-status');
    if (statusEl) statusEl.textContent = 'Calling...';

    startCallTimer();
}

function answerIncomingCall(callId) {
    if (wasm && wasm.answer_call) {
        wasm.answer_call(callId);
    }
    const statusEl = document.getElementById('call-status');
    if (statusEl) statusEl.textContent = 'Connected';
    startCallTimer();
}

function hangupCall() {
    if (wasm && wasm.hangup_call && currentCallId) {
        try { wasm.hangup_call(currentCallId); } catch(e) { console.warn(e); }
    }
    stopLocalMedia();
    stopCallTimer();
    currentCallId = null;
    showView(currentPeerId ? 'chat' : 'contacts');
}

function stopLocalMedia() {
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        localStream = null;
    }
    const localVideo = document.getElementById('local-video');
    if (localVideo) {
        localVideo.srcObject = null;
        localVideo.classList.add('hidden');
    }
}

function startCallTimer() {
    callStartTime = Date.now();
    const timerEl = document.getElementById('call-timer');
    callTimerInterval = setInterval(() => {
        if (!timerEl) return;
        const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
        const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const secs = (elapsed % 60).toString().padStart(2, '0');
        timerEl.textContent = mins + ':' + secs;
    }, 1000);
}

function stopCallTimer() {
    if (callTimerInterval) {
        clearInterval(callTimerInterval);
        callTimerInterval = null;
    }
    callStartTime = null;
    const timerEl = document.getElementById('call-timer');
    if (timerEl) timerEl.textContent = '';
}

function toggleMute() {
    const btn = document.querySelector('.call-btn.mute');
    if (!btn) return;
    btn.classList.toggle('active');

    if (localStream) {
        const audioTracks = localStream.getAudioTracks();
        audioTracks.forEach(track => {
            track.enabled = !track.enabled;
        });
    }
}

function toggleCamera() {
    const btn = document.querySelector('.call-btn.camera');
    if (!btn) return;
    btn.classList.toggle('active');

    if (localStream) {
        const videoTracks = localStream.getVideoTracks();
        videoTracks.forEach(track => {
            track.enabled = !track.enabled;
        });
        const localVideo = document.getElementById('local-video');
        if (localVideo) {
            localVideo.classList.toggle('hidden', !videoTracks[0]?.enabled);
        }
    }
}

// ── File Transfer ───────────────────────────────────────────
function attachFile() {
    const input = document.getElementById('file-input');
    if (input) input.click();
}

function onFileSelected(event) {
    const file = event.target.files[0];
    if (!file || !currentPeerId) return;

    // Show in chat with progress
    const msgId = 'file-' + Date.now();
    const fileTransferEl = document.createElement('div');
    fileTransferEl.id = msgId;
    fileTransferEl.className = 'file-transfer';
    const fileNameEl = document.createElement('div');
    fileNameEl.className = 'file-name';
    fileNameEl.textContent = '\ud83d\udcce ' + file.name;
    const fileSizeEl = document.createElement('div');
    fileSizeEl.className = 'file-size';
    fileSizeEl.textContent = formatSize(file.size);
    const progressEl = document.createElement('div');
    progressEl.className = 'file-progress';
    const progressBar = document.createElement('div');
    progressBar.className = 'file-progress-bar';
    progressBar.style.width = '0%';
    progressEl.appendChild(progressBar);
    const statusEl = document.createElement('div');
    statusEl.className = 'file-status';
    statusEl.textContent = 'Preparing...';
    fileTransferEl.appendChild(fileNameEl);
    fileTransferEl.appendChild(fileSizeEl);
    fileTransferEl.appendChild(progressEl);
    fileTransferEl.appendChild(statusEl);
    appendMessage({
        direction: 'sent',
        domContent: fileTransferEl,
        timestamp: Date.now()
    });

    file.arrayBuffer().then(buffer => {
        const data = new Uint8Array(buffer);
        if (wasm && wasm.create_file_transfer) {
            try {
                const fileId = wasm.create_file_transfer(data, file.name, file.type || null);
                updateFileProgress(msgId, 100, 'Sent');
            } catch (e) {
                updateFileProgress(msgId, 0, 'Failed: ' + e.message);
            }
        } else {
            updateFileProgress(msgId, 0, 'Not connected');
        }
    });

    // Reset input so same file can be selected again
    event.target.value = '';
}

function updateFileProgress(msgId, percent, status) {
    const el = document.getElementById(msgId);
    if (!el) return;
    const bar = el.querySelector('.file-progress-bar');
    const statusEl = el.querySelector('.file-status');
    if (bar) bar.style.width = percent + '%';
    if (statusEl) statusEl.textContent = status;
}

// ── QR Code / Camera ────────────────────────────────────────
let scannerInterval = null;

async function startQRScanner() {
    const video = document.getElementById('qr-scanner-video');
    const statusEl = document.getElementById('qr-scanner-status');
    if (!video) return;

    // Check for BarcodeDetector (Chromium only — NOT available on Safari/iOS)
    const hasBarcodeAPI = 'BarcodeDetector' in window;

    try {
        const stream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }
        });
        video.srcObject = stream;
        await video.play();

        // iOS Safari: video dimensions not ready immediately after play()
        if (video.videoWidth === 0) {
            await new Promise(resolve => {
                video.addEventListener('loadedmetadata', resolve, { once: true });
                setTimeout(resolve, 2000); // safety timeout
            });
        }

        console.log('[QR] path:', hasBarcodeAPI ? 'BarcodeDetector' : 'jsQR',
                    'videoSize:', video.videoWidth + 'x' + video.videoHeight);

        if (hasBarcodeAPI) {
            // Native QR detection (Chromium browsers)
            const detector = new BarcodeDetector({ formats: ['qr_code'] });
            if (statusEl) statusEl.textContent = 'Scanning for QR code...';

            scannerInterval = setInterval(async () => {
                if (!video.srcObject) return;
                try {
                    const barcodes = await detector.detect(video);
                    if (barcodes.length > 0) {
                        const data = barcodes[0].rawValue;
                        stopQRScanner();
                        handleScannedQR(data);
                    }
                } catch (e) {
                    // Frame not ready yet, ignore
                }
            }, 250);
        } else if (typeof jsQR === 'function') {
            // jsQR pure JS decoder (Safari, Firefox, all browsers)
            if (statusEl) statusEl.textContent = 'Scanning for QR code...';
            const scanCanvas = document.createElement('canvas');
            const scanCtx = scanCanvas.getContext('2d', { willReadFrequently: true });

            scannerInterval = setInterval(() => {
                if (!video.srcObject || video.videoWidth === 0) return;
                scanCanvas.width = video.videoWidth;
                scanCanvas.height = video.videoHeight;
                scanCtx.drawImage(video, 0, 0);
                const imageData = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
                const code = jsQR(imageData.data, scanCanvas.width, scanCanvas.height);
                if (code && code.data) {
                    if (isValidQRData(code.data)) {
                        console.log('[QR] jsQR decoded:', code.data.slice(0, 80));
                        stopQRScanner();
                        handleScannedQR(code.data);
                    } else {
                        console.log('[QR] jsQR rejected by validation:', code.data.slice(0, 80));
                    }
                }
            }, 250);
        } else {
            // No decoder available — fall back to manual entry
            if (statusEl) {
                statusEl.innerHTML = 'Your browser doesn\'t support QR scanning.<br>Ask your contact to share their code, then paste it in the <strong>Paste Code</strong> tab.';
            }
        }
    } catch (e) {
        console.error('[QR] Camera error:', e);
        if (statusEl) {
            statusEl.textContent = 'Camera access denied. Check your browser permissions.';
        }
    }
}

function stopQRScanner() {
    if (scannerInterval) {
        clearInterval(scannerInterval);
        scannerInterval = null;
    }
    const video = document.getElementById('qr-scanner-video');
    if (video && video.srcObject) {
        video.srcObject.getTracks().forEach(t => t.stop());
        video.srcObject = null;
    }
    const statusEl = document.getElementById('qr-scanner-status');
    if (statusEl) statusEl.textContent = 'Scanner stopped';
}

// Validate decoded QR data before acting on it
function isValidQRData(data) {
    if (!data || typeof data !== 'string') return false;
    if (data.length < 10) return false;
    // Must be printable ASCII or start with parolnet:
    if (data.startsWith('parolnet:')) return true;
    // Must be hex (our QR payloads are hex-encoded)
    if (/^[0-9a-fA-F]+$/.test(data) && data.length >= 64) return true;
    // Reject anything with non-ASCII (the "Chinese characters" = garbage decode)
    for (let i = 0; i < data.length; i++) {
        const c = data.charCodeAt(i);
        if (c > 127 || c < 32) return false;
    }
    return data.length >= 20;
}

function handleScannedQR(data) {
    console.log('[QR] handleScannedQR:', data.slice(0, 80));

    let peerId = null;
    let sessionEstablished = false;
    let bootstrapSecret = null;

    // Try full QR payload first (hex-encoded CBOR with ratchet key)
    if (/^[0-9a-fA-F]+$/.test(data) && data.length > 64 && wasm && wasm.process_scanned_qr) {
        try {
            const result = wasm.process_scanned_qr(data);
            peerId = result.peer_id;
            bootstrapSecret = result.bootstrap_secret;
            sessionEstablished = true;
            // Privacy: session_established telemetry removed — leaks activity metadata
            console.log('[QR] Session established with:', peerId.slice(0, 8));
        } catch(e) {
            console.warn('[QR] process_scanned_qr failed:', e);
            // Fall through to legacy parsing
        }
    }

    // Legacy format: parolnet:<64-char-hex>
    if (!peerId && data.startsWith('parolnet:')) {
        peerId = data.slice(9).trim();
    }
    // Raw 64-char hex (peer_id directly)
    else if (!peerId && /^[0-9a-fA-F]{64}$/.test(data)) {
        peerId = data.toLowerCase();
    }

    if (!peerId || peerId.length !== 64) {
        showToast('Unrecognized QR code');
        console.warn('[QR] Invalid peerId from scan:', data.slice(0, 40));
        return;
    }

    if (peerId === window._peerId) {
        showToast("That's your own QR code!");
        return;
    }

    // Add as contact and open chat
    showToast(sessionEstablished ? 'Secure contact added!' : 'Contact added (no encryption)');
    dbPut('contacts', {
        peerId: peerId,
        name: peerId.slice(0, 8) + '...',
        lastMessage: sessionEstablished ? 'Encrypted session established' : 'Connected via QR',
        lastTime: formatTime(Date.now()),
        unread: 0
    }).then(async () => {
        loadContacts();
        if (sessionEstablished && wasm && wasm.get_public_key) {
            // Send bootstrap handshake so the presenter can establish their responder session
            const ourIk = wasm.get_public_key();
            sendToRelay(peerId, '__system:bootstrap:' + ourIk);
        } else {
            sendToRelay(peerId, '__system:contact_added');
        }
        openChat(peerId);
    }).catch(e => console.warn('Failed to save contact:', e));
}

function renderBootstrapQR() {
    const canvas = document.getElementById('qr-canvas');
    const codeEl = document.getElementById('qr-share-code');

    // Build the shareable data — always have something to show
    let data = '';

    // Try WASM first
    if (wasm && wasm.get_public_key) {
        try {
            const pubKey = wasm.get_public_key();
            if (pubKey && pubKey.length > 0) {
                if (wasm.generate_qr_payload) {
                    data = wasm.generate_qr_payload(pubKey, null);
                }
                // If generate_qr_payload returned empty, use the public key directly
                if (!data) {
                    data = 'parolnet:' + pubKey;
                }
            }
        } catch(e) {
            console.warn('QR payload generation failed:', e);
        }
    }

    // Fallback: use stored peerId
    if (!data && window._peerId) {
        data = 'parolnet:' + window._peerId;
    }

    // Last resort: generate a fresh identity just for display
    if (!data) {
        if (wasm && wasm.generate_identity) {
            data = 'parolnet:' + wasm.generate_identity();
        } else {
            data = 'parolnet:app-not-loaded';
        }
    }

    // Show the text code — always visible
    if (codeEl) {
        codeEl.textContent = data;
        codeEl.style.wordBreak = 'break-all';
    }

    // Render QR code on canvas
    if (canvas && typeof qrcode === 'function') {
        try {
            const qr = qrcode(0, 'M'); // 0 = auto version, M = medium error correction
            qr.addData(data);
            qr.make();
            const moduleCount = qr.getModuleCount();
            const padding = 4;
            const totalModules = moduleCount + padding * 2;
            const moduleSize = Math.floor(Math.min(canvas.width, canvas.height) / totalModules);
            const offset = Math.floor((canvas.width - totalModules * moduleSize) / 2);
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#000000';
            for (let r = 0; r < moduleCount; r++)
                for (let c = 0; c < moduleCount; c++)
                    if (qr.isDark(r, c))
                        ctx.fillRect(
                            offset + (c + padding) * moduleSize,
                            offset + (r + padding) * moduleSize,
                            moduleSize, moduleSize
                        );
        } catch(e) {
            console.error('QR render error:', e);
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#fff';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#333';
            ctx.font = '11px monospace';
            ctx.textAlign = 'center';
            ctx.fillText('QR error — use code below', canvas.width/2, canvas.height/2);
        }
    }
}

function copyBootstrapCode() {
    const codeEl = document.getElementById('qr-share-code');
    if (!codeEl || !codeEl.textContent) {
        showToast('No code to copy');
        return;
    }
    navigator.clipboard.writeText(codeEl.textContent).then(() => {
        showToast('Code copied to clipboard');
    }).catch(() => {
        // Fallback: select the text
        const range = document.createRange();
        range.selectNodeContents(codeEl);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        showToast('Select and copy the highlighted text');
    });
}

// ── Add Contact Tabs ────────────────────────────────────────
function showAddTab(tabName) {
    document.querySelectorAll('.add-tab-content').forEach(t => t.classList.add('hidden'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));

    const tab = document.getElementById('add-tab-' + tabName);
    if (tab) tab.classList.remove('hidden');

    const btn = document.querySelector(`.tab[data-tab="${tabName}"]`);
    if (btn) btn.classList.add('active');

    // Start/stop camera
    if (tabName === 'qr-scan') {
        startQRScanner();
    } else {
        stopQRScanner();
    }

    // Render QR code
    if (tabName === 'qr-show') {
        renderBootstrapQR();
    }
}

// ── Add Contact by Code ────────────────────────────────────
function connectViaPassphrase() {
    const input = document.querySelector('#add-tab-passphrase input');
    const raw = input?.value?.trim();
    if (!raw) {
        showToast('Paste the code from your contact');
        return;
    }

    // Clean up the input — strip whitespace, newlines, quotes
    let clean = raw.replace(/[\s\n\r"']/g, '');
    console.log('[AddContact] Input cleaned:', clean.slice(0, 80), 'length:', clean.length);

    // Extract PeerId from whatever format they pasted
    let peerId = null;

    if (clean.startsWith('parolnet:')) {
        // Format: parolnet:<64-char-hex>
        peerId = clean.slice(9).trim();
    } else if (/^[0-9a-fA-F]{64}$/.test(clean)) {
        // Raw 64-char hex PeerId
        peerId = clean.toLowerCase();
    } else if (/^[0-9a-fA-F]+$/.test(clean) && clean.length >= 64) {
        // Longer hex — take first 64 chars as PeerId
        peerId = clean.slice(0, 64).toLowerCase();
    }

    // Last resort: maybe they pasted the whole "parolnet:..." with extra stuff
    if (!peerId) {
        const match = clean.match(/parolnet:([0-9a-fA-F]{64})/);
        if (match) peerId = match[1].toLowerCase();
    }

    if (!peerId || peerId.length !== 64) {
        showToast('Invalid code (length ' + (peerId?.length || clean.length) + '). Copy the FULL code.');
        console.warn('[AddContact] Invalid peerId:', clean.slice(0, 40), 'extracted:', peerId?.slice(0, 20));
        return;
    }

    if (peerId === window._peerId) {
        showToast("That's your own code!");
        return;
    }

    // Add as contact, open chat
    dbPut('contacts', {
        peerId: peerId,
        name: peerId.slice(0, 8) + '...',
        lastMessage: '',
        lastTime: formatTime(Date.now()),
        unread: 0
    }).then(() => {
        input.value = '';
        showToast('Contact added!');
        loadContacts();
        // Notify the other peer that we added them
        sendToRelay(peerId, '__system:contact_added');
        openChat(peerId);
    }).catch(e => {
        showToast('Failed: ' + e.message);
    });
}

// ── Settings ────────────────────────────────────────────────
function openSettings() {
    showView('settings');
    updateNetworkSettings();
    updateWebRTCPrivacyUI();

    // Show/hide encryption setup vs status
    const encSetup = document.getElementById('encryption-setup');
    const encStatus = document.getElementById('encryption-status');
    if (encSetup && encStatus) {
        if (cryptoStore.isEnabled()) {
            encSetup.style.display = 'none';
            encStatus.style.display = 'block';
        } else {
            encSetup.style.display = 'block';
            encStatus.style.display = 'none';
        }
    }
}

async function enableEncryption() {
    const input = document.getElementById('encryption-passphrase-input');
    const confirm = document.getElementById('encryption-passphrase-confirm');
    const passphrase = input ? input.value : '';
    const confirmed = confirm ? confirm.value : '';

    if (!passphrase || passphrase.length < 4) {
        showToast('Passphrase must be at least 4 characters');
        return;
    }
    if (passphrase !== confirmed) {
        showToast('Passphrases do not match');
        return;
    }

    try {
        // Setup encryption
        await cryptoStore.setup(passphrase, dbPutRaw, dbGetRaw);

        // Migrate existing plaintext data
        showToast('Encrypting data...');
        await migrateToEncrypted();

        showToast('Encryption enabled!');
        if (input) input.value = '';
        if (confirm) confirm.value = '';

        // Update settings UI
        const encSetup = document.getElementById('encryption-setup');
        const encStatus = document.getElementById('encryption-status');
        if (encSetup) encSetup.style.display = 'none';
        if (encStatus) encStatus.style.display = 'block';
    } catch (e) {
        showToast('Failed to enable encryption: ' + e.message);
    }
}

async function migrateToEncrypted() {
    // Re-encrypt all existing plaintext records
    for (const storeName of ENCRYPTED_STORES) {
        try {
            const items = await dbGetAllRaw(storeName);
            for (const item of items) {
                if (!item._enc) {
                    // This is plaintext — encrypt it
                    await dbPut(storeName, item);
                }
            }
        } catch (e) {
            console.warn('Migration failed for', storeName, e);
        }
    }
}

// ── Data Export/Import ─────────────────────────────────────
async function handleExportData() {
    const password = prompt('Enter a password to encrypt your export:');
    if (!password || password.length < 4) {
        showToast('Password must be at least 4 characters');
        return;
    }
    const confirm = prompt('Confirm password:');
    if (password !== confirm) {
        showToast('Passwords do not match');
        return;
    }

    try {
        showToast('Exporting data...');

        // Gather all store data (raw — includes encrypted records as-is)
        const stores = {};
        for (const storeName of ['contacts', 'messages', 'settings', 'crypto_meta']) {
            stores[storeName] = await dbGetAllRaw(storeName);
        }

        // Get identity key
        let identity = null;
        try {
            if (wasm && wasm.export_secret_key) {
                identity = wasm.export_secret_key();
            }
        } catch (e) {
            console.warn('Could not export identity key:', e);
        }

        const encrypted = await exportData({ stores, identity }, password);

        // Trigger download
        const blob = new Blob([encrypted], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'parolnet-backup.bin';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast('Export complete!');
    } catch (e) {
        showToast('Export failed: ' + e.message);
    }
}

async function handleImportData() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.bin,*/*';

    input.onchange = async () => {
        const file = input.files[0];
        if (!file) return;

        const password = prompt('Enter the export password:');
        if (!password) return;

        try {
            showToast('Reading file...');
            const arrayBuffer = await file.arrayBuffer();
            const encrypted = new Uint8Array(arrayBuffer);

            // Validate first
            const info = await validateExport(encrypted, password);
            const proceed = confirm(
                `This will replace ALL current data.\n\n` +
                `Export contains:\n` +
                `- ${info.contactCount} contacts\n` +
                `- ${info.messageCount} messages\n` +
                `- Identity key: ${info.hasIdentity ? 'Yes' : 'No'}\n\n` +
                `Continue?`
            );
            if (!proceed) return;

            showToast('Importing data...');
            const data = await importData(encrypted, password);

            // Clear existing stores and write imported data
            for (const [storeName, records] of Object.entries(data.stores)) {
                await dbClear(storeName);
                for (const record of records) {
                    await dbPutRaw(storeName, record);
                }
            }

            // Restore identity key
            if (data.identity && wasm && wasm.initialize_from_key) {
                try {
                    wasm.initialize_from_key(data.identity);
                    await dbPut('settings', { key: 'identity_secret', value: data.identity });
                } catch (e) {
                    console.warn('Could not restore identity key:', e);
                    showToast('Warning: Identity key restore failed');
                }
            }

            showToast('Import complete! Reloading...');
            setTimeout(() => location.reload(), 1500);
        } catch (e) {
            showToast('Import failed: ' + e.message);
        }
    };

    input.click();
}

// ── Network Settings ───────────────────────────────────────
async function setCustomRelay() {
    const input = document.getElementById('custom-relay-input');
    if (!input) return;
    const url = input.value.trim();

    if (url && !url.startsWith('wss://') && !url.startsWith('ws://')) {
        showToast('Relay URL must start with wss:// or ws://');
        return;
    }

    if (url) {
        await dbPut('settings', { key: 'custom_relay_url', value: url });
        showToast('Relay URL set — reconnecting...');
    } else {
        // Clear custom URL — revert to default
        try { await dbDelete('settings', 'custom_relay_url'); } catch(e) {}
        showToast('Relay URL reset to default');
    }

    input.value = '';

    // Reconnect relay with new URL
    connMgr.relayUrl = url || (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/ws';
    if (connMgr.relayWs) {
        connMgr.relayWs.close();
    }
    connMgr._connectRelay();
    updateNetworkSettings();
}

async function clearCustomRelay() {
    try { await dbDelete('settings', 'custom_relay_url'); } catch(e) {}

    connMgr.relayUrl = (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/ws';
    if (connMgr.relayWs) {
        connMgr.relayWs.close();
    }
    connMgr._connectRelay();
    showToast('Relay URL reset to default');
    updateNetworkSettings();
}

function updateNetworkSettings() {
    const peerCount = document.getElementById('settings-peer-count');
    const relayStatus = document.getElementById('settings-relay-status');
    const contactChannels = document.getElementById('settings-contact-channels');

    if (peerCount) {
        const count = Object.values(rtcConnections).filter(c => c.dc && c.dc.readyState === 'open').length;
        peerCount.textContent = count.toString();
    }

    if (relayStatus) {
        const isConnected = connMgr.isRelayConnected();
        const knownCount = relayClient.knownRelayCount;
        const statusText = isConnected
            ? 'Connected' + (knownCount > 1 ? ' (' + knownCount + ' relays known)' : '')
            : 'Disconnected' + (knownCount > 0 ? ' (' + knownCount + ' relays known)' : '');
        relayStatus.textContent = statusText;
        relayStatus.style.color = isConnected ? '#4CAF50' : '#f44336';
    }

    const relayUrlDisplay = document.getElementById('relay-url-display');
    if (relayUrlDisplay) {
        dbGet('settings', 'custom_relay_url').then(saved => {
            if (saved && saved.value) {
                relayUrlDisplay.textContent = '';
                const text = document.createTextNode('Current: ' + saved.value + ' ');
                const link = document.createElement('a');
                link.href = '#';
                link.style.color = '#f44';
                link.textContent = 'Reset';
                link.addEventListener('click', (e) => { e.preventDefault(); clearCustomRelay(); });
                relayUrlDisplay.appendChild(text);
                relayUrlDisplay.appendChild(link);
            } else {
                relayUrlDisplay.textContent = 'Default: ' + (connMgr.relayUrl || 'same origin');
            }
        }).catch(() => {
            relayUrlDisplay.textContent = 'Default: ' + (connMgr.relayUrl || 'same origin');
        });
    }

    if (contactChannels) {
        contactChannels.textContent = Object.values(rtcConnections).filter(c => c.dc && c.dc.readyState === 'open').length.toString();
    }
}

function enableDecoyMode() {
    const input = document.getElementById('decoy-code-input');
    const code = input ? input.value : '00000';

    if (wasm && wasm.set_unlock_code) {
        wasm.set_unlock_code(code);
    }

    // Privacy: decoy_enabled is no longer stored in localStorage — it would
    // reveal to an adversary inspecting storage that decoy mode is active.
    // Decoy state is derived solely from WASM at runtime.

    // Swap manifest to calculator
    const manifestLink = document.getElementById('manifest-link');
    if (manifestLink) {
        manifestLink.href = 'manifest-calculator.json';
    }

    showToast('Decoy mode enabled. The app will appear as a calculator on next launch.');
}

// ── Panic Wipe ──────────────────────────────────────────────
function executePanicWipe() {
    // Wipe in-memory encryption key immediately
    cryptoStore.lock();
    if (wasm) { try { wasm.panic_wipe(); } catch {} }

    // Redirect to kill-sw.html which runs cleanup sequentially
    // outside the service worker's cached scope
    window.location.href = './kill-sw.html?panic=1&t=' + Date.now();
}

// ── Push Notifications ──────────────────────────────────────
async function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        await Notification.requestPermission();
    }
}

function showLocalNotification(title, body, peerId) {
    if ('serviceWorker' in navigator && Notification.permission === 'granted') {
        navigator.serviceWorker.ready.then(reg => {
            reg.showNotification(title, {
                body,
                icon: './icons/icon-192.png',
                tag: 'parolnet-' + peerId,
                data: { peerId },
                vibrate: [200, 100, 200]
            });
        });
    }
}

// ── SW Inbox Drain ──────────────────────────────────────────
// Messages that arrived while the page was backgrounded are
// buffered in the SW's IndexedDB. Drain them on page load.
async function drainSwInbox() {
    return new Promise((resolve) => {
        const req = indexedDB.open('parolnet-sw', 1);
        req.onupgradeneeded = (e) => {
            e.target.result.createObjectStore('sw-inbox', { keyPath: 'id', autoIncrement: true });
        };
        req.onsuccess = (e) => {
            const db = e.target.result;
            const tx = db.transaction('sw-inbox', 'readwrite');
            const store = tx.objectStore('sw-inbox');
            const msgs = [];
            store.openCursor().onsuccess = (ce) => {
                const cursor = ce.target.result;
                if (cursor) {
                    msgs.push(cursor.value.msg);
                    cursor.delete();
                    cursor.continue();
                }
            };
            tx.oncomplete = () => {
                db.close();
                msgs.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
                for (const msg of msgs) {
                    try { handleRelayMessage(msg); } catch(e) {}
                }
                if (msgs.length > 0) console.log('[SW-Inbox] drained', msgs.length, 'buffered messages');
                resolve();
            };
            tx.onerror = () => { resolve(); };
        };
        req.onerror = () => resolve();
    });
}

// ── Service Worker Registration ─────────────────────────────
function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;

    // Route messages from SW back into the app
    navigator.serviceWorker.addEventListener('message', event => {
        const d = event.data;
        if (!d || typeof d !== 'object') return;
        if (d.type === 'relay_msg') {
            handleRelayMessage(d.msg);
        } else if (d.type === 'relay_status') {
            const wasConnected = connMgr._swRelayConnected;
            connMgr._swRelayConnected = d.connected;
            updateConnectionStatus();
            if (d.connected) {
                telemetry.track('relay_connect');
                flushMessageQueue();
            } else if (wasConnected) {
                telemetry.track('relay_disconnect');
                // Try WebRTC to known peers when relay drops
                if (window._knownPeers && typeof RTCPeerConnection !== 'undefined') {
                    for (const pid of window._knownPeers) {
                        if (!hasDirectConnection(pid)) {
                            initWebRTC(pid, true).catch(() => {});
                        }
                    }
                }
            }
        }
    });

    navigator.serviceWorker.register('sw.js').then(reg => {
        console.log('SW registered:', reg.scope);
        setInterval(() => reg.update(), 3600000);

        // Drain any messages that arrived while page was backgrounded
        drainSwInbox().catch(() => {});

        // Query current relay status from SW
        navigator.serviceWorker.ready.then(() => {
            if (navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({ type: 'relay_status_query' });
            }
        });
    }).catch(err => {
        console.warn('SW registration failed:', err);
    });
}

// ── Contact Search ──────────────────────────────────────────
function initContactSearch() {
    const input = document.getElementById('contact-search');
    if (!input) return;

    input.addEventListener('input', () => {
        const query = input.value.toLowerCase().trim();
        const items = document.querySelectorAll('.contact-item');
        items.forEach(item => {
            const name = item.querySelector('.contact-name');
            if (!query || (name && name.textContent.toLowerCase().includes(query))) {
                item.style.display = '';
            } else {
                item.style.display = 'none';
            }
        });
    });
}

// ── Utilities ───────────────────────────────────────────────
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeAttr(text) {
    return text.replace(/&/g, '&amp;').replace(/'/g, '&#39;').replace(/"/g, '&quot;');
}

function formatTime(ts) {
    const d = new Date(ts);
    const now = new Date();
    if (d.toDateString() === now.toDateString()) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

// ── Boot ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.body.classList.add(`platform-${platform}`);
    // Ask OS to treat this origin as persistent — reduces likelihood of SW being evicted
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist();
    registerServiceWorker();
    showToast('Starting ParolNet...', 2000);
    // Load user-configurable settings from IndexedDB early
    loadPanicCode().catch(() => {});
    loadCustomStunServers().catch(() => {});
    loadWasm();

    // If stuck on loading for 15 seconds, show recovery buttons
    setTimeout(() => {
        const loading = document.getElementById('view-loading');
        if (loading && !loading.classList.contains('hidden')) {
            const errEl = document.getElementById('loading-error');
            if (errEl) { errEl.style.display = 'block'; errEl.textContent = 'Taking too long. Try clearing cache.'; }
            const btn = document.getElementById('loading-retry');
            if (btn) btn.style.display = 'inline-block';
            const btn2 = document.getElementById('loading-clear');
            if (btn2) btn2.style.display = 'inline-block';
        }
    }, 15000);
    initContactSearch();

    // Parse bootstrap parameter from URL
    const params = new URLSearchParams(window.location.search);
    const bootstrap = params.get('bootstrap');
    if (bootstrap && wasm && wasm.parse_qr_payload) {
        try {
            wasm.parse_qr_payload(bootstrap);
            showToast('Bootstrap data received');
        } catch(e) {
            console.warn('Failed to parse bootstrap:', e);
        }
    }
});

// ── Auto-lock on background ────────────────────────────────
document.addEventListener('visibilitychange', () => {
    if (document.hidden && cryptoStore.isUnlocked()) {
        // Lock after 5 minutes in background
        window._lockTimer = setTimeout(() => {
            cryptoStore.lock();
            // If decoy mode, show calculator; otherwise show unlock
            const decoyEnabled = wasm && wasm.is_decoy_enabled && wasm.is_decoy_enabled();
            if (decoyEnabled) {
                showView('calculator');
            } else if (cryptoStore.isEnabled()) {
                showView('unlock');
            }
        }, 5 * 60 * 1000);
    } else {
        clearTimeout(window._lockTimer);
        // Coming back to foreground — sync relay state and drain any buffered messages
        if (navigator.serviceWorker && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ type: 'relay_status_query' });
        }
        drainSwInbox().catch(() => {});
    }
});

// Export for onclick handlers
window.calcPress = calcPress;
window.sendMessage = sendMessage;
window.openChat = openChat;
window.renameContact = renameContact;
window.attachFile = attachFile;
window.onFileSelected = onFileSelected;
window.openSettings = openSettings;
window.showView = showView;
window.showAddTab = showAddTab;
window.initiateCall = initiateCall;
window.hangupCall = hangupCall;
window.answerIncomingCall = answerIncomingCall;
window.enableDecoyMode = enableDecoyMode;
window.executePanicWipe = executePanicWipe;
window.toggleMute = toggleMute;
window.toggleCamera = toggleCamera;
window.connectViaPassphrase = connectViaPassphrase;
window.startQRScanner = startQRScanner;
window.showToast = showToast;
window.requestNotificationPermission = requestNotificationPermission;
window.copyBootstrapCode = copyBootstrapCode;
window.attemptUnlock = attemptUnlock;
window.enableEncryption = enableEncryption;
window.handleExportData = handleExportData;
window.handleImportData = handleImportData;
window.currentPeerId = null;
// Group management
window.switchListTab = switchListTab;
window.showCreateGroupDialog = showCreateGroupDialog;
window.createGroup = createGroup;
window.openGroupChat = openGroupChat;
window.sendGroupMessage = sendGroupMessage;
window.showGroupMembers = showGroupMembers;
window.closeGroupMembers = closeGroupMembers;
window.addMemberFromInput = addMemberFromInput;
window.addMemberToGroup = addMemberToGroup;
window.removeMemberFromGroup = removeMemberFromGroup;
window.leaveCurrentGroup = leaveCurrentGroup;
// File receive
window.acceptFileOffer = acceptFileOffer;
window.declineFileOffer = declineFileOffer;
// Incoming calls
window.acceptIncomingCall = acceptIncomingCall;
window.declineIncomingCall = declineIncomingCall;
// Group calls
window.startGroupCall = startGroupCall;
window.joinGroupCall = joinGroupCall;
window.leaveGroupCallUI = leaveGroupCallUI;
window.toggleGroupMute = toggleGroupMute;
// Group files
window.attachGroupFile = attachGroupFile;
window.onGroupFileSelected = onGroupFileSelected;
