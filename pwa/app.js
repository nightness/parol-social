// ParolNet PWA — Main Application
// Zero-dependency vanilla JS messaging app with calculator decoy mode.

// ── State ───────────────────────────────────────────────────
let wasm = null;
let currentView = 'loading';
let currentPeerId = null;
let currentCallId = null;
let localStream = null;
let platform = detectPlatform();

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
    }
}

// ── Calculator ──────────────────────────────────────────────
let calcDisplay = '0';
let calcExpression = '';
let calcBuffer = '';

function calcPress(key) {
    if (key === 'C') {
        calcDisplay = '0';
        calcExpression = '';
        calcBuffer = '';
    } else if (key === '=') {
        // Check unlock code BEFORE showing result
        if (calcBuffer === '999999') {
            // PANIC WIPE — immediate, no confirmation
            executePanicWipe();
            return;
        }
        if (wasm && wasm.is_decoy_enabled && wasm.is_decoy_enabled() &&
            wasm.verify_unlock_code && wasm.verify_unlock_code(calcBuffer)) {
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
            // Safe evaluation via Function constructor
            const expr = calcExpression.replace(/[^0-9+\-*/().]/g, '');
            const result = new Function('return ' + expr)();
            calcDisplay = String(result !== undefined && result !== null ? result : 0);
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
            const expr = calcExpression.replace(/[^0-9+\-*/().]/g, '');
            calcDisplay = String(new Function('return ' + expr)());
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
const DB_VERSION = 2;

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
            };
            req.onsuccess = () => { if (!resolved) { resolved = true; clearTimeout(timeout); resolve(req.result); } };
            req.onerror = () => { if (!resolved) { resolved = true; clearTimeout(timeout); reject(req.error); } };
            req.onblocked = () => { if (!resolved) { resolved = true; clearTimeout(timeout); reject(new Error('IndexedDB blocked')); } };
        } catch(e) {
            if (!resolved) { resolved = true; clearTimeout(timeout); reject(e); }
        }
    });
}

async function dbGetAll(storeName) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function dbPut(storeName, item) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        const req = store.put(item);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function dbGet(storeName, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const req = store.get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
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

// ── WASM Loading ────────────────────────────────────────────
async function loadWasm() {
    const statusEl = document.getElementById('loading-status');
    try {
        if (statusEl) statusEl.textContent = 'Loading crypto module...';
        wasm = await import('./pkg/parolnet_wasm.js');
        if (statusEl) statusEl.textContent = 'Initializing...';
        await wasm.default();
        if (statusEl) statusEl.textContent = 'Restoring identity...';
        await onWasmReady();
    } catch (e) {
        console.warn('WASM not available:', e.message);
        showToast('WASM load failed: ' + e.message);
        if (statusEl) statusEl.textContent = 'Running without crypto (' + e.message + ')';
        onWasmUnavailable();
    }
}

async function onWasmReady() {
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

    if (wasm.version) {
        const el = document.getElementById('settings-version');
        if (el) el.textContent = wasm.version();
    }

    // Check if decoy mode is enabled
    if (wasm.is_decoy_enabled && wasm.is_decoy_enabled()) {
        showView('calculator');
    } else {
        showView('contacts');
    }
    loadContacts();
    // Pre-render QR code so it's ready when user opens Add Contact
    renderBootstrapQR();

    // Connect to relay server
    connectRelay();
}

function onWasmUnavailable() {
    // Show contacts view — calculator only shown when decoy mode is explicitly enabled
    showView('contacts');
    const el = document.getElementById('settings-version');
    if (el) el.textContent = 'dev (no WASM)';

    // Connect to relay server even without WASM (plaintext testing)
    connectRelay();
}

// ── WebSocket Relay Connection ─────────────────────────────
let ws = null;
let wsReconnectTimer = null;
let wsReconnectDelay = 1000;

function connectRelay() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    // Determine WebSocket URL from current page location
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = protocol + '//' + location.host + '/ws';

    try {
        ws = new WebSocket(wsUrl);
    } catch(e) {
        console.warn('WebSocket connect failed:', e);
        scheduleReconnect();
        return;
    }

    ws.onopen = () => {
        console.log('Relay connected');
        wsReconnectDelay = 1000; // reset backoff
        updateConnectionStatus(true);

        // Register with our PeerId
        if (window._peerId) {
            ws.send(JSON.stringify({
                type: 'register',
                peer_id: window._peerId
            }));
        }
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleRelayMessage(msg);
        } catch(e) {
            console.warn('Invalid relay message:', e);
        }
    };

    ws.onclose = () => {
        console.log('Relay disconnected');
        updateConnectionStatus(false);
        scheduleReconnect();
    };

    ws.onerror = (e) => {
        console.warn('Relay error');
        updateConnectionStatus(false);
    };
}

function scheduleReconnect() {
    if (wsReconnectTimer) return;
    wsReconnectTimer = setTimeout(() => {
        wsReconnectTimer = null;
        wsReconnectDelay = Math.min(wsReconnectDelay * 2, 30000); // exponential backoff, max 30s
        connectRelay();
    }, wsReconnectDelay);
}

function updateConnectionStatus(connected) {
    const dot = document.getElementById('connection-dot');
    if (dot) {
        dot.className = 'connection-dot ' + (connected ? 'online' : 'offline');
    }
}

function handleRelayMessage(msg) {
    switch (msg.type) {
        case 'registered':
            console.log('Registered with relay. Online peers:', msg.online_peers);
            break;

        case 'message':
            // Incoming message from another peer
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

function onIncomingMessage(fromPeerId, payload) {
    if (!fromPeerId || !payload) return;

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
                    }).then(() => {
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
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        showToast('Not connected to relay');
        return false;
    }
    ws.send(JSON.stringify({
        type: 'message',
        to: toPeerId,
        payload: payload
    }));
    return true;
}

// ── WebRTC Peer Connections ────────────────────────────────
const rtcConnections = {}; // peerId -> { pc: RTCPeerConnection, dc: RTCDataChannel, status: 'connecting'|'open'|'closed' }

const RTC_CONFIG = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
    ]
};

async function initWebRTC(peerId, isInitiator) {
    if (rtcConnections[peerId] && rtcConnections[peerId].status === 'open') return;

    const pc = new RTCPeerConnection(RTC_CONFIG);
    rtcConnections[peerId] = { pc, dc: null, status: 'connecting' };

    // ICE candidate handling
    pc.onicecandidate = (event) => {
        if (event.candidate) {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'rtc_ice',
                    to: peerId,
                    payload: JSON.stringify(event.candidate)
                }));
            }
        }
    };

    pc.onconnectionstatechange = () => {
        console.log('[WebRTC]', peerId.slice(0,8), 'state:', pc.connectionState);
        if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
            cleanupRTC(peerId);
        }
    };

    if (isInitiator) {
        // Create data channel
        const dc = pc.createDataChannel('parolnet', { ordered: true });
        setupDataChannel(peerId, dc);

        // Create and send offer
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'rtc_offer',
                to: peerId,
                payload: JSON.stringify(offer)
            }));
        }
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
        rtcConnections[peerId].status = 'open';
        updatePeerConnectionUI(peerId, 'direct');
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
            if (msg.type === 'chat') {
                onIncomingMessage(peerId, msg.payload);
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

    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'rtc_answer',
            to: fromPeerId,
            payload: JSON.stringify(answer)
        }));
    }
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

// ── Chat View ───────────────────────────────────────────────
function openChat(peerId) {
    currentPeerId = peerId;
    window.currentPeerId = peerId;
    showView('chat');

    const nameEl = document.getElementById('chat-peer-name');
    if (nameEl) {
        nameEl.textContent = peerId.length > 20 ? peerId.slice(0, 16) + '...' : peerId;
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

    // Encrypt and send — try WebRTC first, fall back to relay
    let sent = false;
    if (wasm && wasm.encrypt_message && wasm.has_session && wasm.has_session(currentPeerId)) {
        try {
            const encoder = new TextEncoder();
            const plainBytes = encoder.encode(text);
            const encrypted = wasm.encrypt_message(currentPeerId, plainBytes);
            // Convert Uint8Array to hex for JSON transport
            const hexPayload = Array.from(encrypted).map(b => b.toString(16).padStart(2, '0')).join('');
            const encPayload = 'enc:' + hexPayload;
            // Try WebRTC first, fall back to relay
            if (hasDirectConnection(currentPeerId)) {
                sent = sendViaWebRTC(currentPeerId, encPayload);
            }
            if (!sent) {
                sent = sendToRelay(currentPeerId, encPayload);
            }
        } catch (e) {
            console.error('Encryption failed, sending plaintext:', e);
        }
    }
    if (!sent) {
        // No session or encryption failed — send plaintext (legacy/fallback)
        // Try WebRTC first, fall back to relay
        if (hasDirectConnection(currentPeerId)) {
            sent = sendViaWebRTC(currentPeerId, text);
        }
        if (!sent) {
            sendToRelay(currentPeerId, text);
        }
    }

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
    if (msg.isHtml) {
        div.innerHTML = `<div class="message-bubble">${msg.content}</div><div class="message-time">${formatTime(msg.timestamp)}</div>`;
    } else {
        div.innerHTML = `<div class="message-bubble" dir="auto">${escapeHtml(msg.content)}</div><div class="message-time">${formatTime(msg.timestamp)}</div>`;
    }
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
    appendMessage({
        direction: 'sent',
        content: `<div id="${msgId}" class="file-transfer">
            <div class="file-name">\ud83d\udcce ${escapeHtml(file.name)}</div>
            <div class="file-size">${formatSize(file.size)}</div>
            <div class="file-progress"><div class="file-progress-bar" style="width:0%"></div></div>
            <div class="file-status">Preparing...</div>
        </div>`,
        timestamp: Date.now(),
        isHtml: true
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

    // Check for BarcodeDetector (Chrome 83+, Safari 16.4+, Android)
    const hasBarcodeAPI = 'BarcodeDetector' in window;

    try {
        const stream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }
        });
        video.srcObject = stream;
        await video.play();

        if (hasBarcodeAPI) {
            // Native QR detection — zero library code needed
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
            }, 250); // Scan 4 times per second
        } else if (typeof jsQR === 'function') {
            // Fallback: jsQR pure JS decoder (works on iOS Safari and all browsers)
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
                if (code && code.data && isValidQRData(code.data)) {
                    console.log('[QR] jsQR decoded:', code.data.slice(0, 80));
                    stopQRScanner();
                    handleScannedQR(code.data);
                }
            }, 250);
        } else {
            // Neither BarcodeDetector nor JS decoder available — fall back to manual entry
            if (statusEl) {
                statusEl.innerHTML = 'Your browser doesn\'t support QR scanning.<br>Ask your contact to share their code, then paste it in the <strong>Paste Code</strong> tab.';
            }
        }
    } catch (e) {
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

    // Try full QR payload first (hex-encoded CBOR with ratchet key)
    if (/^[0-9a-fA-F]+$/.test(data) && data.length > 64 && wasm && wasm.process_scanned_qr) {
        try {
            const result = wasm.process_scanned_qr(data);
            peerId = result.peer_id;
            sessionEstablished = true;
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
    }).then(() => {
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
    if (canvas && typeof makeQR === 'function' && typeof renderQRToCanvas === 'function') {
        try {
            const qr = makeQR(data);
            renderQRToCanvas(qr, canvas, 2);
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
}

function enableDecoyMode() {
    const input = document.getElementById('decoy-code-input');
    const code = input ? input.value : '00000';

    if (wasm && wasm.set_unlock_code) {
        wasm.set_unlock_code(code);
    }

    // Store preference locally as fallback
    try {
        localStorage.setItem('decoy_enabled', 'true');
    } catch {
        // storage may be unavailable
    }

    showToast('Decoy mode enabled. The app will appear as a calculator on next launch.');
}

// ── Panic Wipe ──────────────────────────────────────────────
function executePanicWipe() {
    // Clear everything immediately — no confirmation
    try { localStorage.clear(); } catch {}
    try { sessionStorage.clear(); } catch {}

    if (window.indexedDB) {
        indexedDB.databases().then(dbs => {
            dbs.forEach(db => indexedDB.deleteDatabase(db.name));
        }).catch(() => {});
    }

    if (wasm) {
        try { wasm.panic_wipe(); } catch {}
    }

    if ('caches' in window) {
        caches.keys().then(names => names.forEach(n => caches.delete(n))).catch(() => {});
    }

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.getRegistrations().then(regs => {
            regs.forEach(r => r.unregister());
        }).catch(() => {});
    }

    // Blank the screen — looks like calculator showing zero
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#000;color:#fff;font-size:24px;">0</div>';
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

// ── Service Worker Registration ─────────────────────────────
function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
        // First: unregister any old service workers that might be serving stale content
        navigator.serviceWorker.getRegistrations().then(regs => {
            regs.forEach(reg => {
                reg.unregister();
                console.log('Unregistered old SW:', reg.scope);
            });
        });
        // Clear all caches left by old SWs
        if ('caches' in window) {
            caches.keys().then(names => {
                names.forEach(name => {
                    caches.delete(name);
                    console.log('Cleared cache:', name);
                });
            });
        }
        // NOTE: Service Worker registration disabled during development.
        // The SW was caching aggressively and causing stale content on iOS.
        // Re-enable for production by uncommenting:
        // navigator.serviceWorker.register('sw.js').then(reg => {
        //     console.log('SW registered:', reg.scope);
        // });
    }
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
    registerServiceWorker();
    showToast('Starting ParolNet...', 2000);
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

// Export for onclick handlers
window.calcPress = calcPress;
window.sendMessage = sendMessage;
window.openChat = openChat;
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
window.currentPeerId = null;
