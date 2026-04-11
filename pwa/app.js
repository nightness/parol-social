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
        toast.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:12px 24px;border-radius:8px;font-size:14px;z-index:9999;opacity:0;transition:opacity 0.3s;pointer-events:none;max-width:80%;text-align:center;';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.opacity = '1';
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => { toast.style.opacity = '0'; }, duration);
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
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
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
    // Try to restore saved identity
    let peerId = null;
    try {
        const saved = await dbGet('settings', 'identity_secret');
        if (saved && saved.value && wasm.initialize_from_key) {
            peerId = wasm.initialize_from_key(saved.value);
            console.log('Identity restored:', peerId.slice(0, 16) + '...');
        }
    } catch(e) {
        console.warn('Failed to restore identity:', e);
    }

    // If no saved identity, generate new one and save it
    if (!peerId) {
        if (wasm.initialize) {
            peerId = wasm.initialize();
            console.log('New identity generated:', peerId.slice(0, 16) + '...');

            // Save the secret key for future loads
            if (wasm.export_secret_key) {
                try {
                    const secretHex = wasm.export_secret_key();
                    await dbPut('settings', { key: 'identity_secret', value: secretHex });
                    console.log('Identity saved to IndexedDB');
                } catch(e) {
                    console.warn('Failed to save identity:', e);
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
    // Show calculator by default in dev mode (simulates decoy)
    showView('calculator');
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

    // Store the message
    const msg = {
        peerId: fromPeerId,
        direction: 'received',
        content: payload,
        timestamp: Date.now()
    };

    dbPut('messages', msg).catch(e => console.warn('Failed to store message:', e));

    // Update or create contact
    dbPut('contacts', {
        peerId: fromPeerId,
        name: fromPeerId.slice(0, 8) + '...',
        lastMessage: payload.slice(0, 50),
        lastTime: formatTime(Date.now()),
        unread: 1
    }).catch(() => {});

    // If we're viewing this peer's chat, show the message immediately
    if (currentView === 'chat' && currentPeerId === fromPeerId) {
        appendMessage(msg);
    } else {
        // Show notification
        showLocalNotification('New Message', payload.slice(0, 100), fromPeerId);
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

    // Encrypt and send via WASM
    if (wasm && wasm.send_message) {
        try {
            wasm.send_message(currentPeerId, text);
        } catch (e) {
            console.error('Send failed:', e);
        }
    }

    appendMessage(msg);

    // Send through relay
    sendToRelay(currentPeerId, text);

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

    // Extract PeerId from the scanned data
    let peerId = null;

    // Format: parolnet:<64-char-hex>
    if (data.startsWith('parolnet:')) {
        peerId = data.slice(9).trim();
    }
    // Raw 64-char hex
    else if (/^[0-9a-fA-F]{64}$/.test(data)) {
        peerId = data.toLowerCase();
    }
    // Longer hex — might be a QR payload, try WASM parse
    else if (/^[0-9a-fA-F]+$/.test(data) && data.length > 64) {
        if (wasm && wasm.parse_qr_payload) {
            try {
                wasm.parse_qr_payload(data);
                peerId = data.slice(0, 64).toLowerCase();
            } catch(e) {
                console.warn('[QR] WASM parse failed:', e);
            }
        }
        if (!peerId) {
            peerId = data.slice(0, 64).toLowerCase();
        }
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

    // Valid peer — add as contact and open chat
    showToast('Contact added!');
    dbPut('contacts', {
        peerId: peerId,
        name: peerId.slice(0, 8) + '...',
        lastMessage: 'Connected via QR',
        lastTime: formatTime(Date.now()),
        unread: 0
    }).then(() => {
        loadContacts();
        openChat(peerId);
        }).catch(e => console.warn('Failed to save contact:', e));
        return;
    }

    // Unknown QR format
    showToast('Scanned: ' + data.slice(0, 50) + (data.length > 50 ? '...' : ''));
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

    // Extract PeerId from whatever format they pasted
    let peerId = null;

    if (raw.startsWith('parolnet:')) {
        // Format: parolnet:<64-char-hex>
        peerId = raw.slice(9).trim();
    } else if (/^[0-9a-fA-F]{64}$/.test(raw)) {
        // Raw 64-char hex PeerId
        peerId = raw.toLowerCase();
    } else if (/^[0-9a-fA-F]+$/.test(raw) && raw.length > 64) {
        // Full QR payload hex — try WASM parse
        if (wasm && wasm.parse_qr_payload) {
            try {
                wasm.parse_qr_payload(raw);
                // If parse succeeds, the payload contains an identity key
                // Use the raw hex as an identifier for now
                peerId = raw.slice(0, 64).toLowerCase();
            } catch(e) { /* not a valid payload */ }
        }
        if (!peerId) {
            // Take first 64 hex chars as PeerId
            peerId = raw.slice(0, 64).toLowerCase();
        }
    }

    if (!peerId || peerId.length !== 64) {
        showToast('Invalid code. Copy the full code from your contact.');
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
        navigator.serviceWorker.register('sw.js')
            .then(reg => {
                console.log('SW registered:', reg.scope);
            })
            .catch(err => {
                console.error('SW registration failed:', err);
            });
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
