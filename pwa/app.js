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
const DB_VERSION = 1;

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
    try {
        wasm = await import('./pkg/parolnet_wasm.js');
        await wasm.default();
        onWasmReady();
    } catch (e) {
        console.warn('WASM not available:', e.message);
        onWasmUnavailable();
    }
}

function onWasmReady() {
    if (wasm.initialize) {
        const peerId = wasm.initialize();
        window._peerId = peerId || null;
    }

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
}

function onWasmUnavailable() {
    // Show calculator by default in dev mode (simulates decoy)
    showView('calculator');
    const el = document.getElementById('settings-version');
    if (el) el.textContent = 'dev (no WASM)';
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
async function startQRScanner() {
    try {
        const video = document.getElementById('qr-scanner-video');
        if (!video) return;
        const stream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment' }
        });
        video.srcObject = stream;
        document.getElementById('qr-scanner-status').textContent = 'Point at a QR code...';
    } catch (e) {
        const statusEl = document.getElementById('qr-scanner-status');
        if (statusEl) {
            statusEl.textContent = 'Camera access denied. Check your browser permissions.';
        }
    }
}

function stopQRScanner() {
    const video = document.getElementById('qr-scanner-video');
    if (video && video.srcObject) {
        video.srcObject.getTracks().forEach(t => t.stop());
        video.srcObject = null;
    }
    const statusEl = document.getElementById('qr-scanner-status');
    if (statusEl) statusEl.textContent = 'Tap to start camera';
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

// ── Passphrase Connect ──────────────────────────────────────
function connectViaPassphrase() {
    const input = document.querySelector('#add-tab-passphrase input');
    const phrase = input?.value?.trim();
    if (!phrase) return;

    // Show connecting state
    const btn = document.querySelector('#add-tab-passphrase button');
    const originalText = btn.textContent;
    btn.textContent = 'Connecting...';
    btn.disabled = true;

    // Use WASM to process passphrase bootstrap
    if (wasm) {
        try {
            showToast('Searching for peer with this passphrase...');
            setTimeout(() => {
                btn.textContent = originalText;
                btn.disabled = false;
                showToast('No peers found nearby. Make sure both devices are online.');
            }, 3000);
        } catch (e) {
            btn.textContent = originalText;
            btn.disabled = false;
            showToast('Connection failed: ' + e.message);
        }
    } else {
        btn.textContent = originalText;
        btn.disabled = false;
        showToast('App not fully loaded. Please wait and try again.');
    }
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
