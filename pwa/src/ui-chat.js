// ParolNet PWA — Contact List, Chat, Call UI, File Transfer, QR, Add Contact
import {
    wasm, cryptoStore, currentView, currentPeerId, setCurrentPeerId,
    currentCallId, setCurrentCallId, localStream, setLocalStream
} from './state.js';
import {
    showToast, escapeHtml, escapeAttr, formatTime, formatSize,
    generateMsgId, requestNotificationPermission, showLocalNotification
} from './utils.js';
import { dbPut, dbGet, dbGetAll, dbGetByIndex } from './db.js';
import { showView } from './views.js';
import { initWebRTC, hasDirectConnection, sendViaWebRTC, rtcConnections,
         seenGossipMessages, markGossipSeen } from './webrtc.js';
import { sendToRelay, connMgr, queueMessage } from './connection.js';
import { t } from './i18n.js';
import { MSG_TYPE_CHAT, MSG_TYPE_SYSTEM } from './protocol-constants.js';

// ── Session Persistence ──────────────────────────────────
function persistSessions() {
    if (!wasm || !wasm.export_sessions) return;
    try {
        const blob = wasm.export_sessions();
        if (blob) dbPut('settings', { key: 'sessions_blob', value: blob });
    } catch(e) { console.warn('Session persist failed:', e.message); }
}

// ── Contact List ────────────────────────────────────────────
export async function loadContacts() {
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
        list.innerHTML = `<div class="empty-state"><p>${escapeHtml(t('empty.noMessages'))}</p><p>${escapeHtml(t('empty.addContact'))}</p></div>`;
        return;
    }
    list.innerHTML = contacts.map(c => `
        <div class="contact-item" onclick="openChat('${escapeAttr(c.peerId)}')">
            <div class="contact-avatar">${escapeHtml(c.name[0]?.toUpperCase() || '?')}</div>
            <div class="contact-info">
                <div class="contact-name" dir="auto">${escapeHtml(c.name)}</div>
                <div class="contact-last-msg" dir="auto">${escapeHtml(c.lastMessage || t('contact.noMessagesYet'))}</div>
            </div>
            <div class="contact-meta">
                <div class="contact-time">${escapeHtml(c.lastTime || '')}</div>
                ${c.unread ? `<div class="unread-badge">${c.unread}</div>` : ''}
            </div>
        </div>
    `).join('');
}

// ── Address Book ────────────────────────────────────────────
export async function loadAddressBook() {
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
        list.innerHTML = `<div class="empty-state"><p>${escapeHtml(t('empty.noContacts'))}</p><p>${escapeHtml(t('empty.addContact'))}</p></div>`;
        return;
    }
    list.innerHTML = contacts.map(c => {
        const pid = escapeAttr(c.peerId);
        return `
        <div class="contact-item address-book-item" data-peerid="${pid}">
            <div class="contact-avatar">${escapeHtml(c.name[0]?.toUpperCase() || '?')}</div>
            <div class="contact-info" onclick="openChat('${pid}')">
                <div class="contact-name" dir="auto">${escapeHtml(c.name)}</div>
                <div class="contact-peer-id">${escapeHtml(c.peerId.slice(0, 16) + '...')}</div>
            </div>
            <div class="contact-actions">
                <button onclick="openChat('${pid}')" title="${escapeAttr(t('btn.message'))}">💬</button>
                <button onclick="initiateCall('${pid}', false)" title="${escapeAttr(t('btn.voiceCall'))}">📞</button>
                <button onclick="initiateCall('${pid}', true)" title="${escapeAttr(t('btn.videoCall'))}">📹</button>
                <button onclick="renameContact('${pid}')" title="${escapeAttr(t('btn.rename'))}">✏️</button>
            </div>
            <button class="contact-overflow-btn" onclick="toggleContactMenu(this)">⋮</button>
            <div class="contact-overflow-menu hidden">
                <button onclick="openChat('${pid}')">${escapeHtml(t('btn.message'))}</button>
                <button onclick="initiateCall('${pid}', false)">${escapeHtml(t('btn.voiceCall'))}</button>
                <button onclick="initiateCall('${pid}', true)">${escapeHtml(t('btn.videoCall'))}</button>
                <button onclick="renameContact('${pid}')">${escapeHtml(t('btn.rename'))}</button>
            </div>
        </div>`;
    }).join('');
}

export function toggleContactMenu(btn) {
    const menu = btn.nextElementSibling;
    if (!menu) return;
    // Close any other open menus
    document.querySelectorAll('.contact-overflow-menu').forEach(m => {
        if (m !== menu) m.classList.add('hidden');
    });
    menu.classList.toggle('hidden');
    // Close on outside click
    if (!menu.classList.contains('hidden')) {
        const close = (e) => {
            if (!menu.contains(e.target) && e.target !== btn) {
                menu.classList.add('hidden');
                document.removeEventListener('click', close);
            }
        };
        setTimeout(() => document.addEventListener('click', close), 0);
    }
}

export async function renameContact(peerId) {
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
    if (newName === null) return;
    const trimmed = newName.trim();
    if (!trimmed) { showToast('Name cannot be empty'); return; }

    contact.name = trimmed;
    try {
        await dbPut('contacts', contact);
        showToast('Contact renamed');
        loadAddressBook();
        if (window.currentPeerId === peerId) {
            const nameEl = document.getElementById('chat-peer-name');
            if (nameEl) nameEl.textContent = trimmed;
        }
    } catch (e) {
        showToast('Failed to rename: ' + e.message);
    }
}

// ── Chat View ───────────────────────────────────────────────
export function openChat(peerId) {
    setCurrentPeerId(peerId);
    showView('chat');

    const nameEl = document.getElementById('chat-peer-name');
    if (nameEl) {
        nameEl.textContent = peerId.length > 20 ? peerId.slice(0, 16) + '...' : peerId;
        dbGetAll('contacts').then(contacts => {
            const c = contacts.find(x => x.peerId === peerId);
            if (c && c.name && nameEl) nameEl.textContent = c.name;
        }).catch(() => {});
    }
    loadMessages(peerId);

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

export async function sendMessage() {
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

    try { await dbPut('messages', msg); } catch(e) { console.warn(e); }

    appendMessage(msg);

    // Encrypt, wrap in a PNP-001 padded envelope, and send.
    // Every wire frame leaving the client is bucket-padded to 256/1024/4096/16384 bytes.
    let sent = false;
    let relayPayload = null;
    if (!wasm || !wasm.envelope_encode || !wasm.has_session || !wasm.has_session(currentPeerId)) {
        showToast('Cannot send: secure session not established with this contact');
        return;
    }
    try {
        const encoder = new TextEncoder();
        const plainBytes = encoder.encode(text);
        const nowSecs = BigInt(Math.floor(Date.now() / 1000));
        relayPayload = wasm.envelope_encode(currentPeerId, MSG_TYPE_CHAT, plainBytes, nowSecs);
        persistSessions();
        if (hasDirectConnection(currentPeerId)) {
            sent = sendViaWebRTC(currentPeerId, relayPayload);
        }
        if (!sent) {
            sent = sendToRelay(currentPeerId, relayPayload);
        }
    } catch (e) {
        console.error('Envelope encode failed:', e);
        showToast('Encryption failed — message not sent');
        return;
    }
    if (!sent) {
        queueMessage(currentPeerId, relayPayload);
        showToast('Message queued — will send when connected');
    }

    // Broadcast via gossip mesh for redundancy
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

    input.value = '';
    input.focus();

    try {
        await dbPut('contacts', {
            peerId: currentPeerId,
            name: currentPeerId.slice(0, 8) + '...',
            lastMessage: text,
            lastTime: formatTime(Date.now()),
            unread: 0
        });
    } catch(e) { console.warn(e); }

    if ('Notification' in window && Notification.permission === 'default') {
        requestNotificationPermission();
    }
}

export function appendMessage(msg) {
    const container = document.getElementById('message-list');
    if (!container) return;

    const div = document.createElement('div');
    div.className = `message ${msg.direction}`;
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    if (msg.domContent) {
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

export async function initiateCall(peerId, withVideo) {
    if (!peerId) peerId = currentPeerId;
    if (!peerId) return;
    setCurrentCallId(null);

    try {
        const constraints = { audio: true };
        if (withVideo) constraints.video = { width: 320, height: 240 };
        setLocalStream(await navigator.mediaDevices.getUserMedia(constraints));

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

    if (wasm && wasm.start_call) {
        try {
            setCurrentCallId(wasm.start_call(peerId));
        } catch (e) {
            showToast('Call failed: ' + e.message);
            stopLocalMedia();
            return;
        }
    }

    // Notify the peer of incoming call
    const callPayload = JSON.stringify({
        _pn_type: 'call_offer',
        callId: currentCallId,
        withVideo: !!withVideo
    });
    sendToRelay(peerId, callPayload);

    showView('call');
    const nameEl = document.getElementById('call-peer-name');
    if (nameEl) nameEl.textContent = peerId.length > 20 ? peerId.slice(0, 16) + '...' : peerId;

    const statusEl = document.getElementById('call-status');
    if (statusEl) statusEl.textContent = 'Calling...';

    startCallTimer();
}

export function answerIncomingCall(callId) {
    if (wasm && wasm.answer_call) {
        wasm.answer_call(callId);
    }
    const statusEl = document.getElementById('call-status');
    if (statusEl) statusEl.textContent = 'Connected';
    startCallTimer();
}

export function hangupCall() {
    if (wasm && wasm.hangup_call && currentCallId) {
        try { wasm.hangup_call(currentCallId); } catch(e) { console.warn(e); }
    }
    stopLocalMedia();
    stopCallTimer();
    setCurrentCallId(null);
    showView(currentPeerId ? 'chat' : 'contacts');
}

function stopLocalMedia() {
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        setLocalStream(null);
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

export function toggleMute() {
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

export function toggleCamera() {
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
export function attachFile() {
    const input = document.getElementById('file-input');
    if (input) input.click();
}

export function onFileSelected(event) {
    const file = event.target.files[0];
    if (!file || !currentPeerId) return;

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

export async function startQRScanner() {
    const video = document.getElementById('qr-scanner-video');
    const statusEl = document.getElementById('qr-scanner-status');
    if (!video) return;

    const hasBarcodeAPI = 'BarcodeDetector' in window;

    try {
        const stream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }
        });
        video.srcObject = stream;
        await video.play();

        if (video.videoWidth === 0) {
            await new Promise(resolve => {
                video.addEventListener('loadedmetadata', resolve, { once: true });
                setTimeout(resolve, 2000);
            });
        }

        console.log('[QR] path:', hasBarcodeAPI ? 'BarcodeDetector' : 'jsQR',
                    'videoSize:', video.videoWidth + 'x' + video.videoHeight);

        if (hasBarcodeAPI) {
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
                } catch (e) {}
            }, 250);
        } else if (typeof jsQR === 'function') {
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

export function stopQRScanner() {
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

function isValidQRData(data) {
    if (!data || typeof data !== 'string') return false;
    if (data.length < 10) return false;
    if (data.startsWith('parolnet:')) return true;
    if (/^[0-9a-fA-F]+$/.test(data) && data.length >= 64) return true;
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

    if (/^[0-9a-fA-F]+$/.test(data) && data.length > 64 && wasm && wasm.process_scanned_qr) {
        try {
            const result = wasm.process_scanned_qr(data);
            peerId = result.peer_id;
            bootstrapSecret = result.bootstrap_secret;
            sessionEstablished = true;
            console.log('[QR] Session established with:', peerId.slice(0, 8));
            persistSessions();
        } catch(e) {
            console.warn('[QR] process_scanned_qr failed:', e);
        }
    }

    if (!peerId && data.startsWith('parolnet:')) {
        peerId = data.slice(9).trim();
    }
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

    showToast(sessionEstablished ? 'Secure contact added!' : 'Contact added (no encryption)');
    dbPut('contacts', {
        peerId: peerId,
        name: peerId.slice(0, 8) + '...',
        lastMessage: sessionEstablished ? 'Encrypted session established' : 'Connected via QR',
        lastTime: formatTime(Date.now()),
        unread: 0
    }).then(async () => {
        loadContacts();
        if (sessionEstablished && wasm && wasm.get_public_key && wasm.envelope_encode) {
            const ourIk = wasm.get_public_key();
            // Carry our identity key as the SYSTEM payload; the msg_type in the
            // envelope replaces the old "__system:bootstrap:" string marker.
            const encoder = new TextEncoder();
            const nowSecs = BigInt(Math.floor(Date.now() / 1000));
            try {
                const envelope = wasm.envelope_encode(peerId, MSG_TYPE_SYSTEM, encoder.encode('bootstrap:' + ourIk), nowSecs);
                persistSessions();
                if (!sendToRelay(peerId, envelope)) {
                    queueMessage(peerId, envelope);
                }
            } catch(e) {
                console.warn('[Bootstrap] envelope_encode failed:', e);
            }
        }
        openChat(peerId);
    }).catch(e => console.warn('Failed to save contact:', e));
}

export function renderBootstrapQR() {
    const canvas = document.getElementById('qr-canvas');
    const codeEl = document.getElementById('qr-share-code');

    let data = '';

    if (wasm && wasm.get_public_key) {
        try {
            const pubKey = wasm.get_public_key();
            if (pubKey && pubKey.length > 0) {
                if (wasm.generate_qr_payload) {
                    data = wasm.generate_qr_payload(pubKey, null);
                }
                if (!data) {
                    data = 'parolnet:' + pubKey;
                }
            }
        } catch(e) {
            console.warn('QR payload generation failed:', e);
        }
    }

    if (!data && window._peerId) {
        data = 'parolnet:' + window._peerId;
    }

    if (!data) {
        if (wasm && wasm.generate_identity) {
            data = 'parolnet:' + wasm.generate_identity();
        } else {
            data = 'parolnet:app-not-loaded';
        }
    }

    if (codeEl) {
        codeEl.textContent = data;
        codeEl.style.wordBreak = 'break-all';
    }

    if (canvas && typeof qrcode === 'function') {
        try {
            const qr = qrcode(0, 'M');
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

export function copyBootstrapCode() {
    const codeEl = document.getElementById('qr-share-code');
    if (!codeEl || !codeEl.textContent) {
        showToast('No code to copy');
        return;
    }
    navigator.clipboard.writeText(codeEl.textContent).then(() => {
        showToast('Code copied to clipboard');
    }).catch(() => {
        const range = document.createRange();
        range.selectNodeContents(codeEl);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        showToast('Select and copy the highlighted text');
    });
}

// ── Add Contact Tabs ────────────────────────────────────────
export function showAddTab(tabName) {
    document.querySelectorAll('.add-tab-content').forEach(t => t.classList.add('hidden'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));

    const tab = document.getElementById('add-tab-' + tabName);
    if (tab) tab.classList.remove('hidden');

    const btn = document.querySelector(`.tab[data-tab="${tabName}"]`);
    if (btn) btn.classList.add('active');

    if (tabName === 'qr-scan') {
        startQRScanner();
    } else {
        stopQRScanner();
    }

    if (tabName === 'qr-show') {
        renderBootstrapQR();
    }
}

// ── Add Contact by Code ────────────────────────────────────
export function connectViaPassphrase() {
    const input = document.querySelector('#add-tab-passphrase input');
    const raw = input?.value?.trim();
    if (!raw) {
        showToast('Paste the code from your contact');
        return;
    }

    let clean = raw.replace(/[\s\n\r"']/g, '');
    console.log('[AddContact] Input cleaned:', clean.slice(0, 80), 'length:', clean.length);

    let peerId = null;

    if (clean.startsWith('parolnet:')) {
        peerId = clean.slice(9).trim();
    } else if (/^[0-9a-fA-F]{64}$/.test(clean)) {
        peerId = clean.toLowerCase();
    } else if (/^[0-9a-fA-F]+$/.test(clean) && clean.length >= 64) {
        peerId = clean.slice(0, 64).toLowerCase();
    }

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
        // No wire notification: manual add runs before any session exists, and
        // PNP-001 forbids sending unencrypted/unpadded frames. The peer will
        // pick us up via QR bootstrap or normal message flow.
        openChat(peerId);
    }).catch(e => {
        showToast('Failed: ' + e.message);
    });
}

// ── Contact Search ──────────────────────────────────────────
export function initContactSearch() {
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
