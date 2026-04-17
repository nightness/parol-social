// ParolNet PWA — Connection Manager, Message Queue, Peer Discovery
import { relayClient } from './state.js';
import { dbGet, dbGetAll } from './db.js';
import { hasDirectConnection, sendViaWebRTC, initWebRTC } from './webrtc.js';

// ── Connection Manager ─────────────────────────────────────
// WebSocket lives in the Service Worker so it persists when
// the page is backgrounded. connMgr delegates all WS ops via
// postMessage to the SW; status comes back via relay_status.
export const connMgr = {
    relayUrl: null,
    _swRelayConnected: false,
    _discoveredRelays: [],
    _currentRelayIndex: 0,

    _swPost(msg) {
        const sw = navigator.serviceWorker && navigator.serviceWorker.controller;
        if (sw) {
            sw.postMessage(msg);
        } else if (navigator.serviceWorker) {
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

    registerPeer(peerId) {
        this._swPost({ type: 'relay_register', peerId });
    },

    sendSignaling(type, toPeerId, payload) {
        if (!this._swRelayConnected) return false;
        this._swPost({ type: 'relay_signaling', msgType: type, to: toPeerId, payload });
        return true;
    },

    sendRelay(toPeerId, payload, token) {
        if (!this._swRelayConnected) return false;
        // Token is mandatory per PNP-001-MUST-048. The SW forwards it
        // verbatim in the `token` field of the outer frame.
        if (!token) return false;
        this._swPost({ type: 'relay_send', to: toPeerId, payload, token });
        return true;
    },

    isRelayConnected() {
        return this._swRelayConnected;
    },

    isConnected() {
        return this._swRelayConnected;
    }
};

// ── Send To Relay (convenience wrapper) ───────────────────
// `token` is the hex-encoded Privacy Pass token to spend for this frame.
// Outer-frame callers must acquire it via `tokenPool.spendOneToken()`
// before invoking this function.
export function sendToRelay(toPeerId, payload, token) {
    return connMgr.sendRelay(toPeerId, payload, token);
}

// ── Message Queue (offline resilience) ─────────────────────
const messageQueue = [];
const MAX_QUEUE_SIZE = 200;
const MAX_QUEUE_AGE_MS = 3600000; // 1 hour

export function queueMessage(toPeerId, payload) {
    if (messageQueue.length >= MAX_QUEUE_SIZE) messageQueue.shift();
    messageQueue.push({ toPeerId, payload, timestamp: Date.now() });
    console.log('[Queue] Message queued for', toPeerId.slice(0, 8), '- queue size:', messageQueue.length);
}

export function flushMessageQueue() {
    if (messageQueue.length === 0) return;
    // Late-bound import to avoid a circular dependency: messaging.js →
    // token-pool.js → connection.js. The flush path only runs on
    // reconnect so the lazy lookup cost is negligible.
    import('./token-pool.js').then(({ spendOneToken }) => {
        console.log('[Queue] Flushing', messageQueue.length, 'queued messages');
        const toFlush = messageQueue.splice(0, messageQueue.length);
        for (const msg of toFlush) {
            if (Date.now() - msg.timestamp > MAX_QUEUE_AGE_MS) continue; // expired
            let sent = false;
            if (hasDirectConnection(msg.toPeerId)) {
                sent = sendViaWebRTC(msg.toPeerId, msg.payload);
            }
            if (!sent) {
                let token;
                try { token = spendOneToken(); } catch { token = null; }
                if (token) sent = sendToRelay(msg.toPeerId, msg.payload, token);
            }
            if (!sent) {
                messageQueue.push(msg); // re-queue
            }
        }
        if (messageQueue.length > 0) {
            console.log('[Queue]', messageQueue.length, 'messages still queued');
        }
    }).catch(() => {});
}

// ── Peer Discovery ─────────────────────────────────────────
let discoveryInterval = null;

export async function discoverPeers() {
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

export function startDiscoveryInterval() {
    if (!discoveryInterval) discoveryInterval = setInterval(discoverPeers, 300000);
}
