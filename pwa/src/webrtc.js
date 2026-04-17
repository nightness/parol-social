// ParolNet PWA — WebRTC Peer Connections & Gossip Mesh
import { currentView, currentPeerId } from './state.js';
import { showToast } from './utils.js';
import { dbGet, dbPut, dbDelete } from './db.js';
import { telemetry } from './telemetry.js';
import { connMgr, flushMessageQueue } from './connection.js';
import { onIncomingMessage } from './messaging.js';

// ── WebRTC Peer Connections ────────────────────────────────
export const rtcConnections = {}; // peerId -> { pc, dc, status }

// No third-party STUN by default. Contacting public STUN (e.g. Google) leaks
// the client IP to the STUN operator even when the returned candidate is later
// filtered by iceTransportPolicy. Own TURN is fetched from the relay at boot
// (see fetchTurnCredentials below) and populates customIceServers.
const DEFAULT_STUN_SERVERS = [];

let customIceServers = null;

// Privacy mode: when enabled, only relay (TURN) candidates are used, so no
// direct peer connection can expose the client's public IP to the remote peer.
// Default ON — opt-out only. ParolNet's threat model requires that the IP
// never leak to a contact; accepting call-quality degradation is the safer
// trade-off when TURN is unavailable.
let webrtcPrivacyMode = true;

function getRtcConfig() {
    const config = {
        iceServers: customIceServers || DEFAULT_STUN_SERVERS
    };
    if (webrtcPrivacyMode) {
        config.iceTransportPolicy = 'relay';
    }
    return config;
}

export async function loadCustomStunServers() {
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

export async function setCustomStunServers(serversJson) {
    try {
        const servers = JSON.parse(serversJson);
        if (!Array.isArray(servers) || servers.length === 0) {
            throw new Error('Expected a non-empty array of ICE servers');
        }
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

export async function clearCustomStunServers() {
    customIceServers = null;
    try { await dbDelete('settings', 'custom_stun_servers'); } catch(e) {}
    showToast('STUN/TURN servers reset to defaults');
}

export async function setWebRTCPrivacyMode(enabled) {
    webrtcPrivacyMode = enabled;
    await dbPut('settings', { key: 'webrtc_privacy_mode', value: String(enabled) });
    // Close existing connections so new ones use updated config
    Object.keys(rtcConnections).forEach(cleanupRTC);
    updateWebRTCPrivacyUI();
}

export function updateWebRTCPrivacyUI() {
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

// Default fallback TURN/STUN server (parol.social's public TURN)
const FALLBACK_TURN_URL = 'https://parol.social/turn-credentials';

export async function fetchTurnCredentials() {
    // Try connected relay first, then fall back to parol.social
    const urls = [];
    const relayUrl = connMgr && connMgr.relayUrl;
    if (relayUrl) {
        urls.push(relayUrl.replace(/^ws(s?):/, 'http$1:').replace(/\/ws\/?$/, '') + '/turn-credentials');
    }
    urls.push(FALLBACK_TURN_URL);

    for (const url of urls) {
        try {
            const resp = await fetch(url);
            if (!resp.ok) continue;
            const creds = await resp.json();
            if (creds.uris && creds.uris.length > 0) {
                const stunUris = creds.uris.filter(u => u.startsWith('stun:'));
                const turnUris = creds.uris.filter(u => !u.startsWith('stun:'));
                const iceServers = [];
                // Add STUN servers (ours replace Google defaults)
                if (stunUris.length > 0) {
                    iceServers.push(...stunUris.map(u => ({ urls: u })));
                } else {
                    iceServers.push(...DEFAULT_STUN_SERVERS);
                }
                // Add TURN servers with credentials
                iceServers.push(...turnUris.map(u => ({
                    urls: u,
                    username: creds.username,
                    credential: creds.credential
                })));
                customIceServers = iceServers;
                console.log('[WebRTC] TURN credentials from', url, '- TTL:', creds.ttl);
                return;
            }
        } catch (e) {
            console.warn('[WebRTC] TURN fetch failed for', url, e.message);
        }
    }
    console.warn('[WebRTC] No TURN available, using STUN only');
}

export async function initWebRTC(peerId, isInitiator) {
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
            if (isInitiator) {
                const delay = 2000 + Math.random() * 3000;
                setTimeout(() => {
                    console.log('[WebRTC] Auto-reconnecting to', peerId.slice(0,8));
                    initWebRTC(peerId, true).catch(e =>
                        console.warn('[WebRTC] Reconnect failed:', e)
                    );
                }, delay);
            }
        } else if (pc.connectionState === 'closed') {
            cleanupRTC(peerId);
        }
    };

    if (isInitiator) {
        const dc = pc.createDataChannel('parolnet', { ordered: true });
        setupDataChannel(peerId, dc);

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        connMgr.sendSignaling('rtc_offer', peerId, JSON.stringify(offer));
    } else {
        pc.ondatachannel = (event) => {
            setupDataChannel(peerId, event.channel);
        };
    }
}

function setupDataChannel(peerId, dc) {
    rtcConnections[peerId].dc = dc;

    dc.onopen = () => {
        console.log('[WebRTC] Data channel open with', peerId.slice(0,8));
        try {
            dc.send(JSON.stringify({ type: 'identity', peerId: window._peerId }));
        } catch(e) {}
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
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'identity' && msg.peerId) {
                const fullPeerId = msg.peerId;
                if (peerId !== fullPeerId && (peerId.startsWith('pending_') || fullPeerId.startsWith(peerId.slice(0, 40)))) {
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
                if (!msg.msgId || !msg.payload || seenGossipMessages.has(msg.msgId)) return;

                const isForUs = !msg.to || msg.to === window._peerId;
                if (isForUs) {
                    onIncomingMessage(msg.from || peerId, msg.payload);
                }

                if (msg.ttl > 0) {
                    gossipForward(peerId, msg.msgId, msg.to, msg.payload, msg.ttl - 1);
                }
            }
        } catch(e) {
            onIncomingMessage(peerId, event.data);
        }
    };
}

export async function handleRTCOffer(fromPeerId, offerJson) {
    await initWebRTC(fromPeerId, false);
    const pc = rtcConnections[fromPeerId]?.pc;
    if (!pc) return;

    const offer = JSON.parse(offerJson);
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    connMgr.sendSignaling('rtc_answer', fromPeerId, JSON.stringify(answer));
}

export async function handleRTCAnswer(fromPeerId, answerJson) {
    const pc = rtcConnections[fromPeerId]?.pc;
    if (!pc) return;
    const answer = JSON.parse(answerJson);
    await pc.setRemoteDescription(new RTCSessionDescription(answer));
}

export async function handleRTCIce(fromPeerId, candidateJson) {
    const pc = rtcConnections[fromPeerId]?.pc;
    if (!pc) return;
    const candidate = JSON.parse(candidateJson);
    await pc.addIceCandidate(new RTCIceCandidate(candidate));
}

export function sendViaWebRTC(peerId, payload) {
    const conn = rtcConnections[peerId];
    if (conn && conn.dc && conn.dc.readyState === 'open') {
        conn.dc.send(JSON.stringify({ type: 'chat', payload: payload }));
        return true;
    }
    return false;
}

export function cleanupRTC(peerId) {
    const conn = rtcConnections[peerId];
    if (conn) {
        if (conn.dc) try { conn.dc.close(); } catch(e) {}
        if (conn.pc) try { conn.pc.close(); } catch(e) {}
        conn.status = 'closed';
    }
    delete rtcConnections[peerId];
}

export function updatePeerConnectionUI(peerId, type) {
    if (currentView === 'chat' && currentPeerId === peerId) {
        const dot = document.getElementById('connection-dot');
        if (dot) {
            dot.className = 'connection-dot online';
            dot.title = type === 'direct' ? 'Direct (WebRTC)' : 'Relay';
        }
    }
}

export function hasDirectConnection(peerId) {
    const conn = rtcConnections[peerId];
    return conn && conn.dc && conn.dc.readyState === 'open';
}

// ── WebRTC Gossip Mesh ─────────────────────────────────────
export const seenGossipMessages = new Set();
const SEEN_GOSSIP_MAX = 1000;
let gossipForwardCount = 0;
let gossipForwardResetTime = Date.now();
const GOSSIP_RATE_LIMIT = 10; // max forwards per second

export function markGossipSeen(msgId) {
    seenGossipMessages.add(msgId);
    if (seenGossipMessages.size > SEEN_GOSSIP_MAX) {
        const first = seenGossipMessages.values().next().value;
        seenGossipMessages.delete(first);
    }
}

export function gossipForward(originPeerId, msgId, to, payload, ttl) {
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
        if (peerId === originPeerId) continue;
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
