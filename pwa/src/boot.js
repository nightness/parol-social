// ParolNet PWA — Boot, WASM Loading, Service Worker, Window Exports
import {
    wasm, setWasm, cryptoStore, relayClient,
    platform, setPlatform, setLocalStream
} from './state.js';
import { showToast, detectPlatform, showLocalNotification, requestNotificationPermission } from './utils.js';
import { dbGet, dbPut, dbGetRaw } from './db.js';
import { telemetry } from './telemetry.js';
import { showView, calcPress, loadPanicCode } from './views.js';
import { rtcConnections, initWebRTC, hasDirectConnection, loadCustomStunServers } from './webrtc.js';
import { connMgr, flushMessageQueue } from './connection.js';
import {
    handleRelayMessage, switchListTab, showCreateGroupDialog, createGroup,
    openGroupChat, sendGroupMessage, showGroupMembers, closeGroupMembers,
    addMemberFromInput, addMemberToGroup, removeMemberFromGroup, leaveCurrentGroup,
    acceptIncomingCall, declineIncomingCall, startGroupCall, joinGroupCall,
    leaveGroupCallUI, toggleGroupMute, acceptFileOffer, declineFileOffer,
    attachGroupFile, onGroupFileSelected, loadGroups
} from './messaging.js';
import {
    loadContacts, renderBootstrapQR, openChat, sendMessage, renameContact,
    attachFile, onFileSelected, initiateCall, hangupCall,
    answerIncomingCall, toggleMute, toggleCamera, connectViaPassphrase,
    startQRScanner, stopQRScanner, copyBootstrapCode, showAddTab, initContactSearch,
    appendMessage, toggleContactMenu
} from './ui-chat.js';
import {
    openSettings, enableDecoyMode, executePanicWipe, enableEncryption,
    handleExportData, handleImportData, updateNetworkSettings
} from './settings.js';
import { initI18n, t, changeLanguage, applyToDOM } from './i18n.js';

// ── WASM Loading ────────────────────────────────────────────
async function loadWasm() {
    const statusEl = document.getElementById('loading-status');
    try {
        if (statusEl) statusEl.textContent = t('status.loadingCrypto');
        const wasmModule = await import('./pkg/parolnet_wasm.js');
        setWasm(wasmModule);
        if (statusEl) statusEl.textContent = t('status.initializing');
        const wasmUrl = './pkg/parolnet_wasm_bg.wasm?v=' + Date.now();
        await wasm.default({ module_or_path: wasmUrl });
        if (statusEl) statusEl.textContent = t('status.restoringIdentity');
        telemetry.track('wasm_load_success');
        await onWasmReady();
    } catch (e) {
        console.warn('WASM not available:', e.message);
        telemetry.track('wasm_load_fail', { error: e.message });
        showToast(t('error.wasmLoadFailed', { error: e.message }));
        if (statusEl) statusEl.textContent = t('status.runningWithoutCrypto', { error: e.message });
        onWasmUnavailable();
    }
}

async function onWasmReady() {
    const encEnabled = await cryptoStore.checkEnabled(dbGetRaw);
    if (encEnabled && !cryptoStore.isUnlocked()) {
        const decoyEnabled = wasm && wasm.is_decoy_enabled && wasm.is_decoy_enabled();
        if (!decoyEnabled) {
            showView('unlock');
            document.getElementById('loading-status').textContent = t('status.encrypted');
        }
        return;
    }

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

    if (!peerId) {
        if (wasm.initialize) {
            peerId = wasm.initialize();
            console.log('New identity generated:', peerId.slice(0, 16) + '...');

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

    if (wasm.get_peer_id) {
        const peerId = wasm.get_peer_id();
        window._peerId = peerId || window._peerId;
        const el = document.getElementById('settings-peer-id');
        if (el) el.textContent = peerId || '-';
    }
    if (window._peerId) connMgr.registerPeer(window._peerId);

    if (wasm.version) {
        const el = document.getElementById('settings-version');
        if (el) el.textContent = wasm.version();
    }

    if (wasm.is_decoy_enabled && wasm.is_decoy_enabled()) {
        showView('calculator');
        const manifestLink = document.getElementById('manifest-link');
        if (manifestLink) manifestLink.href = 'manifest-calculator.json';
    } else {
        showView('contacts');
    }
    loadContacts();
    renderBootstrapQR();

    relayClient.discover().then(relays => {
        console.log('[App] Discovered', relays.length, 'relays');
        connMgr.start();
        updateConnectionStatus();
        // Poll for relay status until connected (challenge-response is async)
        let statusChecks = 0;
        const checkStatus = setInterval(() => {
            if (connMgr.isRelayConnected() || ++statusChecks > 10) {
                clearInterval(checkStatus);
                updateConnectionStatus();
            } else if (navigator.serviceWorker && navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({ type: 'relay_status_query' });
            }
        }, 1000);
    }).catch(e => {
        console.warn('[App] Relay discovery failed, using defaults:', e.message);
        connMgr.start();
    });
}

export function attemptUnlock() {
    const input = document.getElementById('unlock-input');
    const passphrase = input ? input.value : '';
    if (!passphrase) return;

    cryptoStore.unlock(passphrase, dbGetRaw).then(() => {
        if (input) input.value = '';
        showView('loading');
        document.getElementById('loading-status').textContent = t('status.decrypting');
        onWasmReady();
    }).catch(() => {
        showToast(t('toast.wrongPassphrase'));
        if (input) { input.value = ''; input.focus(); }
    });
}

function onWasmUnavailable() {
    showView('contacts');
    const el = document.getElementById('settings-version');
    if (el) el.textContent = t('settings.devMode');

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
        dot.title = t('status.relayConnected');
    } else if (hasAnyWebRTC) {
        dot.className = 'connection-dot partial';
        dot.title = t('status.directOnly');
    } else {
        dot.className = 'connection-dot offline';
        dot.title = t('status.offline');
    }
    updateNetworkSettings();
}

// ── SW Inbox Drain ──────────────────────────────────────────
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

    navigator.serviceWorker.addEventListener('controllerchange', () => {
        console.log('[SW] New controller active — re-sending relay config');
        if (connMgr.relayUrl) {
            connMgr._swPost({ type: 'relay_connect', url: connMgr.relayUrl, peerId: window._peerId || null });
        }
    });

    navigator.serviceWorker.register('sw.js').then(reg => {
        console.log('SW registered:', reg.scope);
        setInterval(() => reg.update(), 3600000);

        if (reg.waiting) reg.waiting.postMessage('skipWaiting');

        reg.addEventListener('updatefound', () => {
            const newSW = reg.installing;
            if (!newSW) return;
            newSW.addEventListener('statechange', () => {
                if (newSW.state === 'installed' && reg.waiting) {
                    reg.waiting.postMessage('skipWaiting');
                }
            });
        });

        drainSwInbox().catch(() => {});

        navigator.serviceWorker.ready.then(() => {
            if (navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({ type: 'relay_status_query' });
            }
        });
    }).catch(err => {
        console.warn('SW registration failed:', err);
    });
}

// ── Boot ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    setPlatform(detectPlatform());
    document.body.classList.add(`platform-${platform}`);

    // Load saved language preference, then init i18n
    let savedLang = null;
    try {
        const langSetting = await dbGet('settings', 'language');
        if (langSetting && langSetting.value) savedLang = langSetting.value;
    } catch {}
    await initI18n(savedLang).catch(() => {});

    // Set language selector to current value
    const langSelect = document.getElementById('settings-language');
    if (langSelect && savedLang) langSelect.value = savedLang;

    if (navigator.storage && navigator.storage.persist) navigator.storage.persist();
    registerServiceWorker();
    showToast(t('toast.starting'), 2000);
    loadPanicCode().catch(() => {});
    loadCustomStunServers().catch(() => {});
    loadWasm();

    setTimeout(() => {
        const loading = document.getElementById('view-loading');
        if (loading && !loading.classList.contains('hidden')) {
            const errEl = document.getElementById('loading-error');
            if (errEl) { errEl.style.display = 'block'; errEl.textContent = t('error.takingTooLong'); }
            const btn = document.getElementById('loading-retry');
            if (btn) btn.style.display = 'inline-block';
            const btn2 = document.getElementById('loading-clear');
            if (btn2) btn2.style.display = 'inline-block';
        }
    }, 15000);
    initContactSearch();

    const params = new URLSearchParams(window.location.search);
    const bootstrap = params.get('bootstrap');
    if (bootstrap && wasm && wasm.parse_qr_payload) {
        try {
            wasm.parse_qr_payload(bootstrap);
            showToast(t('toast.bootstrapReceived'));
        } catch(e) {
            console.warn('Failed to parse bootstrap:', e);
        }
    }
});

// ── Auto-lock on background ────────────────────────────────
document.addEventListener('visibilitychange', () => {
    if (document.hidden && cryptoStore.isUnlocked()) {
        window._lockTimer = setTimeout(() => {
            cryptoStore.lock();
            const decoyEnabled = wasm && wasm.is_decoy_enabled && wasm.is_decoy_enabled();
            if (decoyEnabled) {
                showView('calculator');
            } else if (cryptoStore.isEnabled()) {
                showView('unlock');
            }
        }, 5 * 60 * 1000);
    } else {
        clearTimeout(window._lockTimer);
        if (navigator.serviceWorker && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ type: 'relay_status_query' });
        }
        drainSwInbox().catch(() => {});
    }
});

// ── Export for onclick handlers ─────────────────────────────
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
window.toggleContactMenu = toggleContactMenu;
// i18n
window.changeLanguage = async function(lang) {
    await changeLanguage(lang);
    dbPut('settings', { key: 'language', value: lang }).catch(() => {});
};
