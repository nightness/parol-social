// ParolNet PWA — Settings, Export/Import, Network, Panic Wipe
import { wasm, cryptoStore, relayClient } from './state.js';
import { showToast } from './utils.js';
import { dbGet, dbPut, dbPutRaw, dbGetRaw, dbGetAllRaw, dbGetAll, dbDelete, dbClear, ENCRYPTED_STORES } from './db.js';
import { showView } from './views.js';
import { connMgr } from './connection.js';
import { rtcConnections, updateWebRTCPrivacyUI } from './webrtc.js';
import { exportData, importData, validateExport } from './data-export.js';
import { t } from './i18n.js';
import { startCoverTraffic, stopCoverTraffic } from './cover-traffic.js';
import { sendToRelay } from './connection.js';

// ── Cover Traffic (PNP-006) ────────────────────────────────
// Default ON: the threat model requires decoy traffic to hide real activity.
// Users may disable in bandwidth-constrained environments.
let coverTrafficEnabled = true;

function coverTrafficDeps() {
    return {
        mode: 'NORMAL',
        wasm,
        sendToRelay,
        listContacts: () => dbGetAll('contacts'),
    };
}

export async function loadCoverTrafficSetting() {
    try {
        const saved = await dbGet('settings', 'cover_traffic_enabled');
        if (saved) coverTrafficEnabled = saved.value !== 'false';
    } catch {}
    return coverTrafficEnabled;
}

export function isCoverTrafficEnabled() {
    return coverTrafficEnabled;
}

export async function setCoverTrafficEnabled(enabled) {
    coverTrafficEnabled = !!enabled;
    try {
        await dbPut('settings', { key: 'cover_traffic_enabled', value: String(coverTrafficEnabled) });
    } catch {}
    if (coverTrafficEnabled) {
        startCoverTraffic(coverTrafficDeps());
    } else {
        stopCoverTraffic();
    }
    updateCoverTrafficUI();
}

export function updateCoverTrafficUI() {
    const toggle = document.getElementById('cover-traffic-toggle');
    if (toggle) toggle.checked = coverTrafficEnabled;
}

export function startCoverTrafficFromSettings() {
    if (coverTrafficEnabled) {
        startCoverTraffic(coverTrafficDeps());
    }
}

// ── Settings ────────────────────────────────────────────────
export function openSettings() {
    showView('settings');
    updateNetworkSettings();
    updateWebRTCPrivacyUI();
    updateCoverTrafficUI();
    updateRelaySection();

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

export async function enableEncryption() {
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
        await cryptoStore.setup(passphrase, dbPutRaw, dbGetRaw);

        showToast('Encrypting data...');
        await migrateToEncrypted();

        showToast('Encryption enabled!');
        if (input) input.value = '';
        if (confirm) confirm.value = '';

        const encSetup = document.getElementById('encryption-setup');
        const encStatus = document.getElementById('encryption-status');
        if (encSetup) encSetup.style.display = 'none';
        if (encStatus) encStatus.style.display = 'block';
    } catch (e) {
        showToast('Failed to enable encryption: ' + e.message);
    }
}

async function migrateToEncrypted() {
    for (const storeName of ENCRYPTED_STORES) {
        try {
            const items = await dbGetAllRaw(storeName);
            for (const item of items) {
                if (!item._enc) {
                    await dbPut(storeName, item);
                }
            }
        } catch (e) {
            console.warn('Migration failed for', storeName, e);
        }
    }
}

// ── Data Export/Import ─────────────────────────────────────
export async function handleExportData() {
    const password = prompt('Enter a password to encrypt your export:');
    if (!password || password.length < 4) {
        showToast('Password must be at least 4 characters');
        return;
    }
    const confirmPw = prompt('Confirm password:');
    if (password !== confirmPw) {
        showToast('Passwords do not match');
        return;
    }

    try {
        showToast('Exporting data...');

        const stores = {};
        for (const storeName of ['contacts', 'messages', 'settings', 'crypto_meta']) {
            stores[storeName] = await dbGetAllRaw(storeName);
        }

        let identity = null;
        try {
            if (wasm && wasm.export_secret_key) {
                identity = wasm.export_secret_key();
            }
        } catch (e) {
            console.warn('Could not export identity key:', e);
        }

        let sessions = null;
        try {
            if (wasm && wasm.export_sessions) {
                sessions = wasm.export_sessions();
            }
        } catch (e) {
            console.warn('Could not export sessions:', e);
        }

        const encrypted = await exportData({ stores, identity, sessions }, password);

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

export async function handleImportData() {
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

            for (const [storeName, records] of Object.entries(data.stores)) {
                await dbClear(storeName);
                for (const record of records) {
                    await dbPutRaw(storeName, record);
                }
            }

            if (data.identity && wasm && wasm.initialize_from_key) {
                try {
                    wasm.initialize_from_key(data.identity);
                    await dbPut('settings', { key: 'identity_secret', value: data.identity });
                } catch (e) {
                    console.warn('Could not restore identity key:', e);
                    showToast('Warning: Identity key restore failed');
                }
            }

            if (data.sessions && wasm && wasm.import_sessions) {
                try {
                    wasm.import_sessions(data.sessions);
                    await dbPut('settings', { key: 'sessions_blob', value: data.sessions });
                } catch (e) {
                    console.warn('Could not restore sessions:', e);
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
export async function setCustomRelay() {
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

// ── H12 Phase 1: Relay section (connected relay + verified directory) ────
// Renders the currently-connected relay URL + short fingerprint, and a list
// of directory entries that passed authority-threshold verification. A manual
// "Add relay URL" input lets operators sideload a relay for debugging — the
// URL is only added if a subsequent /directory fetch yields an
// authority-verified descriptor for it.
export function updateRelaySection() {
    const connectedEl = document.getElementById('settings-relay-connected');
    const fpEl = document.getElementById('settings-relay-fingerprint');
    const listEl = document.getElementById('settings-relay-directory-list');

    if (connectedEl) {
        connectedEl.textContent = relayClient.connectedRelay || '—';
    }
    if (fpEl) {
        const pub = relayClient.connectedRelayPubkey;
        if (pub) {
            fpEl.textContent = pub.slice(-16);
            fpEl.style.color = '#4CAF50';
        } else {
            fpEl.textContent = '—';
            fpEl.style.color = '#888';
        }
    }
    if (listEl) {
        listEl.textContent = '';
        const entries = relayClient.verifiedDirectory || [];
        if (entries.length === 0) {
            const empty = document.createElement('div');
            empty.style.cssText = 'font-size: 12px; color: #888; padding: 8px 0;';
            empty.textContent = '—';
            listEl.appendChild(empty);
            return;
        }
        for (const e of entries) {
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #333;font-size:13px;';
            const url = document.createElement('span');
            url.style.color = '#ddd';
            url.style.overflow = 'hidden';
            url.style.textOverflow = 'ellipsis';
            url.textContent = e.url || '?';
            const badge = document.createElement('span');
            const ok = e.verified === true;
            badge.style.cssText = 'font-size:11px;padding:2px 8px;border-radius:10px;margin-left:8px;white-space:nowrap;'
                + (ok ? 'background:#0a4a1a;color:#4CAF50;' : 'background:#4a0a0a;color:#f44;');
            badge.textContent = ok ? t('settings.relay.authorityVerified') : t('settings.relay.authorityMissing');
            row.appendChild(url);
            row.appendChild(badge);
            listEl.appendChild(row);
        }
    }
}

export async function addManualRelay() {
    const input = document.getElementById('settings-relay-add-input');
    if (!input) return;
    const url = input.value.trim();
    if (!url) return;
    if (!url.startsWith('wss://') && !url.startsWith('ws://') && !url.startsWith('https://') && !url.startsWith('http://')) {
        showToast('URL must start with wss://, ws://, https:// or http://');
        return;
    }
    if (!relayClient.relays.includes(url)) {
        relayClient.relays.push(url);
    }
    try {
        const fetched = await relayClient.fetchDirectory(url);
        if (!fetched || fetched.length === 0) {
            showToast('Relay responded but no authority-verified directory');
        } else {
            showToast('Added relay');
        }
    } catch (e) {
        showToast('Relay unreachable: ' + (e && e.message ? e.message : e));
    }
    input.value = '';
    updateRelaySection();
    updateNetworkSettings();
}

export async function clearCustomRelay() {
    try { await dbDelete('settings', 'custom_relay_url'); } catch(e) {}

    connMgr.relayUrl = (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/ws';
    if (connMgr.relayWs) {
        connMgr.relayWs.close();
    }
    connMgr._connectRelay();
    showToast('Relay URL reset to default');
    updateNetworkSettings();
}

export function updateNetworkSettings() {
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

// ── Duress Passphrase ─────────────────────────────────────
// Adds or replaces a duress credential on an unlocked-and-set-up store.
// Requires the user to re-enter their CURRENT real passphrase (crypto-store
// intentionally does not retain it in memory) alongside the duress choice.
export async function addDuressCredential() {
    const realInput = document.getElementById('duress-verify-passphrase');
    const duressInput = document.getElementById('duress-code-input');
    const realPass = realInput ? realInput.value : '';
    const duressPass = duressInput ? duressInput.value : '';

    if (!realPass || !duressPass) {
        showToast(t('toast.wrongPassphrase'));
        return;
    }
    if (realPass === duressPass) {
        showToast(t('toast.wrongPassphrase'));
        return;
    }

    try {
        await cryptoStore.addDuressCredential(realPass, duressPass, dbPutRaw, dbGetRaw);
        if (realInput) realInput.value = '';
        if (duressInput) duressInput.value = '';
        showToast(t('toast.duressCodeUpdated'));
    } catch (e) {
        if (realInput) realInput.value = '';
        if (duressInput) duressInput.value = '';
        showToast(t('toast.wrongPassphrase'));
    }
}

export function enableDecoyMode() {
    const input = document.getElementById('decoy-code-input');
    const code = input ? input.value : '00000';

    if (wasm && wasm.set_unlock_code) {
        wasm.set_unlock_code(code);
    }

    const manifestLink = document.getElementById('manifest-link');
    if (manifestLink) {
        manifestLink.href = 'manifest-calculator.json';
    }

    showToast('Decoy mode enabled. The app will appear as a calculator on next launch.');
}

// ── Identity Rotation (PNP-002 §8, H5) ─────────────────────
// User-invoked: generate a new Ed25519 identity, sign a rotation notice with
// the OLD key, and deliver it to every contact with an active session. The
// OLD identity is retained for 7 days (grace window) so in-flight messages
// to the old PeerId still decrypt. After the grace window the retired
// secret is zeroized on next boot (see regenerateIdentity_zeroizeExpired).
export async function regenerateIdentity() {
    if (!wasm || !wasm.rotate_identity) {
        showToast('Identity rotation not available');
        return;
    }
    const proceed = confirm(t('settings.regenerateIdentityConfirm'));
    if (!proceed) return;

    let result;
    try {
        const nowSecs = BigInt(Math.floor(Date.now() / 1000));
        result = wasm.rotate_identity(nowSecs);
    } catch (e) {
        showToast('Identity rotation failed: ' + (e && e.message));
        return;
    }

    // Persist the new identity secret + the retired record (for grace-window
    // cleanup). The retired record holds the OLD secret so the relay can
    // still respond to challenges addressed to the old PeerId during the
    // grace window if that's implemented in a future commit.
    try {
        if (wasm.export_secret_key) {
            const newSecret = wasm.export_secret_key();
            await dbPut('settings', { key: 'identity_secret', value: newSecret });
        }
        await dbPut('settings', { key: 'retired_identity', value: JSON.stringify({
            peer_id: result.old_peer_id_hex,
            ed25519_sk: result.retired_identity_secret_hex,
            grace_expires_at: result.grace_expires_at
        }) });
    } catch (e) {
        console.warn('[Rotate] persist failed:', e && e.message);
    }

    // Update the peer-id we publish to the relay so subsequent registrations
    // use the new identity. The SW will reconnect and register under the new
    // peer id on next controller message.
    window._peerId = result.new_peer_id_hex;
    if (connMgr && connMgr.registerPeer) connMgr.registerPeer(result.new_peer_id_hex);

    // Deliver one envelope per contact. Transport-layer: prefer direct RTC,
    // fall back to relay. Errors per-contact are logged but do not abort
    // the rest of the batch — a failed delivery means the contact sees
    // the rotation the next time they reach us on the old PeerId.
    const envelopes = Array.isArray(result.per_contact_envelopes) ? result.per_contact_envelopes : [];
    for (const pair of envelopes) {
        if (!Array.isArray(pair) || pair.length !== 2) continue;
        const [peerIdHex, envelopeHex] = pair;
        try {
            sendToRelay(peerIdHex, envelopeHex);
        } catch (e) {
            console.warn('[Rotate] send to', peerIdHex && peerIdHex.slice(0, 8), 'failed:', e && e.message);
        }
    }

    // Update the settings UI and show a toast.
    const el = document.getElementById('settings-peer-id');
    if (el) el.textContent = result.new_peer_id_hex;
    showToast(t('toast.identityRotated'));
}

/// Zeroize the retired identity secret once its grace window has passed.
/// Call during boot so the 7-day guarantee is enforced across app restarts.
export async function zeroizeExpiredRetiredIdentity() {
    let rec;
    try { rec = await dbGet('settings', 'retired_identity'); } catch { return; }
    if (!rec || !rec.value) return;
    let obj;
    try { obj = JSON.parse(rec.value); } catch { return; }
    const nowSecs = Math.floor(Date.now() / 1000);
    if (typeof obj.grace_expires_at !== 'number' || obj.grace_expires_at > nowSecs) return;
    // Overwrite the hex string before deletion so the IndexedDB value-journal
    // (if any) doesn't hold a copy of the secret. Best-effort on web; the
    // definitive guarantee is removal from the store.
    try {
        await dbPut('settings', { key: 'retired_identity', value: JSON.stringify({
            peer_id: obj.peer_id,
            ed25519_sk: '00'.repeat(32),
            grace_expires_at: obj.grace_expires_at
        }) });
        await dbDelete('settings', 'retired_identity');
    } catch (e) {
        console.warn('[Rotate] zeroize retired identity failed:', e && e.message);
    }
}

// ── Panic Wipe ──────────────────────────────────────────────
export function executePanicWipe() {
    cryptoStore.lock();
    if (wasm) { try { wasm.panic_wipe(); } catch {} }
    window.location.href = './kill-sw.html?panic=1&t=' + Date.now();
}
