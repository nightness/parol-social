// ParolNet PWA — Settings, Export/Import, Network, Panic Wipe
import { wasm, cryptoStore, relayClient } from './state.js';
import { showToast } from './utils.js';
import { dbGet, dbPut, dbPutRaw, dbGetRaw, dbGetAllRaw, dbDelete, dbClear, ENCRYPTED_STORES } from './db.js';
import { showView } from './views.js';
import { connMgr } from './connection.js';
import { rtcConnections, updateWebRTCPrivacyUI } from './webrtc.js';
import { exportData, importData, validateExport } from './data-export.js';
import { t } from './i18n.js';

// ── Settings ────────────────────────────────────────────────
export function openSettings() {
    showView('settings');
    updateNetworkSettings();
    updateWebRTCPrivacyUI();

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

        const encrypted = await exportData({ stores, identity }, password);

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

// ── Panic Wipe ──────────────────────────────────────────────
export function executePanicWipe() {
    cryptoStore.lock();
    if (wasm) { try { wasm.panic_wipe(); } catch {} }
    window.location.href = './kill-sw.html?panic=1&t=' + Date.now();
}
