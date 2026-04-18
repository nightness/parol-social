// ParolNet PWA — IndexedDB Storage
import { cryptoStore } from './state.js';

const DB_NAME = 'parolnet';
const DB_VERSION = 5;

export function openDB() {
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
                // v5: volatile per-contact state split out of `contacts` so the
                // trust-anchor fields (peerId, name, identityPubKey) and the
                // fast-changing fields (lastMessage, lastTime, unread, typing)
                // live in independent stores. `contact_state` is zeroed on
                // panic-wipe without losing verified identities.
                if (!db.objectStoreNames.contains('contact_state')) {
                    db.createObjectStore('contact_state', { keyPath: 'peerId' });
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

export async function dbGetAllRaw(storeName) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function dbPutRaw(storeName, item) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        const req = store.put(item);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function dbGetRaw(storeName, key) {
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
export const ENCRYPTED_STORES = new Set([
    'contacts', 'messages', 'settings', 'groups', 'group_messages', 'contact_state',
]);

function getKeyField(storeName) {
    if (storeName === 'contacts') return 'peerId';
    if (storeName === 'messages') return 'id';
    if (storeName === 'settings') return 'key';
    if (storeName === 'crypto_meta') return 'key';
    if (storeName === 'groups') return 'groupId';
    if (storeName === 'group_messages') return 'id';
    if (storeName === 'contact_state') return 'peerId';
    return 'id';
}

/// Upsert a partial patch into the `contact_state` store. Unknown fields on
/// the patch are preserved; fields listed in the patch overwrite. Used by
/// every call site that previously wrote `lastMessage`/`lastTime`/`unread`
/// onto a contact row.
export async function updateContactState(peerId, patch) {
    const prior = (await dbGet('contact_state', peerId)) || { peerId };
    const next = { ...prior, ...patch, peerId };
    return dbPut('contact_state', next);
}

/// Fetch one contact's volatile state (or `null` if none recorded yet).
export async function loadContactState(peerId) {
    return (await dbGet('contact_state', peerId)) || null;
}

/// Fetch every contact's volatile state keyed by peerId.
export async function loadAllContactStates() {
    const rows = await dbGetAll('contact_state');
    const map = new Map();
    for (const row of rows) {
        if (row && row.peerId) map.set(row.peerId, row);
    }
    return map;
}

// Encrypted wrappers
export async function dbPut(storeName, item) {
    if (cryptoStore.isUnlocked() && ENCRYPTED_STORES.has(storeName)) {
        const keyField = getKeyField(storeName);
        const keyValue = item[keyField];
        const encrypted = await cryptoStore.encrypt(item);
        return dbPutRaw(storeName, { [keyField]: keyValue, _enc: Array.from(encrypted) });
    }
    return dbPutRaw(storeName, item);
}

export async function dbGet(storeName, key) {
    const raw = await dbGetRaw(storeName, key);
    if (raw && raw._enc && cryptoStore.isUnlocked()) {
        return await cryptoStore.decrypt(new Uint8Array(raw._enc));
    }
    return raw;
}

export async function dbGetAll(storeName) {
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

export async function dbGetByIndex(storeName, indexName, value) {
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

export async function dbDelete(storeName, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        const req = store.delete(key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

export async function dbClear(storeName) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        const req = store.clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}
