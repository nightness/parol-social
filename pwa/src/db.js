// ParolNet PWA — IndexedDB Storage
import { cryptoStore } from './state.js';

const DB_NAME = 'parolnet';
const DB_VERSION = 4;

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
export const ENCRYPTED_STORES = new Set(['contacts', 'messages', 'settings', 'groups', 'group_messages']);

function getKeyField(storeName) {
    if (storeName === 'contacts') return 'peerId';
    if (storeName === 'messages') return 'id';
    if (storeName === 'settings') return 'key';
    if (storeName === 'crypto_meta') return 'key';
    if (storeName === 'groups') return 'groupId';
    if (storeName === 'group_messages') return 'id';
    return 'id';
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
