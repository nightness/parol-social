// ParolNet PWA — Encrypted Storage Layer
// AES-256-GCM with PBKDF2 key derivation via Web Crypto API.
// Zero external dependencies.

async function deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptValue(key, value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const data = enc.encode(JSON.stringify(value));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    // Combine iv + ciphertext into single Uint8Array
    const result = new Uint8Array(12 + ct.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ct), 12);
    return result;
}

async function decryptValue(key, encrypted) {
    // encrypted is Uint8Array: first 12 bytes IV, rest ciphertext
    const buf = encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted);
    const iv = buf.slice(0, 12);
    const ct = buf.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(plain));
}

export class CryptoStore {
    constructor() {
        this._key = null;
        this._enabled = false;
    }

    isEnabled() { return this._enabled; }
    isUnlocked() { return this._key !== null; }

    // First-time setup: generate salt, derive key, store verification token
    async setup(passphrase, dbPutRaw, dbGetRaw) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        this._key = await deriveKey(passphrase, salt);

        // Store salt (unencrypted — it's not secret)
        await dbPutRaw('crypto_meta', { key: 'salt', value: Array.from(salt) });

        // Store verification token: encrypt a known string so we can verify passphrase on unlock
        const verifier = await encryptValue(this._key, { verify: 'parolnet' });
        await dbPutRaw('crypto_meta', { key: 'verifier', value: Array.from(verifier) });

        this._enabled = true;
    }

    // Unlock: load salt, derive key, verify against stored token
    async unlock(passphrase, dbGetRaw) {
        const saltRecord = await dbGetRaw('crypto_meta', 'salt');
        if (!saltRecord || !saltRecord.value) {
            throw new Error('No encryption configured');
        }
        const salt = new Uint8Array(saltRecord.value);
        const key = await deriveKey(passphrase, salt);

        // Verify passphrase
        const verifierRecord = await dbGetRaw('crypto_meta', 'verifier');
        if (!verifierRecord || !verifierRecord.value) {
            throw new Error('Missing verifier');
        }
        try {
            const result = await decryptValue(key, new Uint8Array(verifierRecord.value));
            if (result.verify !== 'parolnet') throw new Error('Bad verify');
        } catch {
            throw new Error('Wrong passphrase');
        }

        this._key = key;
        this._enabled = true;
    }

    // Check if encryption has been set up (salt exists)
    async checkEnabled(dbGetRaw) {
        try {
            const saltRecord = await dbGetRaw('crypto_meta', 'salt');
            this._enabled = !!(saltRecord && saltRecord.value);
        } catch {
            this._enabled = false;
        }
        return this._enabled;
    }

    lock() {
        this._key = null;
        // Note: can't truly zeroize JS memory, but nulling removes reference
    }

    async encrypt(value) {
        if (!this._key) throw new Error('Store locked');
        return await encryptValue(this._key, value);
    }

    async decrypt(encrypted) {
        if (!this._key) throw new Error('Store locked');
        return await decryptValue(this._key, encrypted);
    }
}
