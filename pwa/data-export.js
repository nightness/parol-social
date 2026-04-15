// ParolNet PWA — Encrypted Data Export/Import
// Export file format: opaque binary (no magic header)
// Layout: salt(16) || iv(12) || ciphertext(AES-256-GCM)
// Ciphertext decrypts to JSON: { version: 1, stores: {...}, identity: "hex" }

const EXPORT_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;

async function deriveExportKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Export all data as encrypted binary.
 * @param {object} data - { stores: { contacts: [...], messages: [...], settings: [...], crypto_meta: [...] }, identity: "hex_string" }
 * @param {string} password - User-chosen export password
 * @returns {Uint8Array} Opaque encrypted binary (indistinguishable from random)
 */
export async function exportData(data, password) {
    const payload = JSON.stringify({ version: EXPORT_VERSION, ...data });
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveExportKey(password, salt);
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(payload)
    );
    // Combine: salt(16) + iv(12) + ciphertext
    const result = new Uint8Array(16 + 12 + ciphertext.byteLength);
    result.set(salt, 0);
    result.set(iv, 16);
    result.set(new Uint8Array(ciphertext), 28);
    return result;
}

/**
 * Import data from encrypted binary.
 * @param {Uint8Array} encrypted - The export file bytes
 * @param {string} password - Export password
 * @returns {object} { version, stores: {...}, identity: "hex" }
 * @throws {Error} Wrong password or corrupted file
 */
export async function importData(encrypted, password) {
    if (encrypted.length < 29) {
        throw new Error('Invalid export file');
    }
    const salt = encrypted.slice(0, 16);
    const iv = encrypted.slice(16, 28);
    const ciphertext = encrypted.slice(28);
    const key = await deriveExportKey(password, salt);
    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
        const json = JSON.parse(new TextDecoder().decode(plaintext));
        if (!json.version || !json.stores) {
            throw new Error('Invalid export format');
        }
        return json;
    } catch (e) {
        if (e.message === 'Invalid export format') throw e;
        throw new Error('Wrong password or corrupted file');
    }
}

/**
 * Validate an export file without writing anything.
 * @returns {object} { version, storeCount, messageCount, contactCount }
 */
export async function validateExport(encrypted, password) {
    const data = await importData(encrypted, password);
    return {
        version: data.version,
        storeCount: Object.keys(data.stores || {}).length,
        messageCount: (data.stores?.messages || []).length,
        contactCount: (data.stores?.contacts || []).length,
        hasIdentity: !!data.identity,
    };
}
