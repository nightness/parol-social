// ParolNet PWA — Safety Number (out-of-band identity verification)
//
// Generates a 60-digit number that both participants in a pair can compute
// independently from their two PeerIds. They compare the number through a
// trusted side channel (voice, in person, signed note). If the numbers match,
// neither party's identity was substituted during session establishment.
//
// Derivation: sha256(min(pidA,pidB) || max(pidA,pidB)), take first 30 bytes,
// split into six 5-byte groups, each interpreted big-endian mod 10^10 and
// rendered as 10 decimal digits. Format: six space-separated groups of 10
// digits (60 digits total, echoing Signal's safety number convention).
//
// PeerId is already sha256(Ed25519_pub); mixing both PeerIds binds the number
// to both parties' long-term keys. An attacker who substituted either party's
// key during X3DH handshake would produce a different effective PeerId on one
// side, yielding a different safety number — visible at comparison time.

const DIGITS_PER_GROUP = 10;
const NUM_GROUPS = 6;
const BYTES_PER_GROUP = 5;          // 5 bytes → 40 bits → fits 10 decimal digits
const MODULUS = 10_000_000_000n;    // 10^10

function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
        throw new Error('safety-number: input must be even-length hex');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        const byte = parseInt(hex.substr(i * 2, 2), 16);
        if (Number.isNaN(byte)) throw new Error('safety-number: invalid hex');
        bytes[i] = byte;
    }
    return bytes;
}

function compareBytes(a, b) {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
}

function groupToDigits(chunk) {
    // chunk: Uint8Array of length BYTES_PER_GROUP. Big-endian unsigned.
    let v = 0n;
    for (const b of chunk) v = (v << 8n) | BigInt(b);
    const mod = (v % MODULUS).toString().padStart(DIGITS_PER_GROUP, '0');
    return mod;
}

/**
 * Compute the 60-digit safety number for a pair of peers.
 * Both sides pass the same (pidHexA, pidHexB) regardless of order.
 *
 * @param {string} pidHexA 64-char hex PeerId.
 * @param {string} pidHexB 64-char hex PeerId.
 * @returns {Promise<string>} "XXXXXXXXXX XXXXXXXXXX ..." (six groups of 10).
 */
export async function computeSafetyNumber(pidHexA, pidHexB) {
    const a = hexToBytes(pidHexA);
    const b = hexToBytes(pidHexB);
    if (a.length !== 32 || b.length !== 32) {
        throw new Error('safety-number: PeerIds must be 32 bytes (64 hex chars)');
    }

    // Canonicalize order so both sides compute the same input.
    const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    const combined = new Uint8Array(64);
    combined.set(lo, 0);
    combined.set(hi, 32);

    const digestBuf = await crypto.subtle.digest('SHA-256', combined);
    const digest = new Uint8Array(digestBuf);

    const groups = [];
    for (let i = 0; i < NUM_GROUPS; i++) {
        const chunk = digest.slice(i * BYTES_PER_GROUP, (i + 1) * BYTES_PER_GROUP);
        groups.push(groupToDigits(chunk));
    }
    return groups.join(' ');
}

/**
 * Present the safety number in a modal so the user can compare it with their
 * contact's screen. Called from the chat header "verify identity" button.
 */
export async function showSafetyNumberModal(peerId) {
    if (!peerId || peerId.length !== 64) {
        console.warn('[Safety] Invalid peerId for verification:', peerId);
        return;
    }
    const ourPeerId = window._peerId;
    if (!ourPeerId) {
        console.warn('[Safety] Own peerId not ready');
        return;
    }

    let number;
    try {
        number = await computeSafetyNumber(ourPeerId, peerId);
    } catch (e) {
        console.warn('[Safety] computeSafetyNumber failed:', e);
        return;
    }

    let modal = document.getElementById('safety-number-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'safety-number-modal';
        modal.className = 'modal-overlay hidden';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2 data-i18n="heading.verifyIdentity">Verify identity</h2>
                    <button class="modal-close" id="safety-number-close">✕</button>
                </div>
                <div style="padding:16px;">
                    <p style="font-size:13px;opacity:0.75;margin:0 0 12px 0;" data-i18n="safety.intro">
                        Compare these digits with your contact through a channel you trust
                        (phone call, in person). If both screens show the same number, no one
                        substituted keys when your session was set up.
                    </p>
                    <pre id="safety-number-value" style="font-family:ui-monospace,monospace;font-size:18px;letter-spacing:1px;background:var(--input-bg,#111);padding:16px;border-radius:8px;white-space:pre-wrap;word-break:break-word;margin:0;text-align:center;"></pre>
                    <p style="font-size:12px;opacity:0.6;margin-top:12px;" data-i18n="safety.note">
                        If the numbers differ, someone may be intercepting your messages. Re-add
                        the contact via a fresh QR code from a trusted device.
                    </p>
                </div>
            </div>`;
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.add('hidden');
        });
        document.body.appendChild(modal);
        const closeBtn = modal.querySelector('#safety-number-close');
        if (closeBtn) closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    }
    const valueEl = modal.querySelector('#safety-number-value');
    if (valueEl) valueEl.textContent = number;
    modal.classList.remove('hidden');
}
