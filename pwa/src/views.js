// ParolNet PWA — View Management & Calculator
import { wasm, cryptoStore, currentView, setCurrentView } from './state.js';
import { safeEval, showToast } from './utils.js';
import { dbGet, dbPut, dbDelete, dbGetRaw } from './db.js';
import { loadContacts, stopQRScanner, renderBootstrapQR } from './ui-chat.js';
import { loadGroups } from './messaging.js';
import { executePanicWipe } from './settings.js';

// ── View Management ─────────────────────────────────────────
export function showView(viewName) {
    // Stop camera when leaving add-contact view
    if (currentView === 'add-contact' && viewName !== 'add-contact') {
        stopQRScanner();
    }
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    const target = document.getElementById(`view-${viewName}`);
    if (target) {
        target.classList.remove('hidden');
    }
    setCurrentView(viewName);

    // Render QR when entering add-contact view
    if (viewName === 'add-contact') {
        renderBootstrapQR();
    }

    // Refresh contact list when entering contacts view
    if (viewName === 'contacts') {
        loadContacts();
        loadGroups();
    }
}

// ── Calculator ──────────────────────────────────────────────
let calcDisplay = '0';
let calcExpression = '';
let calcBuffer = '';

// Configurable panic (kill) code — defaults to 999999.
const DEFAULT_PANIC_CODE = '999999';
let panicCode = DEFAULT_PANIC_CODE;

export async function loadPanicCode() {
    try {
        const saved = await dbGet('settings', 'panic_code');
        if (saved && saved.value && /^\d{4,10}$/.test(saved.value)) {
            panicCode = saved.value;
        }
    } catch (e) {
        console.warn('[Panic] Failed to load custom panic code:', e);
    }
}

export async function setPanicCode(code) {
    if (!/^\d{4,10}$/.test(code)) {
        showToast('Panic code must be 4-10 digits');
        return false;
    }
    panicCode = code;
    await dbPut('settings', { key: 'panic_code', value: code });
    showToast('Panic code updated');
    return true;
}

export async function resetPanicCode() {
    panicCode = DEFAULT_PANIC_CODE;
    try { await dbDelete('settings', 'panic_code'); } catch(e) {}
    showToast('Panic code reset to default');
}

export async function calcPress(key) {
    if (key === 'C') {
        calcDisplay = '0';
        calcExpression = '';
        calcBuffer = '';
    } else if (key === '=') {
        // Check unlock code BEFORE showing result
        if (calcBuffer === panicCode) {
            // PANIC WIPE — immediate, no confirmation
            executePanicWipe();
            return;
        }
        if (wasm && wasm.is_decoy_enabled && wasm.is_decoy_enabled() &&
            wasm.verify_unlock_code && wasm.verify_unlock_code(calcBuffer)) {
            // Also unlock encrypted storage with the same code
            if (cryptoStore.isEnabled() && !cryptoStore.isUnlocked()) {
                try {
                    await cryptoStore.unlock(calcBuffer, dbGetRaw);
                } catch (e) {
                    console.warn('[Decoy] Crypto unlock failed:', e);
                }
            }
            showView('contacts');
            calcBuffer = '';
            return;
        }
        // Default unlock code check (no WASM fallback)
        if (!wasm && calcBuffer === '00000') {
            showView('contacts');
            calcBuffer = '';
            return;
        }
        // Normal calculation
        try {
            const result = safeEval(calcExpression);
            calcDisplay = String(!isNaN(result) ? result : 'Error');
        } catch {
            calcDisplay = 'Error';
        }
        calcExpression = '';
        calcBuffer = '';
    } else if ('0123456789'.includes(key)) {
        if (calcDisplay === '0' && calcExpression === '') {
            calcDisplay = key;
        } else {
            calcDisplay += key;
        }
        calcExpression += key;
        calcBuffer += key;
    } else if (key === '.') {
        calcDisplay += '.';
        calcExpression += '.';
    } else if ('+-\u00d7\u00f7'.includes(key)) {
        const op = key === '\u00d7' ? '*' : key === '\u00f7' ? '/' : key;
        calcExpression += op;
        calcDisplay += key;
        calcBuffer = ''; // reset buffer on operator
    } else if (key === '\u00b1') {
        if (calcDisplay.startsWith('-')) {
            calcDisplay = calcDisplay.slice(1);
        } else if (calcDisplay !== '0') {
            calcDisplay = '-' + calcDisplay;
        }
    } else if (key === '%') {
        calcExpression += '/100';
        try {
            const result = safeEval(calcExpression);
            if (!isNaN(result)) calcDisplay = String(result);
        } catch {
            // keep display as-is
        }
    }
    updateCalcDisplay();
}

export function updateCalcDisplay() {
    const el = document.getElementById('calc-display');
    if (el) {
        // Truncate long displays
        let text = calcDisplay;
        if (text.length > 12) {
            const num = parseFloat(text);
            if (!isNaN(num)) {
                text = num.toPrecision(10);
            }
        }
        el.textContent = text;
    }
}
