// ParolNet PWA — Opt-in H3 onion routing (main-thread)
//
// When high-anonymity mode is ON, the main thread opens its own relay
// WebSocket (bypassing the service-worker-owned socket), builds a 3-hop
// onion circuit via the existing WASM exports, and routes every relay
// send through `circuit_send`. Incoming DATA cells are drained by an
// interval polling `circuit_recv` and re-hydrated into the existing
// envelope-dispatch path.
//
// Tradeoff (documented in settings copy): while onion is active the
// service-worker relay socket is torn down, so background push-style
// delivery via the SW does not work. The app must stay open.
//
// Relay-server compatibility: the single-relay MVP server peels one
// onion layer on DATA cells and expects the inner bytes to be a JSON
// `{ "to": ..., "payload": ... }` frame — the same shape `relay_send`
// already produces in the SW path. So sends are wrapped as that JSON
// before being handed to `circuit_send`.

// Deliberately avoid importing state.js / messaging.js at the top level
// so this module is loadable under `node --test` without pulling the
// whole DOM-dependent graph. The wasm handle and the incoming dispatch
// function are resolved lazily via dynamic `import()` the first time
// enableOnion() runs; tests inject their own wasm through the `deps`
// parameter so they never hit the real modules.
let _liveWasm = null;
let _liveOnIncoming = null;
async function loadLiveRefs() {
    if (!_liveWasm) {
        try {
            const state = await import('./state.js');
            _liveWasm = state.wasm;
        } catch {
            _liveWasm = null;
        }
    }
    if (!_liveOnIncoming) {
        try {
            const m = await import('./messaging.js');
            _liveOnIncoming = m.onIncomingMessage;
        } catch {
            _liveOnIncoming = null;
        }
    }
}

// ---- Module state ---------------------------------------------------------

let wsId = null;
let circuitId = null;
let recvTimer = null;
let active = false;
let pendingEnable = null;

// Default poll cadence for circuit_recv. Small enough to feel live, large
// enough to avoid busy-looping the browser main thread.
const RECV_POLL_MS = 150;

export function isOnionActive() {
    return active;
}

// ---- Helpers --------------------------------------------------------------

function hexToBytes(hex) {
    if (!hex) return new Uint8Array(0);
    const out = new Uint8Array(hex.length >> 1);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}

// Default incoming-message handler: mirror the SW path in messaging.js.
// The server wraps payloads to this client as JSON `{ from, payload }`
// strings (the same `relay_msg` shape the SW forwards). When an onion
// circuit is multiplexed with direct delivery, the exit hop still emits
// the same JSON frame, so we parse identically here.
function dispatchIncoming(bytes) {
    let text;
    try {
        text = new TextDecoder().decode(bytes);
    } catch {
        return;
    }
    let msg;
    try {
        msg = JSON.parse(text);
    } catch {
        return;
    }
    if (msg && msg.type === 'message' && msg.from && typeof msg.payload === 'string') {
        if (_liveOnIncoming) _liveOnIncoming(msg.from, msg.payload);
    }
}

// ---- Lifecycle ------------------------------------------------------------

// Suspend the service-worker relay socket. The SW honors a
// `relay_disconnect` message (see sw.js) by closing its WebSocket.
function suspendSwRelay() {
    const sw = navigator.serviceWorker && navigator.serviceWorker.controller;
    if (sw) {
        try { sw.postMessage({ type: 'relay_disconnect' }); } catch {}
    }
}

// Resume the service-worker relay socket with the last-known URL + peerId.
function resumeSwRelay(relayUrl) {
    const sw = navigator.serviceWorker && navigator.serviceWorker.controller;
    if (sw) {
        try {
            sw.postMessage({
                type: 'relay_connect',
                url: relayUrl,
                peerId: (typeof window !== 'undefined' && window._peerId) || null,
            });
        } catch {}
    }
}

function startRecvLoop(deps) {
    const handler = (deps && deps.dispatch) || dispatchIncoming;
    const api = (deps && deps.wasm) || _liveWasm;
    if (recvTimer) return;
    recvTimer = setInterval(() => {
        if (circuitId === null || !api || !api.circuit_recv) return;
        // Drain everything available this tick. `circuit_recv` is
        // non-blocking and returns null when no DATA cell is queued.
        for (let i = 0; i < 32; i++) {
            let result;
            try {
                result = api.circuit_recv(circuitId);
            } catch {
                return;
            }
            if (!result) return;
            try { handler(result); } catch (e) {
                console.warn('[Onion] dispatch failed:', e && e.message);
            }
        }
    }, RECV_POLL_MS);
}

function stopRecvLoop() {
    if (recvTimer) {
        clearInterval(recvTimer);
        recvTimer = null;
    }
}

// Build a circuit over a freshly-opened main-thread WebSocket. On any
// failure, tear everything down so the caller can safely fall back to
// the SW path. Injected `deps` let the unit tests swap in a mock wasm.
export async function enableOnion(opts, deps) {
    if (active) return;
    if (pendingEnable) return pendingEnable;

    const relayUrl = opts && opts.relayUrl;
    if (!relayUrl) throw new Error('enableOnion requires relayUrl');

    // When no deps are injected (production path), resolve the live
    // wasm handle by dynamically importing state.js.
    if (!deps || !deps.wasm) {
        await loadLiveRefs();
    }
    const api = (deps && deps.wasm) || _liveWasm;
    if (!api || !api.ws_connect || !api.build_circuit) {
        throw new Error('WASM onion API not available');
    }

    // Serialise overlapping enables.
    const run = (async () => {
        // Close the SW-owned socket first — the relay should see a single
        // connection from us at a time (identified by PeerId), and we want
        // the circuit build to be unambiguous.
        suspendSwRelay();

        let openedWsId = null;
        let builtCircuit = null;
        try {
            openedWsId = api.ws_connect(relayUrl);
            if (api.ws_wait_open) {
                await api.ws_wait_open(openedWsId);
            }
            builtCircuit = await api.build_circuit(openedWsId);

            wsId = openedWsId;
            circuitId = builtCircuit;
            active = true;
            startRecvLoop(deps);
        } catch (e) {
            // Clean up anything half-built.
            if (openedWsId !== null && api.ws_close) {
                try { api.ws_close(openedWsId); } catch {}
            }
            wsId = null;
            circuitId = null;
            active = false;
            // Restore SW relay — user is falling back to the normal path.
            resumeSwRelay(relayUrl);
            throw e;
        }
    })();
    pendingEnable = run;
    try {
        await run;
    } finally {
        pendingEnable = null;
    }
}

// Tear down the circuit + main-thread socket, then hand control back to
// the service worker so background delivery resumes.
export async function disableOnion(opts, deps) {
    if (!active && circuitId === null && wsId === null) return;
    const api = (deps && deps.wasm) || _liveWasm;

    stopRecvLoop();

    if (circuitId !== null && api && api.circuit_destroy) {
        try { api.circuit_destroy(circuitId); } catch {}
    }
    circuitId = null;

    if (wsId !== null && api && api.ws_close) {
        try { api.ws_close(wsId); } catch {}
    }
    wsId = null;

    active = false;

    const relayUrl = opts && opts.relayUrl;
    if (relayUrl) resumeSwRelay(relayUrl);
}

// Send an envelope (hex string) through the active circuit. The inner
// payload is wrapped as the same JSON shape the SW `relay_send` emits so
// the relay server's single-relay MVP routing logic can dispatch it.
// Returns true on success, false if no circuit is active or the send
// path fails.
export function sendViaOnion(toPeerId, envelopeHex, deps) {
    if (!active || circuitId === null) return false;
    const api = (deps && deps.wasm) || _liveWasm;
    if (!api || !api.circuit_send) return false;

    const inner = JSON.stringify({
        type: 'message',
        to: toPeerId,
        payload: envelopeHex,
    });
    const data = new TextEncoder().encode(inner);

    try {
        api.circuit_send(circuitId, data);
        return true;
    } catch (e) {
        console.warn('[Onion] circuit_send failed:', e && e.message);
        return false;
    }
}

// Test-only: reset module state between suites.
export function _resetForTests() {
    stopRecvLoop();
    wsId = null;
    circuitId = null;
    active = false;
    pendingEnable = null;
}

// Exposed for tests / diagnostics.
export function _internalState() {
    return { active, wsId, circuitId };
}

// Re-export the internal dispatcher for tests that want to drive the
// recv-path directly without needing a circuit.
export { dispatchIncoming as _dispatchIncoming, hexToBytes as _hexToBytes, bytesToHex as _bytesToHex };
