// ParolNet PWA — Telemetry
import { isDevMode } from './utils.js';
import { connMgr } from './connection.js';

export const telemetry = {
    sid: Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join(''),
    events: [],
    MAX_EVENTS: 500,

    track(type, meta) {
        if (!isDevMode()) return;
        if (this.events.length >= this.MAX_EVENTS) this.events.shift();
        this.events.push({ type, ts: Date.now(), meta: meta || null });
    },

    async flush() {
        if (!isDevMode()) return;
        if (this.events.length === 0) return;
        // Skip telemetry if no relay server is configured/connected
        const relayUrl = connMgr && connMgr.relayUrl;
        if (!relayUrl) return;
        // Convert WebSocket URL to HTTP base URL for telemetry endpoint
        const httpBase = relayUrl.replace(/^ws(s?):/, 'http$1:').replace(/\/ws\/?$/, '');
        const batch = {
            sid: this.sid,
            ts: Date.now(),
            events: this.events.splice(0, this.events.length)
        };
        try {
            const resp = await fetch(httpBase + '/telemetry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(batch)
            });
            if (!resp.ok) {
                // Put events back
                this.events.unshift(...batch.events);
                if (this.events.length > this.MAX_EVENTS) {
                    this.events.length = this.MAX_EVENTS;
                }
            }
        } catch(e) {
            // Network error — put events back
            this.events.unshift(...batch.events);
            if (this.events.length > this.MAX_EVENTS) {
                this.events.length = this.MAX_EVENTS;
            }
        }
    }
};

// Flush telemetry every 60 seconds
setInterval(() => telemetry.flush(), 60000);

// Flush on page hide (user navigating away)
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
        telemetry.flush();
    }
    telemetry.track(document.visibilityState === 'visible' ? 'app_visible' : 'app_hidden');
});
