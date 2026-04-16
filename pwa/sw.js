// ParolNet Service Worker
// Cache-first strategy: the app works entirely offline after first load.
// If the source site goes down, the app continues to function from cache.

const CACHE_NAME = 'parolnet-v9';

// ── SRI hashes for critical resources ─────────────────────────
// SHA-256 hashes of critical cached resources. On cache hit for these files,
// the service worker verifies the cached content hasn't been tampered with.
// If the hash doesn't match, the resource is re-fetched from the network.
// Regenerate these hashes whenever the corresponding files change.
const RESOURCE_HASHES = {
    'app.js': '1b12c72aa2de8f19654ca814790a6c7db16fd603a7e76d71d68634eddaf36c76',
    'styles.css': 'a4a07e1fe925dbd2324e9cf01e9454dadd9c3409e19e39df1f4254f5682dfcc2',
    'crypto-store.js': '2aba63c04e985c4d9d3aeb969d3321eb9cb9c7e86e3d8519cdc7f4d722b0a45f',
    'index.html': '1a85191fc4392bc09586e39f6bd5aa3456873d8d1a201caa2b4f99331e38d2d1',
};

// Compute SHA-256 hex digest of an ArrayBuffer.
async function sha256Hex(buffer) {
    const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
    const bytes = new Uint8Array(hashBuf);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}

// Extract the filename from a request URL for hash lookup.
function getResourceName(url) {
    const path = new URL(url).pathname;
    const parts = path.split('/');
    return parts[parts.length - 1];
}

// All assets that must be cached for offline operation.
// The app is fully self-contained — zero external dependencies.
const ASSETS_TO_CACHE = [
    './',
    './index.html',
    './styles.css',
    './calculator.css',
    './app.js',
    './crypto-store.js',
    './data-export.js',
    './qrcode.js',
    './qrdecoder.js',
    './manifest.json',
    './manifest-calculator.json',
    './icons/icon.svg',
    './icons/icon-192.png',
    './icons/icon-512.png',
    './icons/calc-ios.svg',
    './icons/calc-android.svg',
    './icons/calc-windows.svg',
    './icons/calc-192.png',
    './icons/calc-512.png',
    './pkg/parolnet_wasm.js',
    './pkg/parolnet_wasm_bg.wasm',
    './network-config.js',
    './relay-client.js',
    './lang/en.json',
    './lang/ru.json',
    './lang/fa.json',
    './lang/zh-CN.json',
    './lang/zh-TW.json',
    './lang/ko.json',
    './lang/ja.json',
    './lang/fr.json',
    './lang/de.json',
    './lang/it.json',
    './lang/pt.json',
    './lang/ar.json',
    './lang/es.json',
    './lang/tr.json',
    './lang/my.json',
    './lang/vi.json',
];

// ── Install: cache all assets ──────────────────────────────────
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('[SW] Caching all assets');
                return cache.addAll(ASSETS_TO_CACHE).catch(err => {
                    // Don't fail install if some assets aren't available yet
                    // (e.g., WASM not built yet during development)
                    console.warn('[SW] Some assets not cached:', err.message);
                });
            })
            // NOTE: skipWaiting() intentionally removed from install handler.
            // A compromised SW update should NOT immediately take control.
            // Users get the new SW on next visit. Explicit skipWaiting is
            // still available via message handler for manual updates.
    );
});

// ── Activate: clean up old caches ──────────────────────────────
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(keys => {
                return Promise.all(
                    keys
                        .filter(key => key !== CACHE_NAME)
                        .map(key => {
                            console.log('[SW] Removing old cache:', key);
                            return caches.delete(key);
                        })
                );
            })
            .then(() => self.clients.claim())
    );
});

// ── Fetch: cache-first, fall back to network ───────────────────
// This is the key to offline-first operation:
// 1. Try the cache first (instant, works offline)
// 2. If not cached, try the network
// 3. If network fails and not cached, show offline page
self.addEventListener('fetch', event => {
    // Only handle same-origin requests
    if (!event.request.url.startsWith(self.location.origin)) {
        return;
    }

    // Only cache GET requests — Cache API doesn't support POST
    if (event.request.method !== 'GET') {
        return;
    }

    event.respondWith(
        caches.match(event.request)
            .then(async cachedResponse => {
                if (cachedResponse) {
                    // Cache hit — verify integrity for critical resources
                    const resourceName = getResourceName(event.request.url);
                    const expectedHash = RESOURCE_HASHES[resourceName];

                    if (expectedHash) {
                        // Clone before reading body (body can only be consumed once)
                        const clone = cachedResponse.clone();
                        try {
                            const buf = await clone.arrayBuffer();
                            const actualHash = await sha256Hex(buf);
                            if (actualHash !== expectedHash) {
                                console.warn('[SW] Integrity mismatch for', resourceName, '— refetching from network');
                                // Hash mismatch: cached resource may be tampered with.
                                // Attempt to fetch a fresh copy from network.
                                try {
                                    const freshResponse = await fetch(event.request);
                                    if (freshResponse && freshResponse.ok) {
                                        const freshClone = freshResponse.clone();
                                        const cache = await caches.open(CACHE_NAME);
                                        await cache.put(event.request, freshClone);
                                        return freshResponse;
                                    }
                                } catch {
                                    // Network unavailable — return cached even if tampered,
                                    // better than nothing for offline use
                                }
                            }
                        } catch {
                            // If integrity check itself fails, fall through to cached
                        }
                    }

                    // Also update cache in background (stale-while-revalidate)
                    fetch(event.request)
                        .then(networkResponse => {
                            if (networkResponse && networkResponse.ok) {
                                const netClone = networkResponse.clone();
                                caches.open(CACHE_NAME).then(cache => {
                                    cache.put(event.request, netClone);
                                });
                            }
                        })
                        .catch(() => {
                            // Network failed, but we have cache — that's fine
                        });

                    return cachedResponse;
                }

                // Not in cache — try network
                return fetch(event.request)
                    .then(networkResponse => {
                        if (networkResponse && networkResponse.ok) {
                            // Cache the new response
                            const clone = networkResponse.clone();
                            caches.open(CACHE_NAME).then(cache => {
                                cache.put(event.request, clone);
                            });
                        }
                        return networkResponse;
                    })
                    .catch(() => {
                        // Network failed, nothing in cache
                        return new Response(
                            '<h1>Offline</h1><p>Not yet cached. Connect to the internet once to enable offline use.</p>',
                            {
                                headers: { 'Content-Type': 'text/html' },
                                status: 503
                            }
                        );
                    });
            })
    );
});

// ── Push Notifications ─────────────────────────────────────────
// Handle incoming push messages from the network.
// The payload is expected to be JSON: { title, body, peerId }
self.addEventListener('push', event => {
    let data = { title: 'New Message', body: 'You have a new message.', peerId: '' };

    if (event.data) {
        try {
            data = Object.assign(data, event.data.json());
        } catch {
            data.body = event.data.text();
        }
    }

    const options = {
        body: data.body,
        icon: './icons/icon-192.png',
        badge: './icons/icon-192.png',
        tag: 'parolnet-' + (data.peerId || 'msg'),
        data: { peerId: data.peerId || '' },
        vibrate: [200, 100, 200],
        requireInteraction: false,
    };

    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// ── Notification Click ─────────────────────────────────────────
// Open the app and navigate to the relevant chat when a notification is tapped.
self.addEventListener('notificationclick', event => {
    event.notification.close();

    const peerId = event.notification.data?.peerId || '';

    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then(clients => {
                // If an app window is already open, focus it
                for (const client of clients) {
                    if (client.url.includes('index.html') || client.url.endsWith('/')) {
                        client.postMessage({ type: 'openChat', peerId });
                        return client.focus();
                    }
                }
                // Otherwise open a new window
                const url = peerId
                    ? `./index.html?chat=${encodeURIComponent(peerId)}`
                    : './index.html';
                return self.clients.openWindow(url);
            })
    );
});

// ── Relay WebSocket (background communications) ────────────
// Owning the WebSocket here keeps it alive when the page is
// backgrounded (Android/Chrome/desktop). Page JS suspends;
// SW does not — messages still arrive.

let relayWs = null;
let relayUrl = null;
let relayPeerId = null;
let relayReconnectTimer = null;
let relayReconnectDelay = 1000;
let relayConnected = false;

function swConnectRelay() {
    if (relayWs && (relayWs.readyState === 0 || relayWs.readyState === 1)) return;
    if (!relayUrl) return;
    try {
        relayWs = new WebSocket(relayUrl);
    } catch(e) {
        swScheduleReconnect();
        return;
    }

    relayWs.onopen = () => {
        console.log('[SW-Relay] WebSocket open, awaiting registration...');
        relayReconnectDelay = 1000;
        if (relayPeerId) {
            relayWs.send(JSON.stringify({ type: 'register', peer_id: relayPeerId }));
        }
    };

    relayWs.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            // Only mark as connected after relay confirms registration
            if (msg.type === 'registered' && !relayConnected) {
                console.log('[SW-Relay] registered with relay');
                relayConnected = true;
                swBroadcastStatus(true);
            }
            swBroadcastOrBuffer(msg);
        } catch(e) {}
    };

    relayWs.onclose = () => {
        console.log('[SW-Relay] disconnected');
        relayConnected = false;
        swBroadcastStatus(false);
        swScheduleReconnect();
    };

    relayWs.onerror = () => {};
}

function swScheduleReconnect() {
    if (relayReconnectTimer) return;
    relayReconnectTimer = setTimeout(() => {
        relayReconnectTimer = null;
        relayReconnectDelay = Math.min(relayReconnectDelay * 2, 30000);
        swConnectRelay();
    }, relayReconnectDelay);
}

function swBroadcastStatus(connected) {
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
        for (const client of clients) {
            client.postMessage({ type: 'relay_status', connected });
        }
    });
}

async function swBroadcastOrBuffer(msg) {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length > 0) {
        for (const client of clients) {
            client.postMessage({ type: 'relay_msg', msg });
        }
    } else {
        await swInboxWrite(msg);
    }
}

async function swInboxWrite(msg) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('parolnet-sw', 1);
        req.onupgradeneeded = (e) => {
            e.target.result.createObjectStore('sw-inbox', { keyPath: 'id', autoIncrement: true });
        };
        req.onsuccess = (e) => {
            const db = e.target.result;
            const tx = db.transaction('sw-inbox', 'readwrite');
            const store = tx.objectStore('sw-inbox');
            store.count().onsuccess = (ce) => {
                if (ce.target.result >= 200) {
                    store.openCursor().onsuccess = (cur) => {
                        if (cur.target.result) cur.target.result.delete();
                    };
                }
                store.add({ msg, timestamp: Date.now() });
            };
            tx.oncomplete = () => { db.close(); resolve(); };
            tx.onerror = () => { db.close(); reject(); };
        };
        req.onerror = reject;
    });
}

// ── Message handling ───────────────────────────────────────────
self.addEventListener('message', event => {
    if (event.data === 'skipWaiting') {
        self.skipWaiting();
        return;
    }

    if (event.data === 'panicWipe') {
        caches.keys().then(keys => {
            keys.forEach(key => caches.delete(key));
        });
        self.registration.unregister();
        return;
    }

    const d = event.data;
    if (!d || typeof d !== 'object') return;

    switch (d.type) {
        case 'relay_connect':
            relayUrl = d.url;
            relayPeerId = d.peerId;
            swConnectRelay();
            break;
        case 'relay_register':
            relayPeerId = d.peerId;
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({ type: 'register', peer_id: d.peerId }));
            }
            break;
        case 'relay_register_auth':
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({
                    type: 'register',
                    peer_id: d.peerId,
                    pubkey: d.pubkey,
                    signature: d.signature,
                    nonce: d.nonce
                }));
            }
            break;
        case 'relay_send':
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({ type: 'message', to: d.to, payload: d.payload }));
            }
            break;
        case 'relay_signaling':
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({ type: d.msgType, to: d.to, payload: d.payload }));
            }
            break;
        case 'relay_status_query':
            if (event.source) {
                event.source.postMessage({ type: 'relay_status', connected: relayConnected });
            }
            break;
    }
});
