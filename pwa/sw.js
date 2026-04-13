// ParolNet Service Worker
// Cache-first strategy: the app works entirely offline after first load.
// If the source site goes down, the app continues to function from cache.

const CACHE_NAME = 'parolnet-v6';

// All assets that must be cached for offline operation.
// The app is fully self-contained — zero external dependencies.
const ASSETS_TO_CACHE = [
    './',
    './index.html',
    './styles.css',
    './calculator.css',
    './app.js',
    './crypto-store.js',
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
            .then(() => self.skipWaiting())
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
            .then(cachedResponse => {
                if (cachedResponse) {
                    // Cache hit — return cached version
                    // Also update cache in background (stale-while-revalidate)
                    const fetchPromise = fetch(event.request)
                        .then(networkResponse => {
                            if (networkResponse && networkResponse.ok) {
                                const clone = networkResponse.clone();
                                caches.open(CACHE_NAME).then(cache => {
                                    cache.put(event.request, clone);
                                });
                            }
                            return networkResponse;
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

// ── Message handling ───────────────────────────────────────────
self.addEventListener('message', event => {
    if (event.data === 'skipWaiting') {
        self.skipWaiting();
    }

    // Panic wipe: clear all caches
    if (event.data === 'panicWipe') {
        caches.keys().then(keys => {
            keys.forEach(key => caches.delete(key));
        });
        // Unregister self
        self.registration.unregister();
    }
});
