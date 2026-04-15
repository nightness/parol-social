// ParolNet Relay Discovery Client
// Implements fallback chain: cached directory -> bootstrap relays -> fetch from any relay.
// Goal: any single relay alive = entire network reachable.

import { BOOTSTRAP_RELAYS, AUTHORITY_PUBKEYS } from './network-config.js';

const DIRECTORY_CACHE_KEY = 'parolnet_relay_directory';
const DIRECTORY_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const BRIDGE_RELAYS_DB_KEY = 'bridge_relays';

/**
 * Relay discovery and connection with fallback chain.
 *
 * Startup order:
 *   1. Load cached directory from localStorage (from last session)
 *   2. Fall back to bundled BOOTSTRAP_RELAYS from network-config.js
 *   3. Try each known relay to fetch the full directory via GET /directory
 *   On success: cache the directory and populate this.relays
 */
export class RelayClient {
    constructor() {
        /** @type {string[]} Known relay WebSocket URLs */
        this.relays = [];
        /** @type {string|null} Currently connected relay URL */
        this.connectedRelay = null;
        /** @type {boolean} */
        this.connected = false;
        /** @type {Object|null} Raw directory data from last fetch */
        this._lastDirectory = null;
        /**
         * Bridge relays for censorship circumvention.
         * Each entry: { host, port, front_domain?, fingerprint?, wsUrl }
         * @type {Object[]}
         */
        this.bridgeRelays = [];
    }

    /**
     * Initialize relay discovery with fallback chain.
     * Populates this.relays with all known relay addresses.
     * Also loads bridge relays from IndexedDB.
     * @returns {Promise<string[]>} List of discovered relay URLs
     */
    async discover() {
        // 0. Load bridge relays from IndexedDB
        await this.loadBridges();

        // 1. Try cached directory from last session
        const cached = this.loadCachedDirectory();
        if (cached && cached.relays && cached.relays.length > 0) {
            console.log('[RelayClient] Loaded', cached.relays.length, 'relays from cache');
            this.relays = cached.relays.slice();
        }

        // 2. Merge in bundled bootstrap relays
        if (BOOTSTRAP_RELAYS && BOOTSTRAP_RELAYS.length > 0) {
            for (const url of BOOTSTRAP_RELAYS) {
                if (!this.relays.includes(url)) {
                    this.relays.push(url);
                }
            }
            console.log('[RelayClient] After bootstrap merge:', this.relays.length, 'relays');
        }

        // 3. If we have no relays at all, use same-origin as fallback
        if (this.relays.length === 0) {
            const origin = location.protocol + '//' + location.host;
            this.relays.push(origin);
            console.log('[RelayClient] Using same-origin fallback:', origin);
        }

        // 4. Try to fetch full directory from any known relay
        await this._fetchFromAnyRelay();

        return this.relays;
    }

    /**
     * Try fetching directory from each known relay until one succeeds.
     * @returns {Promise<boolean>}
     */
    async _fetchFromAnyRelay() {
        // Shuffle for load distribution
        const shuffled = this._shuffle(this.relays.slice());
        for (const relayUrl of shuffled) {
            try {
                const relays = await this.fetchDirectory(relayUrl);
                if (relays && relays.length > 0) {
                    // Merge discovered relays into our list
                    let added = 0;
                    for (const url of relays) {
                        if (!this.relays.includes(url)) {
                            this.relays.push(url);
                            added++;
                        }
                    }
                    if (added > 0) {
                        console.log('[RelayClient] Discovered', added, 'new relays from', relayUrl);
                    }
                    // Cache updated directory
                    this.cacheDirectory({ relays: this.relays, fetchedAt: Date.now() });
                    return true;
                }
            } catch (e) {
                console.debug('[RelayClient] Failed to fetch directory from', relayUrl, e.message);
            }
        }
        return false;
    }

    /**
     * Fetch directory from a specific relay.
     * @param {string} relayUrl - Base URL of the relay (e.g., "https://relay.example.com")
     * @returns {Promise<string[]>} List of relay addresses extracted from directory
     */
    async fetchDirectory(relayUrl) {
        const url = relayUrl.replace(/\/$/, '') + '/directory';
        const resp = await fetch(url, {
            signal: AbortSignal.timeout(10000),
        });
        if (!resp.ok) {
            throw new Error('HTTP ' + resp.status);
        }

        const contentType = resp.headers.get('content-type') || '';
        let descriptors;

        if (contentType.includes('cbor')) {
            // Parse CBOR response — try WASM bindings first, fall back to raw parsing
            const arrayBuf = await resp.arrayBuffer();
            descriptors = await this._parseCborDirectory(new Uint8Array(arrayBuf));
        } else {
            // Fallback: try JSON
            descriptors = await resp.json();
        }

        if (!Array.isArray(descriptors)) {
            return [];
        }

        this._lastDirectory = descriptors;

        // Extract relay addresses from descriptors
        // Each descriptor has an `addr` field (SocketAddr as string like "1.2.3.4:9000")
        const relayAddrs = [];
        for (const desc of descriptors) {
            if (desc && desc.addr) {
                // Convert SocketAddr to HTTP URL
                const httpUrl = this._socketAddrToUrl(desc.addr);
                if (httpUrl) {
                    relayAddrs.push(httpUrl);
                }
            }
        }
        return relayAddrs;
    }

    /**
     * Parse CBOR-encoded directory data.
     * Uses WASM bindings if available, otherwise attempts minimal CBOR decode.
     * @param {Uint8Array} data
     * @returns {Promise<Object[]>}
     */
    async _parseCborDirectory(data) {
        // Try WASM CBOR decoder if available
        if (typeof window !== 'undefined' && window._parolnetWasm &&
            typeof window._parolnetWasm.decode_cbor === 'function') {
            try {
                return window._parolnetWasm.decode_cbor(data);
            } catch (e) {
                console.debug('[RelayClient] WASM CBOR decode failed, using fallback:', e.message);
            }
        }

        // Minimal CBOR array-of-maps decoder for relay descriptors.
        // The relay server encodes Vec<RelayDescriptor> as a CBOR array of maps.
        // We only need the "addr" field from each map entry.
        //
        // This is a best-effort decoder — if it fails, we return an empty array
        // and rely on the fallback chain.
        try {
            return this._decodeCborDescriptors(data);
        } catch (e) {
            console.debug('[RelayClient] Fallback CBOR decode failed:', e.message);
            return [];
        }
    }

    /**
     * Minimal CBOR decoder for relay descriptor arrays.
     * Handles the subset of CBOR needed for our directory format.
     * @param {Uint8Array} data
     * @returns {Object[]}
     */
    _decodeCborDescriptors(data) {
        let offset = 0;

        function readByte() {
            if (offset >= data.length) throw new Error('unexpected end');
            return data[offset++];
        }

        function readUint(additionalInfo) {
            if (additionalInfo < 24) return additionalInfo;
            if (additionalInfo === 24) return readByte();
            if (additionalInfo === 25) {
                const hi = readByte(), lo = readByte();
                return (hi << 8) | lo;
            }
            if (additionalInfo === 26) {
                let val = 0;
                for (let i = 0; i < 4; i++) val = (val << 8) | readByte();
                return val;
            }
            if (additionalInfo === 27) {
                // 8-byte integer — JS safe integer limit may apply
                let val = 0;
                for (let i = 0; i < 8; i++) val = val * 256 + readByte();
                return val;
            }
            throw new Error('unsupported additional info: ' + additionalInfo);
        }

        function readItem() {
            const initial = readByte();
            const majorType = initial >> 5;
            const additionalInfo = initial & 0x1f;

            switch (majorType) {
                case 0: // unsigned integer
                    return readUint(additionalInfo);
                case 1: // negative integer
                    return -1 - readUint(additionalInfo);
                case 2: { // byte string
                    const len = readUint(additionalInfo);
                    const bytes = data.slice(offset, offset + len);
                    offset += len;
                    return bytes;
                }
                case 3: { // text string
                    const len = readUint(additionalInfo);
                    const textBytes = data.slice(offset, offset + len);
                    offset += len;
                    return new TextDecoder().decode(textBytes);
                }
                case 4: { // array
                    const len = readUint(additionalInfo);
                    const arr = [];
                    for (let i = 0; i < len; i++) arr.push(readItem());
                    return arr;
                }
                case 5: { // map
                    const len = readUint(additionalInfo);
                    const obj = {};
                    for (let i = 0; i < len; i++) {
                        const key = readItem();
                        const val = readItem();
                        obj[String(key)] = val;
                    }
                    return obj;
                }
                case 6: { // tag (skip tag number, return content)
                    readUint(additionalInfo);
                    return readItem();
                }
                case 7: { // simple values / float
                    if (additionalInfo === 20) return false;
                    if (additionalInfo === 21) return true;
                    if (additionalInfo === 22) return null;
                    if (additionalInfo === 23) return undefined;
                    if (additionalInfo === 25 || additionalInfo === 26 || additionalInfo === 27) {
                        // float — skip bytes
                        const floatLen = additionalInfo === 25 ? 2 : additionalInfo === 26 ? 4 : 8;
                        offset += floatLen;
                        return 0; // simplified: we don't need float precision
                    }
                    return null;
                }
                default:
                    throw new Error('unknown CBOR major type: ' + majorType);
            }
        }

        return readItem();
    }

    /**
     * Convert a SocketAddr string (e.g., "1.2.3.4:9000") to an HTTP URL.
     * @param {string} addr
     * @returns {string|null}
     */
    _socketAddrToUrl(addr) {
        if (!addr || typeof addr !== 'string') return null;
        // Handle IPv6 bracket notation
        if (addr.startsWith('[')) {
            // [::1]:9000 format
            const closeBracket = addr.lastIndexOf(']');
            if (closeBracket < 0) return null;
            const host = addr.slice(0, closeBracket + 1);
            const port = addr.slice(closeBracket + 2);
            return 'http://' + host + ':' + port;
        }
        // IPv4 format: 1.2.3.4:9000
        return 'http://' + addr;
    }

    /**
     * Try connecting to any available relay via WebSocket.
     * Bridge relays are tried first (priority), then regular relays.
     * Shuffles each group for load distribution.
     * @returns {Promise<string|null>} URL of connected relay, or null
     */
    async connect() {
        // Try bridge relays first (priority for censored networks)
        if (this.bridgeRelays.length > 0) {
            const shuffledBridges = this._shuffle(this.bridgeRelays.slice());
            for (const bridge of shuffledBridges) {
                const wsUrl = bridge.wsUrl;
                try {
                    const success = await this._tryConnect(wsUrl);
                    if (success) {
                        this.connectedRelay = wsUrl;
                        this.connected = true;
                        console.log('[RelayClient] Connected via bridge relay:', wsUrl);
                        return wsUrl;
                    }
                } catch (e) {
                    console.debug('[RelayClient] Bridge connection failed to', wsUrl, e.message);
                }
            }
        }

        // Fall back to regular relays
        const shuffled = this._shuffle(this.relays.slice());
        for (const relayUrl of shuffled) {
            const wsUrl = this._toWebSocketUrl(relayUrl);
            try {
                const success = await this._tryConnect(wsUrl);
                if (success) {
                    this.connectedRelay = relayUrl;
                    this.connected = true;
                    console.log('[RelayClient] Connected to relay:', relayUrl);
                    return relayUrl;
                }
            } catch (e) {
                console.debug('[RelayClient] Connection failed to', relayUrl, e.message);
            }
        }
        this.connected = false;
        this.connectedRelay = null;
        return null;
    }

    /**
     * Attempt a WebSocket connection with a timeout.
     * @param {string} wsUrl
     * @returns {Promise<boolean>}
     */
    _tryConnect(wsUrl) {
        return new Promise((resolve) => {
            const timeout = setTimeout(() => {
                try { ws.close(); } catch (_) {}
                resolve(false);
            }, 5000);

            let ws;
            try {
                ws = new WebSocket(wsUrl);
            } catch (_) {
                clearTimeout(timeout);
                resolve(false);
                return;
            }

            ws.onopen = () => {
                clearTimeout(timeout);
                ws.close();
                resolve(true);
            };
            ws.onerror = () => {
                clearTimeout(timeout);
                resolve(false);
            };
            ws.onclose = () => {
                clearTimeout(timeout);
                resolve(false);
            };
        });
    }

    /**
     * Convert an HTTP URL to a WebSocket URL with /ws path.
     * @param {string} httpUrl
     * @returns {string}
     */
    _toWebSocketUrl(httpUrl) {
        let url = httpUrl.replace(/\/$/, '');
        if (url.startsWith('https://')) {
            url = 'wss://' + url.slice(8);
        } else if (url.startsWith('http://')) {
            url = 'ws://' + url.slice(7);
        }
        return url + '/ws';
    }

    /**
     * Cache directory to localStorage.
     * @param {Object} directory - { relays: string[], fetchedAt: number }
     */
    cacheDirectory(directory) {
        try {
            localStorage.setItem(DIRECTORY_CACHE_KEY, JSON.stringify(directory));
        } catch (e) {
            console.debug('[RelayClient] Failed to cache directory:', e.message);
        }
    }

    /**
     * Load cached directory from localStorage.
     * Returns null if cache is missing or expired.
     * @returns {Object|null}
     */
    loadCachedDirectory() {
        try {
            const raw = localStorage.getItem(DIRECTORY_CACHE_KEY);
            if (!raw) return null;
            const parsed = JSON.parse(raw);
            if (!parsed || !parsed.fetchedAt) return null;
            // Check TTL
            if (Date.now() - parsed.fetchedAt > DIRECTORY_CACHE_TTL_MS) {
                localStorage.removeItem(DIRECTORY_CACHE_KEY);
                return null;
            }
            return parsed;
        } catch (e) {
            return null;
        }
    }

    /**
     * Add a bridge relay from a bridge address string.
     * Format: bridge:host:port[;front=domain][;fp=hex_fingerprint]
     * @param {string} bridgeString
     * @returns {Object} The parsed bridge entry
     */
    addBridge(bridgeString) {
        const bridge = this._parseBridgeString(bridgeString);
        // Avoid duplicates
        const existing = this.bridgeRelays.find(
            b => b.host === bridge.host && b.port === bridge.port
        );
        if (!existing) {
            this.bridgeRelays.push(bridge);
            console.log('[RelayClient] Added bridge relay:', bridge.wsUrl);
        }
        return bridge;
    }

    /**
     * Parse a bridge address string into an object.
     * Format: bridge:host:port[;front=domain][;fp=hex_fingerprint]
     * @param {string} s
     * @returns {Object} { host, port, front_domain, fingerprint, wsUrl }
     */
    _parseBridgeString(s) {
        s = s.trim();
        if (!s.startsWith('bridge:')) {
            throw new Error('Bridge string must start with "bridge:"');
        }
        const rest = s.slice('bridge:'.length);
        const parts = rest.split(';');
        const hostPort = parts[0];

        // Find last colon for port separator
        const lastColon = hostPort.lastIndexOf(':');
        if (lastColon < 0) {
            throw new Error('Bridge string missing port');
        }
        const host = hostPort.slice(0, lastColon);
        const port = parseInt(hostPort.slice(lastColon + 1), 10);
        if (!host || isNaN(port)) {
            throw new Error('Invalid bridge host:port');
        }

        let front_domain = null;
        let fingerprint = null;

        for (let i = 1; i < parts.length; i++) {
            const param = parts[i];
            if (param.startsWith('front=')) {
                front_domain = param.slice('front='.length);
            } else if (param.startsWith('fp=')) {
                fingerprint = param.slice('fp='.length);
            }
        }

        // Build WebSocket URL
        let wsUrl;
        if (front_domain) {
            wsUrl = 'wss://' + front_domain + '/ws';
        } else {
            wsUrl = 'wss://' + host + ':' + port + '/ws';
        }

        return { host, port, front_domain, fingerprint, wsUrl };
    }

    /**
     * Load bridge relays from IndexedDB settings.
     * @returns {Promise<void>}
     */
    async loadBridges() {
        try {
            if (typeof window === 'undefined' || !window.indexedDB) return;
            const bridges = await this._idbGet(BRIDGE_RELAYS_DB_KEY);
            if (Array.isArray(bridges) && bridges.length > 0) {
                this.bridgeRelays = bridges;
                console.log('[RelayClient] Loaded', bridges.length, 'bridge relays from IndexedDB');
            }
        } catch (e) {
            console.debug('[RelayClient] Failed to load bridges from IndexedDB:', e.message);
        }
    }

    /**
     * Save bridge relays to IndexedDB settings.
     * @returns {Promise<void>}
     */
    async saveBridges() {
        try {
            if (typeof window === 'undefined' || !window.indexedDB) return;
            await this._idbSet(BRIDGE_RELAYS_DB_KEY, this.bridgeRelays);
        } catch (e) {
            console.debug('[RelayClient] Failed to save bridges to IndexedDB:', e.message);
        }
    }

    /**
     * Read a value from IndexedDB 'parolnet_settings' store.
     * @param {string} key
     * @returns {Promise<any>}
     */
    _idbGet(key) {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open('parolnet_settings', 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings');
                }
            };
            req.onsuccess = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains('settings')) {
                    db.close();
                    resolve(null);
                    return;
                }
                const tx = db.transaction('settings', 'readonly');
                const store = tx.objectStore('settings');
                const getReq = store.get(key);
                getReq.onsuccess = () => resolve(getReq.result);
                getReq.onerror = () => reject(getReq.error);
                tx.oncomplete = () => db.close();
            };
            req.onerror = () => reject(req.error);
        });
    }

    /**
     * Write a value to IndexedDB 'parolnet_settings' store.
     * @param {string} key
     * @param {any} value
     * @returns {Promise<void>}
     */
    _idbSet(key, value) {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open('parolnet_settings', 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings');
                }
            };
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction('settings', 'readwrite');
                const store = tx.objectStore('settings');
                store.put(value, key);
                tx.oncomplete = () => { db.close(); resolve(); };
                tx.onerror = () => { db.close(); reject(tx.error); };
            };
            req.onerror = () => reject(req.error);
        });
    }

    /**
     * Get the number of known relays.
     * @returns {number}
     */
    get knownRelayCount() {
        return this.relays.length;
    }

    /**
     * Fisher-Yates shuffle (in-place).
     * @param {any[]} arr
     * @returns {any[]}
     */
    _shuffle(arr) {
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    }
}
