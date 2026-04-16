// ParolNet PWA — Shared Mutable State
import { CryptoStore } from './crypto-store.js';
import { RelayClient } from './relay-client.js';

export const cryptoStore = new CryptoStore();
export const relayClient = new RelayClient();

export let wasm = null;
export function setWasm(w) { wasm = w; }

export let currentView = 'loading';
export function setCurrentView(v) { currentView = v; }

export let currentPeerId = null;
export function setCurrentPeerId(v) { currentPeerId = v; window.currentPeerId = v; }

export let currentCallId = null;
export function setCurrentCallId(v) { currentCallId = v; }

export let currentGroupId = null;
export function setCurrentGroupId(v) { currentGroupId = v; }

export let currentGroupCallId = null;
export function setCurrentGroupCallId(v) { currentGroupCallId = v; }

export let incomingCallInfo = null; // { from, callId }
export function setIncomingCallInfo(v) { incomingCallInfo = v; }

export let localStream = null;
export function setLocalStream(v) { localStream = v; }

export let platform = 'default';
export function setPlatform(v) { platform = v; }

// File receive tracking: fileId -> { name, size, chunksReceived, totalChunks, msgEl }
export const pendingFileReceives = {};

// Group call participant poll interval
export let groupCallPollInterval = null;
export function setGroupCallPollInterval(v) { groupCallPollInterval = v; }

window._knownPeers = [];
