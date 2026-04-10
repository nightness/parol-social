/* tslint:disable */
/* eslint-disable */

/**
 * Answer an incoming call.
 */
export function answer_call(call_id_hex: string): void;

/**
 * Reassemble a completed file transfer and return the raw bytes.
 */
export function assemble_file(file_id_hex: string): Uint8Array;

/**
 * Compute a 6-digit SAS verification string.
 */
export function compute_sas(bootstrap_secret_hex: string, ik_alice_hex: string, ik_bob_hex: string, ek_alice_hex: string, ek_bob_hex: string): string;

/**
 * Create a new outgoing file transfer. Returns the file_id as hex.
 */
export function create_file_transfer(data: Uint8Array, filename: string, mime_type?: string | null): string;

/**
 * Establish a Double Ratchet session with a peer.
 *
 * All arguments are hex-encoded 32-byte values.
 */
export function create_session(peer_id_hex: string, shared_secret_hex: string, ratchet_key_hex: string): void;

/**
 * Decrypt a message using the Double Ratchet session for the given peer.
 *
 * `peer_id_hex` — 32-byte peer id, hex-encoded.
 * `ciphertext` — bytes previously produced by `encrypt_message` (header + ciphertext).
 *
 * Returns the decrypted plaintext bytes.
 */
export function decrypt_message(peer_id_hex: string, ciphertext: Uint8Array): Uint8Array;

/**
 * Encrypt a message using the Double Ratchet session for the given peer.
 *
 * `peer_id_hex` — 32-byte peer id, hex-encoded.
 * `plaintext` — raw bytes to encrypt.
 *
 * Returns the ciphertext bytes (header + ciphertext concatenated).
 */
export function encrypt_message(peer_id_hex: string, plaintext: Uint8Array): Uint8Array;

/**
 * Enter decoy mode — the app should switch to a fake UI.
 */
export function enter_decoy_mode(): void;

/**
 * Generate a new identity keypair and return the PeerId (32 bytes, hex-encoded).
 */
export function generate_identity(): string;

/**
 * Generate a new identity and return the public key bytes (hex-encoded).
 */
export function generate_keypair(): any;

/**
 * Generate a QR bootstrap payload (CBOR bytes, hex-encoded).
 */
export function generate_qr_payload(identity_key_hex: string, relay_hint?: string | null): string;

/**
 * Get the state of a call. Returns one of:
 * "idle", "offering", "ringing", "active", "ended", "rejected", or "unknown".
 */
export function get_call_state(call_id_hex: string): string;

/**
 * Get the file offer for an outgoing transfer.
 * Returns `{ file_id, file_name, file_size, chunk_size, total_chunks }`.
 */
export function get_file_offer(file_id_hex: string): any;

/**
 * Get the next chunk from an outgoing file transfer.
 * Returns `{ chunk_index, data_hex, is_last }` or null if all chunks are sent.
 */
export function get_next_chunk(file_id_hex: string): any;

/**
 * Hang up an active call.
 */
export function hangup_call(call_id_hex: string): void;

/**
 * Check if a session exists for a peer.
 */
export function has_session(peer_id_hex: string): boolean;

/**
 * Initialize the WASM module.
 */
export function init(): void;

/**
 * Create a new ParolNet instance with default config.
 * Returns the peer_id as hex.
 */
export function initialize(): string;

/**
 * Check if an unlock code has been set (decoy mode is enabled).
 */
export function is_decoy_enabled(): boolean;

/**
 * Emergency: wipe all state from memory.
 */
export function panic_wipe(): void;

/**
 * Parse a QR bootstrap payload from hex-encoded CBOR bytes.
 */
export function parse_qr_payload(hex_data: string): any;

/**
 * Receive a chunk for an incoming file transfer. Returns true if this was the last chunk.
 */
export function receive_chunk(file_id_hex: string, chunk_index: number, data: Uint8Array, is_last: boolean): boolean;

/**
 * Register an incoming file transfer from a received offer.
 */
export function receive_file_offer(file_id_hex: string, file_name: string, file_size: bigint, chunk_size: number, sha256_hex: string): void;

/**
 * Reject an incoming call.
 */
export function reject_call(call_id_hex: string): void;

/**
 * Send an encrypted message within an established session.
 *
 * Returns a JS object `{ header_json, ciphertext_hex }`.
 */
export function send_message(peer_id_hex: string, plaintext: string): any;

/**
 * Get the number of active sessions.
 */
export function session_count(): number;

/**
 * Set an unlock code. The code is SHA-256 hashed before storage.
 */
export function set_unlock_code(code: string): void;

/**
 * Start an outgoing call to a peer. Returns the call_id as hex.
 */
export function start_call(peer_id_hex: string): string;

/**
 * Verify an unlock code using constant-time comparison.
 */
export function verify_unlock_code(code: string): boolean;

/**
 * Get the ParolNet version.
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly answer_call: (a: number, b: number, c: number) => void;
    readonly assemble_file: (a: number, b: number, c: number) => void;
    readonly compute_sas: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
    readonly create_file_transfer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly create_session: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly decrypt_message: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly encrypt_message: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly generate_identity: (a: number) => void;
    readonly generate_keypair: () => number;
    readonly generate_qr_payload: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly get_call_state: (a: number, b: number, c: number) => void;
    readonly get_file_offer: (a: number, b: number, c: number) => void;
    readonly get_next_chunk: (a: number, b: number, c: number) => void;
    readonly hangup_call: (a: number, b: number, c: number) => void;
    readonly has_session: (a: number, b: number) => number;
    readonly init: () => void;
    readonly initialize: (a: number) => void;
    readonly is_decoy_enabled: () => number;
    readonly panic_wipe: () => void;
    readonly parse_qr_payload: (a: number, b: number, c: number) => void;
    readonly receive_chunk: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly receive_file_offer: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number, i: number) => void;
    readonly reject_call: (a: number, b: number, c: number) => void;
    readonly send_message: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly set_unlock_code: (a: number, b: number, c: number) => void;
    readonly start_call: (a: number, b: number, c: number) => void;
    readonly verify_unlock_code: (a: number, b: number) => number;
    readonly version: (a: number) => void;
    readonly enter_decoy_mode: () => void;
    readonly session_count: () => number;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
