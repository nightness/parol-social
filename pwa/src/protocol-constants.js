// ParolNet PWA — Protocol message-type constants (PNP-001 §3.4)
//
// Codes MUST match the canonical registry in specs/PNP-001-wire-protocol.md §3.4.
// Do not invent values here — add to the spec first, then mirror into this file.

// Normal user chat (text, JSON-wrapped structured messages that are carried as
// application-layer payload bytes). PNP-001 §3.4 code 0x01 "TEXT".
export const MSG_TYPE_CHAT = 0x01;

// Session control / bootstrap handshake payloads (e.g. the responder-side
// identity-key message that used to be transmitted as the "__system:bootstrap:"
// string marker). PNP-001 §3.4 code 0x03 "CONTROL".
export const MSG_TYPE_SYSTEM = 0x03;

// File-transfer chunks carried inside an envelope (see PNP-007 §5 for the
// wrapped chunk semantics). PNP-001 §3.4 code 0x09 "FILE_CHUNK".
export const MSG_TYPE_FILE_CHUNK = 0x09;
