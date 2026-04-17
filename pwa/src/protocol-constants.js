// ParolNet PWA — Protocol message-type constants (PNP-001 §3.4)
//
// Codes MUST match the canonical registry in specs/PNP-001-wire-protocol.md §3.4.
// Do not invent values here — add to the spec first, then mirror into this file.

// ── PNP-001 core ──────────────────────────────────────────────
// 0x01 TEXT — user text / structured JSON payloads.
export const MSG_TYPE_CHAT = 0x01;
// 0x02 FILE — file transfer payload or fragment.
export const MSG_TYPE_FILE = 0x02;
// 0x03 CONTROL — session control (acks, typing, read receipts, bootstrap).
export const MSG_TYPE_SYSTEM = 0x03;
// 0x04 DECOY — cover traffic.
export const MSG_TYPE_DECOY = 0x04;
// 0x05 HANDSHAKE — PNP-002 session establishment messages.
export const MSG_TYPE_HANDSHAKE = 0x05;
// 0x06 RELAY_CONTROL — relay-layer signaling.
export const MSG_TYPE_RELAY_CONTROL = 0x06;

// ── PNP-007 media & file ──────────────────────────────────────
// 0x07 AUDIO — audio stream frame.
export const MSG_TYPE_AUDIO = 0x07;
// 0x08 VIDEO — video stream frame.
export const MSG_TYPE_VIDEO = 0x08;
// 0x09 FILE_CHUNK — file transfer chunk (PNP-007 §5).
export const MSG_TYPE_FILE_CHUNK = 0x09;
// 0x0A FILE_CONTROL — file transfer control signaling (offer/accept/reject).
export const MSG_TYPE_FILE_CONTROL = 0x0A;
// 0x0B CALL_SIGNAL — call state-machine signaling (offer/accept/reject/end).
export const MSG_TYPE_CALL_SIGNAL = 0x0B;

// ── PNP-009 group communication ───────────────────────────────
// 0x0C GROUP_TEXT — group text message (sender-key encrypted).
export const MSG_TYPE_GROUP_TEXT = 0x0C;
// 0x0D GROUP_CALL_SIGNAL — group call state-machine signaling.
export const MSG_TYPE_GROUP_CALL_SIGNAL = 0x0D;
// 0x0E GROUP_FILE_OFFER — group file offer.
export const MSG_TYPE_GROUP_FILE_OFFER = 0x0E;
// 0x0F GROUP_FILE_CHUNK — group file transfer chunk.
export const MSG_TYPE_GROUP_FILE_CHUNK = 0x0F;
// 0x10 GROUP_FILE_CONTROL — group file control signaling.
export const MSG_TYPE_GROUP_FILE_CONTROL = 0x10;
// 0x11 SENDER_KEY_DISTRIBUTION — sender key distribution.
export const MSG_TYPE_SENDER_KEY_DISTRIBUTION = 0x11;
// 0x12 GROUP_ADMIN — group admin operation (invite, member add/remove).
export const MSG_TYPE_GROUP_ADMIN = 0x12;

// ── PNP-002 §8 identity rotation (H5) ─────────────────────────
// 0x13 IDENTITY_ROTATE — signed identity rotation notification.
export const MSG_TYPE_IDENTITY_ROTATE = 0x13;

// All message-type codes in PNP-001 §3.4 (registry mirror — tests enumerate this).
export const ALL_MSG_TYPES = Object.freeze({
    TEXT:                    MSG_TYPE_CHAT,
    FILE:                    MSG_TYPE_FILE,
    CONTROL:                 MSG_TYPE_SYSTEM,
    DECOY:                   MSG_TYPE_DECOY,
    HANDSHAKE:               MSG_TYPE_HANDSHAKE,
    RELAY_CONTROL:           MSG_TYPE_RELAY_CONTROL,
    AUDIO:                   MSG_TYPE_AUDIO,
    VIDEO:                   MSG_TYPE_VIDEO,
    FILE_CHUNK:              MSG_TYPE_FILE_CHUNK,
    FILE_CONTROL:            MSG_TYPE_FILE_CONTROL,
    CALL_SIGNAL:             MSG_TYPE_CALL_SIGNAL,
    GROUP_TEXT:              MSG_TYPE_GROUP_TEXT,
    GROUP_CALL_SIGNAL:       MSG_TYPE_GROUP_CALL_SIGNAL,
    GROUP_FILE_OFFER:        MSG_TYPE_GROUP_FILE_OFFER,
    GROUP_FILE_CHUNK:        MSG_TYPE_GROUP_FILE_CHUNK,
    GROUP_FILE_CONTROL:      MSG_TYPE_GROUP_FILE_CONTROL,
    SENDER_KEY_DISTRIBUTION: MSG_TYPE_SENDER_KEY_DISTRIBUTION,
    GROUP_ADMIN:             MSG_TYPE_GROUP_ADMIN,
    IDENTITY_ROTATE:         MSG_TYPE_IDENTITY_ROTATE,
});
