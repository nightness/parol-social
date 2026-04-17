# PNP-007: ParolNet Media and File Transfer Protocol

### Status: CANDIDATE
### Version: 0.2
### Date: 2026-04-17

---

## Changelog

**v0.2 (2026-04-17) — Harmonization pass**

- Status bumped from DRAFT to CANDIDATE.
- Confirmed `MediaSource` field naming (§6.7.1) is distinct from the PNP-006 dummy/real flag (§4.3.4). No naming conflict — the two fields are in different specs and different payload layers. Added a clarifying note in §6.7.1.
- Added clause IDs to every RFC 2119 statement (`PNP-007-MUST-NNN`, `-SHOULD-NNN`, `-MAY-NNN`).
- Cross-referenced message-type code allocation against PNP-001 §3.4 canonical registry (0x07–0x0B).
- Completed cross-reference table.

**v0.1 (2026-04-10)** — Initial draft.

---

## Implementation Note

This specification describes the media/file-transfer design target. Current code has core/WASM helpers for calls and file transfer, but the PWA UI does not yet send media or file traffic through production 3-hop onion circuits with MediaCall traffic shaping.

---

## 1. Overview

The ParolNet Media and File Transfer Protocol (PMFTP) extends ParolNet beyond text messaging to support real-time voice calls, video calls, and file transfer. All media and file data is routed through the existing 3-hop onion relay circuits (PNP-004), maintaining the same untrackable guarantees as text messaging. An observer -- whether a network intermediary, a compromised relay, or a state-level adversary performing DPI -- MUST NOT be able to distinguish voice, video, or file transfer traffic from ordinary text messaging or cover traffic. **PNP-007-MUST-001**

PMFTP introduces new message types for audio, video, file transfer, and call signaling, a new relay cell type optimized for low-latency media delivery, and a new traffic shaping bandwidth mode tailored to real-time media streams.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

- **RTP (Real-time Transport Protocol)**: A network protocol (RFC 3550) for delivering audio and video over IP networks, providing sequence numbering, timestamping, and payload type identification.
- **SRTP (Secure Real-time Transport Protocol)**: The encrypted profile of RTP (RFC 3711), providing confidentiality, message authentication, and replay protection for RTP streams.
- **SDP (Session Description Protocol)**: A format (RFC 8866) for describing multimedia session parameters including codecs, transport addresses, and media types.
- **Codec**: An algorithm that encodes and decodes audio or video data. Examples: Opus (audio), Codec2 (audio), VP8/VP9 (video).
- **Jitter Buffer**: A receive-side buffer that reorders and delays incoming packets to compensate for variable network delay (jitter), producing a smooth playout stream.
- **Keyframe (I-frame)**: A video frame that is independently decodable without reference to other frames. Required for stream initialization and error recovery.
- **P-frame**: A predictive video frame that encodes only differences from a preceding reference frame. Smaller than keyframes but cannot be decoded independently.
- **Chunk**: A fixed-size segment of a file being transferred. Each chunk is independently encrypted and transmitted.

## 3. Message Types

### 3.1 New Wire Protocol Message Types

The following message type codes are allocated by this specification as part of the canonical registry in PNP-001 §3.4:

| Code | Name | Description |
|------|------|-------------|
| 0x07 | AUDIO | Audio frame (SRTP-encrypted RTP packet) |
| 0x08 | VIDEO | Video frame or fragment (SRTP-encrypted RTP packet) |
| 0x09 | FILE_CHUNK | File transfer data chunk |
| 0x0A | FILE_CONTROL | File transfer control (offer, accept, reject, pause, resume, cancel) |
| 0x0B | CALL_SIGNAL | Call signaling (SDP offer/answer, reject, hangup, mute) |

These message types are carried in the `msg_type` field of the PNP-001 cleartext header. As with all message types, unrecognized codes MUST be treated as DECOY and silently discarded after decryption (PNP-001 §3.4 / PNP-001-MUST-008).

### 3.2 New Relay Cell Type

The following cell type extends the table in PNP-004 §3.2:

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| 0x09 | MEDIA_DATA | Bidirectional | Low-latency cell that bypasses burst smoothing |

MEDIA_DATA cells use the same 512-byte fixed cell format as DATA cells (PNP-004 §3.1) and are encrypted identically through onion layers. The distinction exists solely to inform the traffic shaping layer (§8) that this cell MUST be transmitted immediately rather than queued for burst smoothing. **PNP-007-MUST-002**

Relay nodes MUST forward MEDIA_DATA cells with the same processing as DATA cells (PNP-004 §5.5). **PNP-007-MUST-003** The cell type does NOT alter relay behavior except that relay-to-relay padding timers MUST NOT delay MEDIA_DATA cells. **PNP-007-MUST-004**

## 4. Call Signaling Protocol

### 4.1 Call Identifiers

Each call is identified by a **Call ID**: a cryptographically random 128-bit (16-byte) value generated by the call initiator. The Call ID MUST be unique across all active calls for a given peer pair. **PNP-007-MUST-005** Implementations MUST generate Call IDs using a cryptographically secure random source. **PNP-007-MUST-006**

### 4.2 Signaling Messages

Call signaling messages are carried as CALL_SIGNAL (0x0B) message types within PNP-001 envelopes, encrypted under the existing Double Ratchet session between the two peers. All signaling messages are CBOR-encoded maps with the following structures:

```
Offer = {
  "type"    : "offer",
  "call_id" : bstr(16),     -- Random 128-bit call identifier
  "sdp"     : tstr           -- SDP offer (codec capabilities, media types)
}

Answer = {
  "type"    : "answer",
  "call_id" : bstr(16),
  "sdp"     : tstr           -- SDP answer (selected codecs, media types)
}

Reject = {
  "type"    : "reject",
  "call_id" : bstr(16)
}

Hangup = {
  "type"    : "hangup",
  "call_id" : bstr(16)
}

Mute = {
  "type"    : "mute",
  "call_id" : bstr(16),
  "muted"   : bool           -- true = muted, false = unmuted
}
```

### 4.3 Call State Machine

```
                +------------------+
                |      IDLE        |
                +--------+---------+
                         |
                    Send Offer
                         |
                         v
                +--------+---------+
    +-----------|    OFFERING      |
    |           +--------+---------+
    |                    |
    |           Receive Answer
    |                    |
    |                    v
    |           +--------+---------+
    |           |    RINGING       |
    |           +--------+---------+
    |                    |
    |           Remote picks up
    |           (first media frame)
    |                    |
    |                    v
    |           +--------+---------+
    |           |     ACTIVE       |<----> Media flows
    |           +--------+---------+
    |                    |
    |             Hangup (local
    |             or remote)
    |                    |
    |                    v
    |           +--------+---------+
    +---------->|     ENDED        |
                +------------------+

Alternate transitions:
  OFFERING --[Receive Reject]--> ENDED
  OFFERING --[30s timeout]-----> TIMEOUT --> ENDED
  RINGING  --[Receive Reject]--> ENDED
  RINGING  --[30s timeout]-----> TIMEOUT --> ENDED
  ACTIVE   --[Receive Hangup]--> ENDED
  Any      --[Circuit DESTROY]-> ENDED
```

#### 4.3.1 State Descriptions

| State | Description |
|-------|-------------|
| IDLE | No active call. Ready to send or receive Offer. |
| OFFERING | Offer sent, awaiting Answer or Reject. |
| RINGING | Answer received (caller) or Offer received (callee). UI SHOULD present ring indication. |
| ACTIVE | Media is flowing. Both sides exchange audio/video frames. |
| ENDED | Call terminated. All call-related resources MUST be released. |

#### 4.3.2 Timeout Rules

1. If no Answer or Reject is received within 30 seconds of sending an Offer, the caller MUST transition to ENDED and SHOULD send a Hangup. **PNP-007-MUST-007**
2. If the callee does not act on a received Offer within 30 seconds, the callee MUST transition to ENDED. **PNP-007-MUST-008**
3. Implementations SHOULD display a missed-call notification when a call times out. **PNP-007-SHOULD-001**

#### 4.3.3 Callee State Machine

The callee follows a parallel state machine:

```
  IDLE --[Receive Offer]--> RINGING
  RINGING --[User accepts, send Answer]--> ACTIVE
  RINGING --[User rejects, send Reject]--> ENDED
  RINGING --[30s timeout]--> ENDED
  ACTIVE --[Send/Receive Hangup]--> ENDED
```

## 5. Audio Framing

### 5.1 RTP Packetization

Audio frames MUST be packetized per RFC 3550. **PNP-007-MUST-009** Each RTP packet carries exactly one codec frame. **PNP-007-MUST-010** The RTP header fields MUST be populated as follows:

```
RTP Header (12 bytes minimum):
  Offset  Length  Field
  ------  ------  -----
  0       1       V=2, P, X, CC (Version MUST be 2, CC MUST be 0)
  1       1       M, PT (Payload Type: 111 for Opus, 112 for Codec2)
  2       2       Sequence Number, big-endian uint16
  4       4       Timestamp, big-endian uint32 (sample clock)
  8       4       SSRC, big-endian uint32 (random, constant per call)
```

### 5.2 SRTP Encryption

1. Audio RTP packets MUST be encrypted using SRTP per RFC 3711. **PNP-007-MUST-011**
2. SRTP keying material MUST be derived from the existing Double Ratchet session state. **PNP-007-MUST-012** Specifically, both peers MUST derive SRTP master key and master salt from the current Double Ratchet root key using HKDF-SHA256 with info string `"pmftp-srtp-audio-v1"`:
   - Bytes 0-15: SRTP master key (128-bit, for AES-128-CM)
   - Bytes 16-29: SRTP master salt (112-bit)
3. The SRTP crypto suite MUST be AES_CM_128_HMAC_SHA1_80 (RFC 3711 §4). **PNP-007-MUST-013**
4. SRTP keys MUST be rederived whenever the Double Ratchet advances to a new root key. **PNP-007-MUST-014** Both peers MUST synchronize the transition using the RTP SSRC and sequence number.
5. Implementations MUST NOT use SDES key exchange or DTLS-SRTP. **PNP-007-MUST-015** Key material comes exclusively from the Double Ratchet.

### 5.3 Codec Negotiation

Codec selection is negotiated via SDP in the Offer/Answer exchange (§4.2). The following codecs MUST be supported:

| Priority | Codec | Standard | Sample Rate | Channels | Frame Duration | Frame Size |
|----------|-------|----------|-------------|----------|----------------|------------|
| Primary | Opus | RFC 6716 | 16 kHz | Mono | 20 ms | ~40-80 bytes |
| Fallback | Codec2 | 3200 bps mode | 8 kHz | Mono | 20 ms | 8 bytes |

1. Implementations MUST offer both codecs in the SDP Offer, with Opus listed first. **PNP-007-MUST-016**
2. The answerer MUST select the highest-priority mutually supported codec. **PNP-007-MUST-017**
3. **Codec2 selection rule**: Codec2 MUST be selected when the available circuit bandwidth is below 16 kbps. **PNP-007-MUST-018** This is typical in mesh/BLE relay scenarios where relay capacity is severely constrained.
4. Codec switching during an active call is NOT RECOMMENDED. If bandwidth conditions change significantly, the caller SHOULD renegotiate by sending a new Offer with updated SDP. **PNP-007-SHOULD-002**

### 5.4 Jitter Buffer

1. Implementations MUST maintain an adaptive jitter buffer on the receiving side. **PNP-007-MUST-019**
2. The buffer depth MUST be configurable between 50 ms and 200 ms. **PNP-007-MUST-020**
3. Initial buffer depth SHOULD be 100 ms and SHOULD adapt based on observed jitter. **PNP-007-SHOULD-003**
4. Packets MUST be reordered by RTP sequence number before playout. **PNP-007-MUST-021**
5. Packets arriving later than the current buffer depth MUST be dropped. **PNP-007-MUST-022**
6. If three or more consecutive packets are missing, the implementation SHOULD perform packet loss concealment (PLC) using the codec's built-in PLC mechanism (Opus provides native PLC). **PNP-007-SHOULD-004**

### 5.5 Silence Suppression

1. When the local microphone is muted, the sender MUST NOT stop transmitting. **PNP-007-MUST-023**
2. Instead, the sender MUST continue sending comfort noise frames at the same rate (one frame per 20 ms) and the same size as active audio frames. **PNP-007-MUST-024**
3. Comfort noise frames MUST be generated by encoding silence through the active codec, producing valid encoded frames that decode to near-silence. **PNP-007-MUST-025**
4. This ensures a constant traffic rate regardless of mute state, preventing an observer from inferring call activity by monitoring traffic volume.

## 6. Video Framing

### 6.1 RTP Packetization

Video frames MUST be packetized per RFC 3550 with fragmentation support for frames exceeding the relay cell payload capacity. **PNP-007-MUST-026**

```
RTP Header for Video:
  Same format as §5.1, with:
  - Payload Type: 96 for VP8, 97 for VP9
  - Marker bit (M): set to 1 on the last RTP packet of a video frame
  - Timestamp: 90 kHz clock (standard for video RTP)
```

### 6.2 Codec Selection

1. Video encoding and decoding MUST be performed by the browser's WebCodecs API, not in Rust. **PNP-007-MUST-027**
2. The Rust/WASM layer handles packetization, SRTP encryption, and relay circuit transport.
3. Supported codecs, negotiated via SDP:
   - **VP8**: MUST be supported (baseline compatibility). **PNP-007-MUST-028**
   - **VP9**: SHOULD be supported (better compression). **PNP-007-SHOULD-005**

### 6.3 Encoding Parameters

| Parameter | Low Mode | Normal Mode |
|-----------|----------|-------------|
| Resolution | 320x240 | 640x480 |
| Frame Rate | 15 fps | 30 fps |
| Bitrate | 100-200 kbps | 200-500 kbps |
| Keyframe Interval | Every 2 s (30 frames at 15fps) | Every 2 s (60 frames at 30fps) |

1. Mode selection MUST be adaptive based on measured circuit bandwidth. **PNP-007-MUST-029**
2. If available bandwidth drops below 150 kbps, the encoder MUST switch to Low Mode. **PNP-007-MUST-030**
3. If available bandwidth exceeds 300 kbps, the encoder MAY switch to Normal Mode. **PNP-007-MAY-001**
4. Hysteresis of 50 kbps MUST be applied to prevent rapid mode oscillation. **PNP-007-MUST-031**

### 6.4 Frame Fragmentation

Video frames frequently exceed the relay cell payload capacity (457 bytes after 3-hop onion encryption, per PNP-004 §5.2.4). Large frames MUST be fragmented into multiple RTP packets, each fitting within the cell payload. **PNP-007-MUST-032**

```
Maximum RTP payload per cell:
  Cell payload capacity:           457 bytes  (PNP-004)
  - RTP header:                     12 bytes
  - SRTP auth tag:                  10 bytes
  = Maximum RTP payload:           435 bytes

Frame fragmentation:
  +--------------------------------------------------+
  | Video Frame (e.g., keyframe, 15000 bytes)         |
  +--------------------------------------------------+
         |              |              |         |
         v              v              v         v
  +----------+   +----------+   +----------+  +------+
  | RTP pkt  |   | RTP pkt  |   | RTP pkt  |  | RTP  |
  | 435 B    |   | 435 B    |   | 435 B    |  | last |
  | M=0      |   | M=0      |   | M=0      |  | M=1  |
  +----------+   +----------+   +----------+  +------+
```

1. Each RTP packet MUST fit within a single relay cell. An RTP packet MUST NOT span multiple cells. **PNP-007-MUST-033**
2. The RTP marker bit (M) MUST be set to 1 on the last packet of a frame and 0 on all preceding packets. **PNP-007-MUST-034**
3. Implementations MUST use codec-specific packetization modes (e.g., VP8 payload descriptor per RFC 7741) to enable independent decodability of each packet where possible. **PNP-007-MUST-035**

### 6.5 Loss Resilience

1. The receiver MUST track packet loss by monitoring RTP sequence number gaps. **PNP-007-MUST-036**
2. If packet loss exceeds 5% over any 2-second window, the receiver MUST request a keyframe by sending a CALL_SIGNAL message: **PNP-007-MUST-037**

```
KeyframeRequest = {
  "type"       : "keyframe_req",
  "call_id"    : bstr(16),
  "ssrc"       : uint32          -- SSRC of the video stream
}
```

3. Upon receiving a keyframe request, the sender MUST encode and send a keyframe within 500 ms. **PNP-007-MUST-038**
4. If a keyframe is lost (detected by missing the start of a keyframe), the receiver MUST request another immediately. **PNP-007-MUST-039**

### 6.6 SRTP for Video

1. Video SRTP keying follows the same mechanism as audio (§5.2) but with a distinct HKDF info string: `"pmftp-srtp-video-v1"`.
2. Audio and video streams MUST use separate SRTP contexts with independent key material, sequence counters, and rollover counters. **PNP-007-MUST-040**
3. SSRC values for audio and video MUST be distinct within the same call. **PNP-007-MUST-041**

### 6.7 Screen Sharing

#### 6.7.1 Media Source Identifier

Each video frame carries a `MediaSource` field inside the encrypted payload that identifies the capture source:

```
MediaSource = uint8
  0x00 = Camera     -- Default, webcam capture
  0x01 = Screen     -- Screen/window/tab capture
```

The `MediaSource` field is part of the encrypted payload content and MUST NOT appear in the cleartext header. **PNP-007-MUST-042** Relay nodes MUST NOT be able to distinguish screen share traffic from camera video traffic. **PNP-007-MUST-043** Screen share frames use the same `VIDEO` (0x08) message type as camera frames.

**Note on naming**: `MediaSource` (camera vs screen) is a distinct field from the PNP-006 §4.3.4 decoy flag (dummy vs real). Both are first-byte flags inside encrypted payloads but they encode orthogonal properties and live in different specs.

#### 6.7.2 One Video Stream Per User

A participant MUST NOT send camera video and screen share video simultaneously. **PNP-007-MUST-044** When screen sharing begins, camera video MUST be paused. **PNP-007-MUST-045** When screen sharing ends, camera video MUST resume. **PNP-007-MUST-046** This constraint ensures:

1. Traffic volume remains within MediaCall mode bandwidth limits (§8).
2. No additional SRTP context is needed -- screen share reuses the video SRTP context (`"pmftp-srtp-video-v1"`, §6.6).
3. The traffic profile remains indistinguishable from a camera-only call.

#### 6.7.3 Encoding Parameters

| Parameter | Low Mode | Normal Mode |
|-----------|----------|-------------|
| Resolution | 960x540 | 1280x720 |
| Frame Rate | 5 fps | 15 fps |
| Bitrate | 300-500 kbps | 500-1500 kbps |
| Keyframe Interval | Every 3 s (15 frames at 5fps) | Every 3 s (45 frames at 15fps) |
| Preferred Codec | VP9 | VP9 |

1. VP9 is preferred for screen share content because it handles sharp edges and text better than VP8.
2. Mode selection MUST be adaptive based on measured circuit bandwidth, following the same hysteresis rules as camera video (§6.3). **PNP-007-MUST-047**
3. If available bandwidth drops below 300 kbps, the encoder MUST switch to Low Mode. **PNP-007-MUST-048**
4. If available bandwidth exceeds 600 kbps, the encoder MAY switch to Normal Mode. **PNP-007-MAY-002**

#### 6.7.4 Signaling

Screen share start and stop are signaled via CALL_SIGNAL (0x0B) messages:

```
ScreenShareStart = {
  "type"    : "screen_share_start",
  "call_id" : bstr(16),
  "config"  : VideoConfig          -- Encoding parameters for the screen share stream
}

ScreenShareStop = {
  "type"    : "screen_share_stop",
  "call_id" : bstr(16)
}
```

1. `ScreenShareStart` MUST only be sent when the call is in ACTIVE state. **PNP-007-MUST-049**
2. Upon receiving `ScreenShareStart`, the receiver MUST prepare to render incoming video frames as screen share content (typically in a larger viewport). **PNP-007-MUST-050**
3. Upon receiving `ScreenShareStop`, the receiver MUST expect subsequent video frames to be camera video. **PNP-007-MUST-051**
4. If the screen capture source is terminated by the operating system or browser (e.g., the user clicks the browser's "Stop sharing" button), the sender MUST send `ScreenShareStop` and resume camera video. **PNP-007-MUST-052**

#### 6.7.5 SRTP

Screen share frames reuse the video SRTP context established with HKDF info string `"pmftp-srtp-video-v1"` (§6.6). Since only one video stream is active at a time (§6.7.2), the SSRC and sequence number space are shared between camera and screen share. When switching sources, the SRTP sequence counter continues incrementing without reset. **PNP-007-MUST-053**

## 7. File Transfer Protocol

### 7.1 File Offer

A file transfer begins when the sender transmits a FILE_CONTROL (0x0A) message containing a FileOffer:

```
FileOffer = {
  "type"       : "offer",
  "file_id"    : bstr(16),       -- Random 128-bit file transfer identifier
  "file_name"  : tstr,           -- Original file name (UTF-8)
  "file_size"  : uint64,         -- Total file size in bytes
  "chunk_size" : uint32,         -- Chunk size in bytes (default 4096)
  "sha256"     : bstr(32),       -- SHA-256 hash of the complete file
  "mime_type"  : tstr            -- MIME type (e.g., "image/png", "application/pdf")
}
```

1. The `file_id` MUST be cryptographically random and unique per transfer. **PNP-007-MUST-054**
2. The `chunk_size` MUST default to 4096 bytes. **PNP-007-MUST-055** This value is chosen to fit within the 4096-byte PNP-001 envelope bucket size.
3. The `file_size` is a uint64, imposing no protocol-level limit on file size.
4. The `sha256` hash MUST be computed over the plaintext file content before any chunking or encryption. **PNP-007-MUST-056**

### 7.2 File Control Messages

After a FileOffer, the receiver responds with a FILE_CONTROL message. All control messages share the file_id:

```
FileAccept = {
  "type"    : "accept",
  "file_id" : bstr(16)
}

FileReject = {
  "type"    : "reject",
  "file_id" : bstr(16)
}

FileCancel = {
  "type"    : "cancel",
  "file_id" : bstr(16)
}

FilePause = {
  "type"    : "pause",
  "file_id" : bstr(16)
}

FileResume = {
  "type"    : "resume",
  "file_id" : bstr(16),
  "resume_from" : uint64         -- Chunk index to resume from
}
```

### 7.3 File Chunks

After receiving FileAccept, the sender transmits the file as a sequence of FILE_CHUNK (0x09) messages:

```
FileChunk = {
  "file_id"     : bstr(16),
  "chunk_index" : uint64,        -- Zero-based chunk index
  "chunk_data"  : bstr,          -- Chunk payload (up to chunk_size bytes)
  "is_last"     : bool           -- true if this is the final chunk
}
```

### 7.4 Encryption

1. Each file chunk MUST be encrypted individually using the session's Double Ratchet. **PNP-007-MUST-057**
2. The Double Ratchet MUST advance for each chunk, providing forward secrecy per chunk: compromise of the key material for one chunk MUST NOT reveal the contents of any other chunk. **PNP-007-MUST-058**
3. The chunk is placed in the `body` field of the PNP-001 encrypted payload (§3.3 of PNP-001) and encrypted as part of the standard envelope processing.

### 7.5 Integrity Verification

1. Upon receiving the final chunk (`is_last` = true), the receiver MUST reconstruct the complete file and compute its SHA-256 hash. **PNP-007-MUST-059**
2. The computed hash MUST be compared with the `sha256` value from the FileOffer. **PNP-007-MUST-060**
3. If the hashes do not match, the receiver MUST discard the file **PNP-007-MUST-061** and SHOULD notify the user of a transfer integrity failure. **PNP-007-SHOULD-006**
4. Hash comparison MUST use constant-time comparison (the `subtle` crate) to prevent timing side channels. **PNP-007-MUST-062**

### 7.6 Resume

1. If a transfer is interrupted (circuit destroyed, peer disconnected), the receiver MAY send a FileResume with `resume_from` set to the index of the last successfully received and verified chunk plus one. **PNP-007-MAY-003**
2. The sender MUST skip all chunks with index less than `resume_from` and continue transmitting from the specified index. **PNP-007-MUST-063**
3. Implementations MUST retain partial file state and the original FileOffer metadata to support resume across session reconnections. **PNP-007-MUST-064**
4. If the original Double Ratchet session is lost, resume is not possible; the transfer MUST restart from the beginning. **PNP-007-MUST-065**

### 7.7 Progress Tracking

1. Progress MUST be computed as: `progress = chunk_index / ceil(file_size / chunk_size)`. **PNP-007-MUST-066**
2. Implementations SHOULD provide progress indication to the user. **PNP-007-SHOULD-007**
3. The sender SHOULD pace chunk transmission to avoid overwhelming the relay circuit. A sending rate of one chunk per padding interval (matching the active bandwidth mode) is RECOMMENDED. **PNP-007-SHOULD-008**

## 8. Traffic Shaping for Media (MediaCall Mode)

### 8.1 New Bandwidth Mode

PMFTP introduces a new bandwidth mode extending PNP-006 §3:

| Mode | Padding Interval | Dummy Traffic % | Max Bandwidth | Use Case |
|------|-------------------|-----------------|---------------|----------|
| MEDIA_CALL | 20 ms | 0% | ~400 KB/s active | Active voice/video call |

### 8.2 Activation Rules

1. MediaCall mode MUST be activated on the circuit when a call transitions to ACTIVE state (§4.3). **PNP-007-MUST-067**
2. MediaCall mode MUST be deactivated when a call transitions to ENDED state. **PNP-007-MUST-068**
3. Only the circuit carrying the active call MUST switch to MediaCall mode. Other circuits on the same node MUST remain in their current bandwidth mode. **PNP-007-MUST-069**
4. A node MUST NOT have more than one circuit in MediaCall mode simultaneously. If a second call is attempted, it MUST be rejected. **PNP-007-MUST-070**

### 8.3 Timing Behavior

1. **Padding interval**: 20 ms, matching the Opus codec frame rate (50 frames/second). **PNP-007-MUST-071**
2. **No burst smoothing**: MEDIA_DATA cells (§3.2) MUST be transmitted immediately upon availability. **PNP-007-MUST-072** The burst smoothing rules of PNP-006 §4.2 MUST NOT apply to MEDIA_DATA cells. **PNP-007-MUST-073**
3. **Padding size**: When no real media frame is available at a 20 ms tick, a PADDING cell MUST be sent. **PNP-007-MUST-074** The padding cell payload MUST be sized to match a typical audio frame (~80 bytes of meaningful payload within the 505-byte cell payload, with the remainder being random padding as usual per PNP-004 §3.9). **PNP-007-MUST-075**
4. **Jitter**: Timing jitter for MediaCall mode MUST be drawn from a uniform distribution over [0, 5 ms]. **PNP-007-MUST-076** Larger jitter would degrade call quality.

### 8.4 Mute Behavior

1. During mute, the sender MUST continue sending at the same 20 ms rate. **PNP-007-MUST-077**
2. Muted frames MUST be comfort noise encoded through the active codec (§5.5), encrypted with SRTP, and transmitted as AUDIO messages. **PNP-007-MUST-078**
3. An observer MUST NOT be able to distinguish active speech from muted silence by traffic volume or timing. **PNP-007-MUST-079**

### 8.5 DPI Profile

1. During MediaCall mode, the traffic profile MUST resemble a streaming video site (e.g., YouTube, Netflix): a long-lived connection with steady bitrate and occasional bursts for video keyframes. **PNP-007-MUST-080**
2. The steady-state bitrate SHOULD be approximately 50-80 kbps for audio-only calls and 150-500 kbps for audio+video calls. **PNP-007-SHOULD-009**
3. Keyframe bursts (multiple cells in rapid succession) SHOULD occur at regular intervals matching the keyframe interval (every 2 seconds), mimicking adaptive bitrate streaming segment boundaries. **PNP-007-SHOULD-010**

### 8.6 Post-Hangup Padding

After a call ends (Hangup sent or received), the circuit MUST NOT immediately drop to normal-mode traffic volume. **PNP-007-MUST-081** Instead:

1. The node MUST continue sending padding at the MediaCall rate (20 ms interval) for a random duration between 5 and 30 seconds. **PNP-007-MUST-082**
2. The duration MUST be drawn from a uniform distribution using a cryptographically secure random source. **PNP-007-MUST-083**
3. After the post-hangup padding period, the circuit MUST transition to the node's standard bandwidth mode (LOW, NORMAL, or HIGH per PNP-006). **PNP-007-MUST-084**
4. This prevents an observer from precisely determining when a call ended.

## 9. Security Considerations

1. **End-to-end media encryption**: All audio and video frames are encrypted with SRTP, keyed from the Double Ratchet session. No relay in the 3-hop circuit can decrypt media content. The SRTP key derivation is bound to the Double Ratchet state, inheriting its forward secrecy and post-compromise security properties.

2. **No cleartext codec metadata**: The codec type, resolution, frame rate, and all media parameters are carried inside the PNP-001 encrypted envelope. Relay nodes see only encrypted cells of fixed size and MUST NOT be able to determine whether a cell carries audio, video, file data, or text. **PNP-007-MUST-085**

3. **Call duration obfuscation**: Post-hangup padding (§8.6) prevents an observer from determining the exact moment a call ends. Combined with constant-rate padding during the call, the observable traffic pattern reveals only that a long-lived media session existed, not its precise start or end time.

4. **File transfer forward secrecy**: Each file chunk is encrypted with an independently advanced Double Ratchet state. Compromise of the key material for chunk N does not reveal the contents of chunks 0 through N-1 (forward secrecy) or chunks N+1 onward (provided the ratchet advances).

5. **Video keyframe size distinguishability**: Video keyframes (I-frames) are significantly larger than P-frames (typically 10-50x). Even though the content is encrypted, the burst of cells required for a keyframe is observable. Mitigations:
   - In NORMAL security mode, keyframes are sent as-is (acceptable trade-off for usability).
   - In HIGH security mode, implementations SHOULD pad all inter-keyframe intervals to a constant cell count matching the worst-case keyframe size. **PNP-007-SHOULD-011** This consumes more bandwidth but prevents frame-type inference.

6. **Codec fingerprinting**: Different codecs produce characteristic frame size distributions. Opus frames at 16 kHz mono are typically 40-80 bytes; Codec2 at 3200 bps is exactly 8 bytes. To prevent codec identification by frame size, all audio frames MUST be padded to the same size before SRTP encryption. **PNP-007-MUST-086** The padding size SHOULD be 80 bytes (the upper bound of typical Opus frame sizes). **PNP-007-SHOULD-012**

7. **SRTP replay protection**: SRTP provides native replay protection via the ROC (Rollover Counter) and sequence number. Implementations MUST enable SRTP replay protection **PNP-007-MUST-087** and MUST maintain the replay window per RFC 3711 §3.3.2. **PNP-007-MUST-088**

8. **Screen share indistinguishability**: Screen share frames use the same `VIDEO` (0x08) message type and the same SRTP context as camera video (§6.7). The `MediaSource` field is carried inside the encrypted payload. Relay nodes and network observers MUST NOT be able to determine whether a participant is sharing their screen or transmitting camera video. **PNP-007-MUST-089** The one-stream-per-user rule (§6.7.2) ensures that screen sharing does not alter the observable traffic volume profile.

## 10. Privacy Considerations

1. **No server-side call logs**: All calls are peer-to-peer through relay circuits. No central server records call participants, duration, or frequency. Relay nodes forward encrypted cells without knowledge of call semantics.

2. **Call metadata protection**: Call duration and frequency are protected by the combination of constant-rate MediaCall padding (§8.3) and post-hangup padding (§8.6). An observer can detect that a media session exists on a circuit but cannot determine how many calls occurred within it or their individual durations.

3. **File metadata confidentiality**: File names, sizes, MIME types, and SHA-256 hashes are carried inside encrypted PNP-001 envelopes. Relay nodes see only encrypted cells and cannot determine whether a transfer is in progress, what is being transferred, or how large the file is.

4. **Codec negotiation privacy**: SDP offer/answer messages are carried as encrypted CALL_SIGNAL messages within the Double Ratchet session. Relay nodes cannot determine whether a call uses audio, video, or both, nor which codecs are in use.

5. **Relay-level indistinguishability**: From a relay's perspective, MEDIA_DATA cells are processed identically to DATA cells (same size, same encryption, same forwarding logic). The cell type distinction (0x09 vs 0x05) is visible only within the encrypted onion layers and is acted upon only by the circuit endpoints.

6. **Contact pattern masking**: Because MediaCall mode maintains constant-rate traffic and post-hangup padding smooths transitions, an observer monitoring a relay node cannot distinguish between a user making multiple short calls and a user on a single long call. The traffic pattern is intentionally uniform.

## 11. Cross-Protocol References

| Spec | Relationship |
|------|-------------|
| PNP-001 (Wire Protocol) | AUDIO (0x07), VIDEO (0x08), FILE_CHUNK (0x09), FILE_CONTROL (0x0A), CALL_SIGNAL (0x0B) message types are allocated by this spec and registered in PNP-001 §3.4. All media and file data is carried in standard PNP-001 envelopes with bucket padding. |
| PNP-002 (Handshake) | Double Ratchet session state established via PNP-002 provides the keying material for SRTP (§§5.2, 6.6) and per-chunk file encryption (§7.4). |
| PNP-004 (Relay Circuit) | Media flows through 3-hop circuits. MEDIA_DATA (0x09) extends PNP-004 §3.2. Maximum per-cell payload of 457 bytes (PNP-004 §5.2.4) governs RTP packet sizing (§§5.1, 6.4). |
| PNP-006 (Traffic Shaping) | MediaCall bandwidth mode (§8) extends PNP-006 §3. MediaCall overrides burst smoothing (PNP-006 §4.2) for MEDIA_DATA cells. |
| PNP-009 (Group Communication) | Group calls and group file transfers reuse the audio/video framing and file-transfer mechanisms defined here, with sender-key encryption instead of pairwise Double Ratchet. |
