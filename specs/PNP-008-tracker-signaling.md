# PNP-008: Tracker-Based Peer Signaling

### Status: DRAFT
### Version: 0.1
### Date: 2026-04-11

---

## 1. Overview

PNP-008 defines how ParolNet peers discover and establish WebRTC data channel connections through existing WebTorrent tracker infrastructure. Trackers serve as untrusted signaling relays: they see only opaque info_hashes and WebRTC SDP blobs. No ParolNet-specific metadata is exposed to tracker operators.

This mechanism is the primary peer discovery path for the PWA. Relay-based connections (PNP-004) serve as a fallback when direct WebRTC connectivity is unavailable.

## 2. Terminology

- **Tracker**: A WebTorrent tracker server that facilitates WebRTC signaling between peers sharing a common info_hash. Communication uses WebSocket transport and the [BitTorrent Tracker Protocol (BEP 15)](https://www.bittorrent.org/beps/bep_0015.html) extended for WebRTC.
- **info_hash**: A 20-byte identifier that groups peers into a swarm. Peers announcing the same info_hash can exchange WebRTC offers and answers through the tracker.
- **Announce**: A JSON message sent to a tracker declaring interest in an info_hash and optionally carrying WebRTC offers.
- **Offer**: A WebRTC SDP offer wrapped in the tracker announce protocol, forwarded by the tracker to another peer in the same swarm.
- **Answer**: A WebRTC SDP answer sent in response to a received offer, routed back through the tracker.
- **Mesh Hash**: The info_hash used for general ParolNet peer discovery. All ParolNet peers share this hash.
- **Contact Hash**: A pairwise info_hash derived from a shared secret, used for targeted peer discovery between two contacts.
- **Tracker PeerId**: A 20-byte identifier used within the tracker protocol. Derived from the ParolNet PeerId by truncation.
- **ParolNet PeerId**: A 32-byte identifier defined as `SHA-256(Ed25519_public_key)`. The canonical identity within ParolNet.

## 3. Info Hash Derivation

### 3.1 Mesh Discovery Hash

The mesh discovery hash is a well-known info_hash shared by all ParolNet peers:

```
mesh_info_hash = SHA-1("parolnet-mesh-v1")
             = 0x<20 bytes>
```

Any ParolNet peer announcing this hash will be introduced to other ParolNet peers by the tracker. This hash is public and reveals that a peer is using ParolNet, which is an acceptable tradeoff for mesh formation.

### 3.2 Contact-Specific Hash

When two peers share a bootstrap secret (exchanged via QR code or other out-of-band mechanism), they derive a contact-specific info_hash:

```
contact_info_hash = SHA-1(bootstrap_secret || "parolnet-contact")
```

where `||` denotes byte concatenation and `bootstrap_secret` is the raw bytes of the shared secret. Only the two parties possessing the bootstrap secret can compute this hash. The tracker learns nothing about the relationship between the peers.

### 3.3 Tracker PeerId

The tracker protocol requires a 20-byte peer identifier. ParolNet derives this by truncation:

```
tracker_peer_id = ParolNet_PeerId[0..20]
```

That is, the first 20 bytes of the 32-byte SHA-256 hash of the Ed25519 public key. After a WebRTC data channel is established, peers perform an identity exchange (Section 6) to verify the full 32-byte PeerId.

## 4. Tracker Connection

### 4.1 Default Tracker List

Implementations MUST ship with at least the following default trackers:

```
wss://tracker.openwebtorrent.com
wss://tracker.webtorrent.dev
wss://tracker.btorrent.xyz
wss://tracker.fastcast.nz
```

Implementations MAY allow users to add or remove trackers.

### 4.2 WebSocket Handshake

The tracker WebSocket connection uses the subprotocol identifier as expected by the WebTorrent tracker protocol. No additional authentication or custom headers are sent; the connection is indistinguishable from a normal WebTorrent client.

### 4.3 Reconnection

When a tracker WebSocket connection is lost, the client MUST attempt to reconnect with exponential backoff:

```
delay = min(base * 2^attempt, cap)
```

Where:
- `base` = 1000 ms
- `cap` = 60000 ms (60 seconds)
- `attempt` starts at 0 and increments on each consecutive failure

On successful reconnection, the attempt counter resets to 0 and the client MUST immediately re-announce all active info_hashes.

## 5. Announce Protocol

### 5.1 Outbound Announce (with Offers)

The client generates N WebRTC peer connections (default N=5, configurable via `numwant`), gathers ICE candidates to completion on each, then sends:

```json
{
  "action": "announce",
  "info_hash": "<20-byte hex info_hash>",
  "peer_id": "<20-byte hex tracker peer_id>",
  "event": "started",
  "numwant": 5,
  "offers": [
    {
      "offer_id": "<20-byte hex random>",
      "offer": {
        "type": "offer",
        "sdp": "<full SDP with ICE candidates>"
      }
    }
  ]
}
```

ICE candidates MUST be fully gathered before the offer is sent. Trickle ICE is NOT used because the tracker protocol has no mechanism for incremental candidate exchange.

The `event` field MUST be `"started"` on the first announce after connecting to a tracker. Subsequent periodic announces SHOULD omit the `event` field or set it to `"update"`.

### 5.2 Inbound Offer

When the tracker forwards another peer's offer, the client receives:

```json
{
  "action": "announce",
  "info_hash": "<20-byte hex info_hash>",
  "peer_id": "<20-byte hex of offering peer>",
  "offer_id": "<20-byte hex>",
  "offer": {
    "type": "offer",
    "sdp": "<SDP>"
  }
}
```

The client MUST:
1. Create a new `RTCPeerConnection`.
2. Set the received SDP as the remote description.
3. Create an answer.
4. Wait for ICE gathering to complete.
5. Send the answer back through the tracker (Section 5.3).

### 5.3 Outbound Answer

```json
{
  "action": "announce",
  "info_hash": "<20-byte hex info_hash>",
  "peer_id": "<20-byte hex of answering peer (self)>",
  "to_peer_id": "<20-byte hex of offering peer>",
  "offer_id": "<20-byte hex>",
  "answer": {
    "type": "answer",
    "sdp": "<full SDP with ICE candidates>"
  }
}
```

### 5.4 Inbound Answer

When the tracker routes an answer back to the offering peer:

```json
{
  "action": "announce",
  "info_hash": "<20-byte hex info_hash>",
  "peer_id": "<20-byte hex of answering peer>",
  "offer_id": "<20-byte hex>",
  "answer": {
    "type": "answer",
    "sdp": "<SDP>"
  }
}
```

The client MUST:
1. Look up the pending `RTCPeerConnection` by `offer_id`.
2. Set the received SDP as the remote description.
3. If no pending connection exists for the `offer_id`, silently discard the message.

## 6. Identity Exchange

After a WebRTC data channel opens (either via offer or answer path), the peers MUST perform an identity exchange before sending any application data.

### 6.1 Identity Message

Each peer sends:

```json
{
  "type": "identity",
  "peerId": "<64-char hex string of full 32-byte ParolNet PeerId>"
}
```

### 6.2 Verification

Upon receiving the identity message, the peer MUST verify:

1. The first 20 bytes of the received `peerId` match the `peer_id` (tracker PeerId) from the signaling exchange.
2. The `peerId` is a valid 32-byte hex string (64 characters).

If verification fails, the data channel and underlying `RTCPeerConnection` MUST be closed immediately.

### 6.3 Ordering

The identity message MUST be the first message sent on a newly opened data channel. Messages received before a valid identity exchange MUST be discarded.

## 7. Announce Scheduling

### 7.1 Mesh Announces

1. **On connect**: Immediately upon establishing a WebSocket connection to a tracker, the client MUST announce the mesh discovery hash.
2. **Periodic**: Every 30 seconds, plus a random jitter uniformly distributed in [-5s, +5s] (i.e., 25-35 seconds), the client MUST re-announce the mesh discovery hash to all connected trackers.

### 7.2 Contact-Specific Announces

1. **On startup**: The client MUST announce all known contact-specific hashes immediately after connecting to trackers.
2. **After QR scan**: When a new contact is added via QR code, the client MUST immediately announce the corresponding contact-specific hash on all connected trackers.
3. **Periodic**: Contact-specific hashes follow the same 30s +/-5s schedule as mesh announces.

### 7.3 Jitter

Jitter MUST be applied independently per announce cycle. The purpose is to prevent temporal correlation of announces across trackers and across peers.

## 8. Multi-Tracker Behavior

### 8.1 Parallel Operation

The client MUST announce on ALL connected trackers simultaneously. Each tracker operates independently; failure of one tracker does not affect others.

### 8.2 Deduplication

When receiving offers or answers from multiple trackers for the same remote peer, the client MUST deduplicate by the tuple `(peer_id, offer_id)`. If a connection to a peer is already established or in progress, redundant offers for that peer SHOULD be discarded.

### 8.3 First Connection Wins

If multiple WebRTC connections to the same peer succeed (e.g., via different trackers), the first connection to reach the `open` state on the data channel MUST be kept, and all others MUST be closed.

## 9. Fallback Priority

Implementations MUST follow this connection priority:

1. **Existing WebRTC data channel** - If already connected via any mechanism, use it.
2. **Tracker-mediated WebRTC** - Primary discovery and signaling path.
3. **Relay circuit (PNP-004)** - Fallback when direct WebRTC connectivity fails.

When a direct WebRTC connection exists, the client SHOULD still maintain tracker presence for mesh health and to accept connections from new peers.

## 10. Security Considerations

### 10.1 Tracker Trust Model

Trackers are completely untrusted. They observe:
- The info_hash being announced (reveals ParolNet usage for mesh hash, reveals nothing for contact hash).
- WebRTC SDP blobs (contain IP addresses and ICE candidates — inherent to WebRTC, not a protocol leak).
- Tracker PeerIds (20-byte truncation of ParolNet PeerId — does not reveal the Ed25519 public key).
- Timing of announces (can correlate peers by temporal proximity).

Trackers do NOT observe:
- Any ParolNet application data (exchanged over the WebRTC data channel after identity verification).
- The full ParolNet PeerId (only 20 bytes exposed).
- The Ed25519 public key (PeerId is a hash, not the key itself).

### 10.2 Mesh Hash Visibility

The mesh discovery hash `SHA-1("parolnet-mesh-v1")` is deterministic and publicly computable. A tracker operator or network observer can determine that a peer is using ParolNet by recognizing this hash. This is an acceptable tradeoff: ParolNet usage is not secret; message content and social graph are.

### 10.3 Contact Hash Privacy

Contact-specific hashes are derived from shared secrets. Without the bootstrap secret, an observer cannot link a contact hash to ParolNet or to any particular pair of users. The hash appears as an opaque BitTorrent info_hash.

### 10.4 SDP and IP Exposure

WebRTC SDP offers and answers contain the peer's IP address and ICE candidates. This is inherent to the WebRTC protocol and cannot be avoided without a TURN relay. Users requiring IP privacy SHOULD use a VPN or connect only through ParolNet relays (PNP-004).

### 10.5 Eclipse Attack Mitigation

An adversary controlling one or more trackers could attempt to isolate a peer by returning only malicious peer connections. Mitigation:

1. Connect to multiple independent trackers (Section 8).
2. Verify peer identity via the identity exchange protocol (Section 6).
3. Prefer peers discovered through multiple independent trackers.
4. Maintain connections to peers discovered via other mechanisms (mDNS, relay, gossip).

### 10.6 Tracker PeerId Collision

The 20-byte tracker PeerId is a truncation of a 32-byte hash. The collision probability is negligible (~2^-160 for birthday attacks on 20-byte identifiers). The identity exchange (Section 6) provides full 32-byte verification after the data channel opens, resolving any theoretical collision.

## 11. Wire Format Summary

| Direction | Action | Key Fields |
|-----------|--------|------------|
| Client -> Tracker | Announce with offers | action, info_hash, peer_id, numwant, offers[] |
| Tracker -> Client | Forwarded offer | action, info_hash, peer_id, offer_id, offer |
| Client -> Tracker | Answer to offer | action, info_hash, peer_id, to_peer_id, offer_id, answer |
| Tracker -> Client | Forwarded answer | action, info_hash, peer_id, offer_id, answer |
| Peer <-> Peer | Identity exchange | type, peerId |
