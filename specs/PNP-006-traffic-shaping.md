# PNP-006: ParolNet Traffic Shaping Protocol

### Status: DRAFT
### Version: 0.1
### Date: 2026-04-10

---

## Implementation Note

This document is a traffic-shaping design target. Current code has transport camouflage primitives, but the user-facing PWA/relay path does not yet provide constant-rate cover traffic, HTTP/2-shaped browser relay traffic, or full TLS fingerprint mimicry end to end.

## 1. Overview

The ParolNet Traffic Shaping Protocol (PTSP) is a behavioral specification, not a wire protocol. It defines how ParolNet nodes MUST shape their network traffic so that, to any observer performing deep packet inspection (DPI) or statistical traffic analysis, the traffic is indistinguishable from a user browsing a CDN-hosted website over HTTP/2 using a mainstream browser.

PTSP operates at three layers: (a) TLS fingerprint mimicry to defeat ClientHello-based fingerprinting, (b) connection behavior patterns that match normal HTTPS usage, and (c) traffic timing and volume shaping that prevents statistical classification.

This specification does not define new message types or wire formats. It constrains the behavior of the existing protocols (PNP-004, PNP-005) and the underlying TLS transport.

## 2. Terminology

- **Cover Traffic**: Padding or dummy data sent to maintain constant traffic rate when no real data is pending.
- **Dummy Message**: A complete gossip or circuit message that is cryptographically valid but carries no application-meaningful payload. Indistinguishable from real messages to any party except the final recipient.
- **Bandwidth Mode**: A configuration parameter controlling the intensity of cover traffic.
- **TLS Fingerprint**: The set of parameters in a TLS ClientHello message (cipher suites, extensions, supported groups, etc.) that uniquely identifies a TLS implementation.
- **Traffic Shape**: The statistical distribution of packet sizes, inter-packet timing, and burst patterns observable on a connection.
- **Jitter**: Random variation added to message send times.
- **DPI (Deep Packet Inspection)**: Network inspection technology that examines packet contents and metadata beyond basic header fields.

## 3. Bandwidth Modes

PTSP defines three bandwidth modes. A node MUST support all three and MUST allow the user to select a mode. The default MUST be NORMAL.

| Mode   | Padding Interval | Dummy Traffic % | Max Bandwidth | Use Case                        |
|--------|-------------------|-----------------|---------------|---------------------------------|
| LOW    | 2000ms            | 5%              | ~2 KB/s idle  | Metered/mobile connections      |
| NORMAL | 500ms             | 20%             | ~8 KB/s idle  | Standard desktop/broadband      |
| HIGH   | 100ms             | 40%             | ~40 KB/s idle | Maximum anonymity, high threat  |

The padding interval is the maximum time between consecutive sends (real or padding) on any connection. Dummy traffic percentage is the fraction of total sent messages that are decoy.

## 4. Behavioral Rules

### 4.1 Constant-Rate Padding

```
    Time --->

    Real traffic:     [D]   [D][D]                [D]        [D]
    Padding fill:  [P]   [P]      [P][P][P][P][P]    [P][P]     [P]
    Wire (merged):  P  D  P  D  D  P  P  P  P  P  D  P  P  D  P
                    |--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|
                    ^     ^                          ^
                    Interval                         Interval

    Legend: D = real Data, P = Padding
    The interval between any two consecutive sends MUST NOT exceed
    the configured padding interval.
```

1. When a connection is idle (no real data to send), the node MUST send a PADDING cell (for circuit connections, PNP-004 Section 3.9) or a dummy gossip message (for gossip connections) at the configured padding interval.
2. When real data is available, it replaces padding -- the node MUST NOT send both a real message and a padding message at the same tick. Real data takes priority.
3. The padding interval MUST NOT be perfectly regular. Each interval MUST have jitter applied (see Section 4.4).

### 4.2 Burst Smoothing

1. When the application layer produces a burst of N messages in quick succession, the transport layer MUST NOT send them all immediately.
2. Instead, messages MUST be queued and drained at the current padding rate, with real messages replacing padding slots.
3. If the queue depth exceeds 32 messages, the node MAY temporarily double the send rate for at most 5 seconds, then return to the base rate. This mimics a web page load burst followed by idle.
4. The queue MUST be served in FIFO order. Priority messages (DESTROY cells, key exchange messages) MAY jump the queue.

### 4.3 Dummy Traffic Generation

1. At every send opportunity, the node MUST decide whether to send a real message, a padding cell, or a dummy message.
2. The dummy traffic percentage (5/20/40% per mode) is applied as follows: of all non-real sends, the specified percentage MUST be dummy messages rather than simple padding cells.
3. A dummy message is a fully-formed gossip message (type USER_MESSAGE) or circuit DATA cell with random encrypted payload. It MUST be routed through a real circuit and MUST be indistinguishable from genuine traffic to all relays.
4. The final recipient of a dummy message (the exit relay or the destination node) identifies it as dummy by a reserved flag in the decrypted inner payload (first byte 0x00 = dummy, 0x01 = real). This byte MUST be inside the innermost encryption layer and MUST NOT be visible to intermediate relays.
5. Dummy messages MUST have valid AEAD tags and MUST be processed through the same encryption pipeline as real messages.

### 4.4 Timing Jitter

1. All message sends MUST have random jitter added to the base interval.
2. The jitter MUST be drawn from a uniform distribution over [0, J_max], where J_max depends on bandwidth mode:
   - LOW: J_max = 500ms
   - NORMAL: J_max = 100ms
   - HIGH: J_max = 30ms
3. The jitter MUST be generated from a cryptographically secure random source.
4. Jitter MUST be applied independently to each send event. Implementations MUST NOT use a predictable jitter pattern.

### 4.5 Connection Behavior

1. **Long-lived connections**: Nodes MUST establish TLS connections and maintain them for extended periods. The minimum connection lifetime before voluntary teardown MUST be 10 minutes. The RECOMMENDED lifetime is 1-4 hours, randomized.
2. **No rapid reconnect**: After disconnecting from a peer, a node MUST wait at least 30 seconds before reconnecting. This prevents the connect/disconnect pattern characteristic of non-browser traffic.
3. **Connection count**: A node SHOULD maintain 2-8 simultaneous connections. This mimics a browser with connections to a CDN and a few origins.
4. **Connection reuse**: Nodes MUST multiplex circuits and gossip streams over a single TLS connection to a given peer (like HTTP/2 streams over one connection).
5. **Graceful shutdown**: Connections MUST be closed with a proper TLS close_notify. Abrupt RST-based termination MUST be avoided unless the peer is unresponsive.
6. **Keepalive**: If the TLS library supports it, TCP keepalive MUST be enabled with a 30-second interval, matching typical browser behavior.

### 4.6 Session Traffic Patterns

1. To mimic HTTPS browsing, nodes SHOULD shape their traffic into "request-response" cadences:
   a. A burst of 2-8 cells (simulating an HTTP/2 request + server push) followed by a quiet period.
   b. Quiet periods of 1-10 seconds (simulating reading time).
   c. Occasional large bursts of 20-50 cells (simulating a page load).
2. This shaping is RECOMMENDED but not REQUIRED. It is most effective when the node is under active DPI surveillance. Implementations MAY provide a "stealth mode" that enables full traffic pattern mimicry at the cost of increased latency.
3. The traffic pattern profile SHOULD be configurable and updatable without a software release, loaded from a "traffic profile" configuration file.

## 5. TLS Fingerprint Requirements

### 5.1 ClientHello Mimicry

1. The TLS ClientHello message MUST match the fingerprint of a recent version of a mainstream browser. The RECOMMENDED target is the latest stable release of Chrome or Firefox at the time of the implementation's release.
2. Specifically, the following ClientHello fields MUST match the target browser:
   a. **Cipher suites**: Same list, same order.
   b. **Extensions**: Same set, same order. This includes SNI, ALPN, supported_versions, key_share, signature_algorithms, ec_point_formats, and all others.
   c. **Supported groups**: Same list, same order.
   d. **ALPN**: MUST advertise "h2" and "http/1.1" in that order.
   e. **SNI**: MUST be set to a plausible hostname (see Section 5.2).
   f. **Key share**: MUST include X25519 (and optionally Kyber768/ML-KEM for Chrome mimicry).
3. Implementations MUST use a TLS library that supports fine-grained ClientHello customization. The RECOMMENDED library is rustls with a custom ClientHello builder or utls-equivalent functionality.
4. TLS fingerprints MUST be updatable without a full software release. Implementations SHOULD load fingerprint profiles from a configuration file or embed multiple profiles and rotate.

### 5.2 SNI and Domain Fronting

1. The SNI field MUST contain a plausible domain name. Implementations SHOULD select from a configurable list of domains that resolve to CDN IP addresses (e.g., domains hosted on Cloudflare, Fastly, or AWS CloudFront).
2. The actual ParolNet relay MAY be reached via domain fronting, where the SNI and Host header differ. However, domain fronting availability varies and is not guaranteed.
3. If domain fronting is unavailable, the relay MUST serve a plausible HTTPS response (a static web page, a 200 OK with generic content) to non-ParolNet clients connecting to it. This prevents relay identification by probing.
4. Relay nodes MUST listen on port 443. Listening on non-standard ports is NOT RECOMMENDED as it enables trivial identification.

### 5.3 Application Layer Protocol Behavior

1. After TLS handshake, the connection MUST negotiate HTTP/2 via ALPN.
2. The initial exchange MUST include valid HTTP/2 connection preface and SETTINGS frames.
3. ParolNet cells MUST be transported as HTTP/2 DATA frames on a dedicated stream. This ensures DPI systems see valid HTTP/2 framing.
4. Implementations MUST handle incoming HTTP/2 requests from probes by responding with a valid HTTP response (status 200, content-type text/html, a generic page body).

## 6. Security Considerations

1. **TLS fingerprint staleness**: Browser TLS fingerprints evolve with each release. An outdated fingerprint becomes a distinguishing signal. Implementations MUST update their fingerprint profiles at least every 6 months. Automatic fingerprint update via gossip-distributed profile bundles is RECOMMENDED.
2. **Traffic analysis by volume**: Even with constant-rate padding, the total bandwidth consumption of a node may differ from genuine browser traffic. LOW mode minimizes this discrepancy for casual observers but provides less protection. HIGH mode provides maximum cover at the cost of bandwidth.
3. **Active probing**: An adversary may connect to a suspected relay and attempt protocol-specific probes. Relay nodes MUST respond to non-ParolNet connections with a plausible web server response (Section 5.2). The relay MUST NOT reveal ParolNet protocol behavior until the client provides a valid circuit CREATE cell.
4. **Timing side channels**: Even with jitter, sufficiently precise timing measurement may distinguish ParolNet traffic from genuine browsing. The jitter distribution (uniform) is simple; implementations in high-threat environments MAY use empirically-derived distributions matching real browser inter-packet times.
5. **Dummy message overhead**: Dummy messages consume bandwidth and relay resources. A compromised relay could detect dummy messages if it is the exit node (by seeing the dummy flag). This reveals that the circuit originator is running ParolNet but does not reveal message content or identity. The exit relay already knows it is part of a ParolNet circuit, so this is not considered additional information leakage.
6. **Resource exhaustion**: HIGH mode consumes approximately 40 KB/s of idle bandwidth. On metered connections, this could be costly. Implementations MUST clearly warn users about bandwidth consumption in each mode and MUST default to NORMAL.

## 7. Privacy Considerations

1. **Observer's view**: To a passive network observer (ISP, firewall, national gateway), a ParolNet node's traffic MUST appear as a user maintaining a few long-lived HTTPS/2 connections to CDN-hosted websites, with typical browsing traffic patterns. The observer sees: TLS 1.3 with a standard browser fingerprint, HTTP/2 framing, steady low-bandwidth traffic with occasional bursts, and standard port 443.
2. **What the observer cannot determine**: (a) That the traffic is ParolNet rather than web browsing, (b) the identity of the communicating parties, (c) the content of any messages, (d) which traffic is real and which is padding/dummy.
3. **What the observer can determine**: (a) The IP addresses of the communicating nodes (mitigated by relay circuits, PNP-004), (b) the total volume of traffic over long periods (mitigated by bandwidth mode selection), (c) connection duration and timing of establishment/teardown.
4. **Correlation attacks**: A sophisticated adversary controlling both the network and one or more relays may attempt to correlate traffic entering and exiting the network. Constant-rate padding and dummy traffic increase the difficulty but do not make correlation impossible. This is an inherent limitation documented for transparency.
5. **Fingerprint diversity**: If all ParolNet nodes use the same browser fingerprint, an adversary could block that fingerprint. Implementations SHOULD support multiple fingerprint profiles (Chrome, Firefox, Edge) and SHOULD distribute them across the node population so that no single fingerprint accounts for more than 50% of ParolNet traffic.
6. **Local network privacy**: Older protocol text specifies mDNS advertisements (PNP-005 Section 5.9), which would reveal ParolNet node presence to local observers. Current code uses obfuscated UDP broadcast discovery instead, but local discovery is still observable network behavior. In high-threat environments, nodes SHOULD disable local discovery and rely on manual peer configuration or pre-shared peer lists.

## 8. Cross-Protocol Interactions

- **PNP-004 (Circuits) + PNP-006 (Traffic Shaping)**: All circuit cell transmission MUST comply with PTSP timing, padding, and TLS fingerprint requirements. Circuit PADDING cells (PNP-004 Section 3.9) are the mechanism by which PTSP constant-rate padding is achieved on circuit connections.
- **PNP-005 (Gossip) + PNP-006 (Traffic Shaping)**: Gossip message forwarding timing MUST comply with PTSP jitter and burst smoothing rules. Dummy gossip messages provide the PTSP dummy traffic quota on gossip connections.
- **PNP-005 (Gossip) + PNP-004 (Circuits)**: Relay descriptors are distributed via gossip. High-sensitivity user messages SHOULD be injected into circuits before entering the gossip layer, using the circuit's exit relay as the gossip injection point.
