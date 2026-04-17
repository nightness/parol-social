# H12 Phase 1 — Deploy a Secondary Relay

This runbook brings up a second, independently-hostable ParolNet relay so
that a takedown of the primary operator does not silently kill the network.
Users can still only message peers on the **same** relay — cross-relay
message forwarding is Phase 2/3. What you gain here is deployment
redundancy and legal/operational decentralization.

## 1. Provision a VPS

Anything that can run Docker works. The relay uses ~30 MB RAM idle.

Minimum:

- 1 vCPU, 512 MB RAM, 5 GB disk
- Public IPv4 (IPv6 optional but recommended)
- Open ports `80/tcp`, `443/tcp`, `3478/udp+tcp`, `5349/tcp`,
  `49152-49252/udp` (TURN relay range). Match the primary.

SSH in, install Docker and `docker compose`. Nothing ParolNet-specific
yet.

## 2. DNS

Pick a subdomain for the secondary. Example assumes `biscuits-two.parol.social`.

- `A`  `biscuits-two.parol.social`  → secondary VPS IPv4
- `AAAA` (optional) → secondary VPS IPv6

Wait for propagation (`dig +short biscuits-two.parol.social`).

## 3. TLS cert

```
sudo apt install certbot
sudo certbot certonly --standalone -d biscuits-two.parol.social
```

The cert lands in `/etc/letsencrypt/live/biscuits-two.parol.social/`.
Symlink into the path the compose file expects, or adjust the compose
volume mounts:

```yaml
volumes:
  - /etc/letsencrypt/live/biscuits-two.parol.social:/etc/turn-certs:ro
  - /etc/letsencrypt/archive/biscuits-two.parol.social:/etc/letsencrypt/archive/biscuits-two.parol.social:ro
```

## 4. Clone + boot

```
git clone https://github.com/nightness/parolnet.git
cd parolnet
cp .env.example .env   # or copy from primary, minus any primary-only creds
```

Create the persistent identity directory **before** first boot so the
volume mount picks it up:

```
mkdir -p ./relay-data-secondary
chmod 700 ./relay-data-secondary
```

Do **not** copy `relay.key` from the primary — each relay must have its
own Ed25519 identity. The relay generates `relay-data-secondary/relay.key`
(mode 0600) automatically on first boot.

## 5. Configure peer discovery

Both relays need to know about each other so `/directory` sync picks up
new descriptors.

Primary's `.env`:
```
PEER_RELAY_URLS=https://biscuits-two.parol.social
```

Secondary's `.env`:
```
PEER_RELAY_URLS=https://biscuits.parol.social
```

Restart both. Check logs for a `relay_directory_sync` line indicating a
successful pull.

## 6. Start the secondary

On the secondary VPS:

```
docker compose up -d --build
```

Note: the repo ships the secondary service as a profiled entry
(`docker compose --profile secondary up -d relay-secondary`) intended
for local multi-relay testing. In production, deploy the secondary to
its own VPS using the default service — one relay per host is the
natural configuration.

Verify identity persistence:

```
docker compose exec parolnet ls -la /data/relay.key
# -rw------- 1 root root 32 ... /data/relay.key
docker compose restart parolnet
docker compose logs parolnet | grep 'Relay Ed25519 public key'
# Pubkey must be stable across restarts.
```

## 7. Authority endorsement

For clients to accept the secondary's descriptors, the authority set
(baked into `pwa/network-config.js` at build time) must have endorsed
it. Use `parolnet-authority-cli` (see `crates/parolnet-authority-cli/`)
on the offline authority machine to produce an `AuthorityEndorsement`
CBOR blob for the secondary's descriptor, then upload it to the
secondary.

This runbook does not cover the authority signing ceremony itself —
that is operator-specific and should run on an airgapped machine.

## 8. Rebuild the PWA with both relays

On the dev machine:

```
cd pwa
./build.sh \
    --pubkeys AUTH1_HEX,AUTH2_HEX,AUTH3_HEX \
    --threshold 2 \
    --network-name "ParolNet" \
    --bootstrap-relays https://biscuits.parol.social,https://biscuits-two.parol.social
```

That populates `BOOTSTRAP_RELAYS` in the generated `network-config.js`
with both entries. The PWA will iterate through them on connect — first
successful register wins — and fetch `/directory` from the chosen relay
with authority-threshold verification of each descriptor.

Redeploy the PWA bundle to both relays (nginx serves it from
`/usr/share/nginx/html/pwa/`).

## 9. Verify

1. Open the PWA in a fresh browser profile. DevTools → Application →
   LocalStorage → confirm `parolnet_relay_directory` contains both URLs.
2. Settings → Relay → confirm the connected-relay URL and its Ed25519
   fingerprint are shown, and the known-directory list has the second
   relay with an authority-verified badge.
3. Kill the primary container. The PWA should reconnect to the
   secondary on its next WebSocket retry.

## 9a. Phase 2 Multi-Relay Routing (H12 Phase 2)

Phase 2 unlocks client-side cross-relay routing: a PWA on relay A can now
message a peer on relay B without moving hosts. Two deployment
prerequisites must hold on **every** relay before it will work:

**1. Set `RELAY_PUBLIC_URL` on every relay.** When a client hits
`/peers/lookup?id=...` on its home relay, the relay answers with the
home_relay_url for the target peer. If `RELAY_PUBLIC_URL` is unset the
relay falls back to whatever bind address it booted with (typically
`0.0.0.0:<port>` or a container-internal name), and clients on the
public internet cannot connect to the returned URL.

The PWA mitigates partial misconfigurations (caveat 1 of H12 Phase 2
commit 2): if the lookup response returns an unreachable URL but the
PWA's BOOTSTRAP_RELAYS already contains a reachable URL whose
authority-verified directory entry matches the same `relay_peer_id`, the
PWA will swap in the BOOTSTRAP URL for the outbound connection. The
signature / identity binding is preserved — only the transport URL is
swapped. This is a safety net, not an excuse: set `RELAY_PUBLIC_URL`
explicitly on every relay in production.

```
# Primary's .env
RELAY_PUBLIC_URL=https://biscuits.parol.social

# Secondary's .env
RELAY_PUBLIC_URL=https://biscuits-two.parol.social
```

**2. Exact-string match between `PEER_RELAY_URLS` and each relay's
`/directory` `addr` field.** Federation presence-fetch does a naive
string comparison between the URL form in `PEER_RELAY_URLS` (the relay
to poll) and the URL form the peer relay advertises through its own
`/directory` descriptor. A difference as small as a trailing slash,
`http://` vs `https://`, or a hostname-vs-IP substitution silently
disables cross-relay presence population for that peer.

Concretely, if relay A has `PEER_RELAY_URLS=https://B.example` but B's
`/directory` advertises itself under `addr=1.2.3.4:9000` (which the PWA
normalizes to `http://1.2.3.4:9000`), A will fetch B's `/peers/presence`
but never associate its entries with B's descriptor. Operators must
choose one canonical form and use it in both env vars across the
federation.

The authoritative operator-side contract:

- `PEER_RELAY_URLS` entries on every relay match the exact strings that
  each peer's `/directory` returns as its own `addr`-derived URL.
- Test with `curl -s https://<peer>/directory | hexdump -C | head`
  (CBOR) or `curl -s -H 'Accept: application/json' https://<peer>/directory`
  if the relay supports the JSON form; compare against your
  `PEER_RELAY_URLS` string byte-for-byte.
- When in doubt, prefer `https://<hostname>` (no trailing slash, no
  port) and configure the relay to derive its public URL from the same
  hostname.

This is pinned as a PNP-008 deployment note; the 1-second-window
`/peers/lookup` rate limiter (10 events/window) is intentional and
acceptable for Phase 2.

## 10. What Phase 1 does NOT do

- **No cross-relay messaging.** Alice on primary and Bob on secondary
  still cannot talk to each other. They must both be registered to the
  same relay.
- **No federation link between relays.** Relays exchange `/directory`
  entries over HTTP polling, not over a persistent TLS link.
- **No IBLT descriptor sync, no circuit-cell forwarding.** Those are
  Phase 2/3 and unlock H3 onion's real guarantees.

The win is narrow but meaningful: the network now has two
independently-operated legal targets, two independent operators, and
two independent physical hosts. Clients can fail over between them.
