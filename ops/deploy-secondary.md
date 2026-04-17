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
