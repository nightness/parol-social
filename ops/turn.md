# TURN / coturn operations runbook

The ParolNet relay spawns one-off TURN credentials per session but does not
run the TURN server itself — a sidecar `coturn` process running inside the
main relay container handles RFC 5766 allocations, STUN binding, and ICE
relay transport. This doc covers how to deploy, rotate secrets for, monitor,
and debug that sidecar.

## Architecture

- The relay Docker image bundles `coturn` alongside the relay Rust binary
  (see `Dockerfile` + `entrypoint.sh`).
- `server/turnserver.conf` is the production config; it reads secrets from
  environment variables set in `.env`. A sanitized template lives at
  `ops/turn/coturn.conf.example` for review and copy-paste.
- Relay minting endpoint: `GET /turn-credentials` on the relay server
  returns `{username, password, ttl_secs, stun_urls[], turn_urls[]}`. The
  `static-auth-secret` in `turnserver.conf` MUST match `TURN_SECRET` in
  `.env` so the credentials verify at allocation time.

## Deployment (first-time)

1. Create `.env` from `.env.example`. Fill in:
   - `TURN_REALM=biscuits.parol.social` (or your domain)
   - `TURN_SECRET` — at least 32 bytes, random, base64 or hex
   - `TURN_EXTERNAL_IP` — the public IPv4 the server announces
2. Ensure Let's Encrypt certs are present at the paths mounted in
   `docker-compose.yml` (`/etc/letsencrypt/live/biscuits.parol.social`). If
   not, provision them with `certbot certonly --standalone -d <host>`
   BEFORE `docker compose up`.
3. `docker compose up -d parolnet`. The container will:
   - expand `${TURN_SECRET}` / `${TURN_REALM}` / `${TURN_EXTERNAL_IP}` into
     `turnserver.conf` at entrypoint;
   - start `turnserver` on UDP/TCP 3478, TLS on 5349;
   - start the relay Rust binary on port 80 (mapped to host :1411).
4. Verify with `curl http://<host>:1411/turn-credentials` — response MUST
   carry `stun:<host>:3478` and `turn:<host>:3478`. If `external-ip` is
   missing, re-check `TURN_EXTERNAL_IP`.

## Credential rotation

TURN credentials minted by `/turn-credentials` are time-limited (`ttl_secs`,
default 600 s). The underlying `TURN_SECRET` is long-lived and should rotate
on the same cadence as other production secrets (≤ 90 days), or immediately
if compromise is suspected.

**To rotate `TURN_SECRET`:**

1. Pick a new value: `openssl rand -base64 48`.
2. Update `.env` on the host.
3. `docker compose up -d --force-recreate parolnet`. `docker compose` will
   recreate the container with the new secret.
4. **Active sessions break.** Clients will re-request credentials via
   `/turn-credentials` and succeed. Expect a ≤ 2 s gap in any call that was
   mid-allocation; full teardown-and-redial if the call had not yet
   reached `connected` state.

## Monitoring

- **coturn logs**: `/var/log/turnserver/turn.log` inside the container,
  mounted to the host as `/var/log/turnserver`. Look for:
  - `ERROR`: usually port conflicts or cert reload failures.
  - `stale nonce`: benign, indicates `stale-nonce=600` is firing.
  - `Refusing allocation`: quota exceeded (`total-quota=100`).
- **Relay Prometheus metrics**: exported on the relay's admin HTTP port
  (if enabled) include TURN credential issuance count and rate.
- **Client-side**: the PWA's WebRTC stats panel (settings → network)
  shows ICE candidate types. Absence of `relay` candidates means clients
  are not reaching coturn — check firewall on UDP 3478 and the
  `external-ip` setting.

## Multi-relay TURN pooling — operator-only

**Decision (2026-04-18): TURN pooling across federated relays is NOT in the
PNP-008 protocol.** Each relay advertises its own coturn endpoint via
`/turn-credentials`. A client that is home-connected to relay A uses
`A.turn-credentials`; a client roaming to relay B uses `B.turn-credentials`.

Rationale:

- ICE gathering with multiple competing TURN servers increases call setup
  latency because a browser will try every TURN in the candidate list.
- Per-relay coturn keeps the attack surface local — a seized relay can leak
  that relay's TURN secret but not others'.
- The current H12 federation protocol has no authority-agreed TURN secret
  distribution path. Adding one would couple two independent state
  machines for minimal user benefit.

Operators who want a shared TURN pool (typical for commercial SFU
deployments) can stand up a fronted coturn endpoint outside ParolNet and
return that URL from a customized relay build — the `/turn-credentials`
response shape does not care where the URL points.

## Debugging common failures

| Symptom                                       | Likely cause                                                                 |
|-----------------------------------------------|-------------------------------------------------------------------------------|
| No `relay` ICE candidates                     | UDP 3478 blocked at host firewall, or `external-ip` wrong                     |
| 401 from coturn                               | `TURN_SECRET` drift between relay binary and coturn (rotation half-applied)   |
| TLS (5349) fails, UDP works                   | Expired / missing Let's Encrypt cert in `/etc/turn-certs`                     |
| Allocation succeeds, media doesn't flow       | Port range `49152-49252/udp` blocked at firewall or not mapped in compose     |
| 486 Allocation quota reached                  | `total-quota=100` exceeded; bump only after monitoring kernel socket usage    |
| Client PWA shows "TURN unavailable"           | `/turn-credentials` response cached stale; check browser network tab for 5xx |

## Related files

- `server/turnserver.conf` — production config (env-interpolated).
- `ops/turn/coturn.conf.example` — sanitized template.
- `Dockerfile` + `entrypoint.sh` — how coturn launches inside the relay image.
- `crates/parolnet-relay-server/src/main.rs::handle_turn_credentials` —
  credential minting handler.
- `docker-compose.yml` — port mappings (`3478/udp`, `3478/tcp`, `5349/tcp`,
  `49152-49252/udp`) and volume mounts.
