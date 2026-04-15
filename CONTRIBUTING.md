# Contributing to ParolNet

Thank you for your interest in ParolNet. This project exists to protect the right to private communication for people living under surveillance and censorship. Every contribution matters.

We welcome contributors from all backgrounds, especially those from communities this software is designed to serve. Whether you are a developer, a translator, a security researcher, or someone with lived experience of digital repression, your perspective is valuable.

## Development Environment

### Prerequisites

- **Rust** (edition 2024, MSRV 1.91) -- install via [rustup](https://rustup.rs/)
- **wasm-pack** -- for building the WASM/PWA target: `cargo install wasm-pack`
- **clippy** -- `rustup component add clippy`

### Repository Structure

ParolNet is a Cargo workspace with 9 crates and a PWA shell:

```
crates/
  parolnet-crypto       Pure crypto primitives (WASM-compatible)
  parolnet-protocol     Wire format, envelopes (WASM-compatible)
  parolnet-transport    TLS, WebSocket, traffic shaping (native only)
  parolnet-mesh         Gossip protocol, store-and-forward
  parolnet-relay        Onion routing, circuits
  parolnet-core         Public API: bootstrap, send, recv, panic wipe
  parolnet-wasm         Browser bindings via wasm-bindgen
  parolnet-relay-server Axum WebSocket relay server
  parolnet-authority-cli Authority key and relay endorsement CLI
pwa/                    Installable PWA shell (HTML/JS/manifest)
specs/                  Protocol specifications PNP-001 through PNP-009
```

### Crate Dependency Order

```
parolnet-crypto  (no workspace deps, WASM-compatible)
  |
  v
parolnet-protocol  (depends on crypto, WASM-compatible)
  |
  v
parolnet-transport  (depends on crypto + protocol, native only)
  |
  +---> parolnet-mesh  (+ transport)
  +---> parolnet-relay (+ transport)
  |
  v
parolnet-core  (depends on all above)

parolnet-wasm  (depends on crypto + protocol + core, WASM target only)

parolnet-relay-server  (binary crate for relay deployment)
parolnet-authority-cli (binary crate for authority operations)
```

When adding dependencies, respect this order. `parolnet-crypto` and `parolnet-protocol` must remain WASM-compatible (no tokio, no system libraries).

## Build and Test Commands

```bash
cargo check --workspace              # Verify everything compiles
cargo test --workspace               # Run all tests
cargo clippy --workspace             # Lint -- must pass with no warnings
cargo doc --workspace --no-deps      # Generate documentation
wasm-pack build crates/parolnet-wasm # Build WASM bindings
```

Run all four checks before submitting a PR. CI will run them too.

## Coding Conventions

- **Error handling**: Define error enums with `thiserror`. Propagate errors with `?`. Do not use `.unwrap()` outside of tests.
- **Async**: Use `tokio` directly. Use `async-trait` for async trait methods.
- **Serialization**: CBOR via `ciborium` + `serde`. Not JSON, not protobuf.
- **Logging**: Use the `tracing` crate. No `println!` or `eprintln!` in library code.
- **Dependencies**: Prefer audited, well-maintained crates from established projects (dalek-cryptography, RustCrypto). Use latest stable versions.

## Security Requirements

These are non-negotiable. Every PR is reviewed against these rules. A violation in any of them will block merge.

### 1. No identifying information -- anywhere

`PeerId = SHA-256(Ed25519_pubkey)`. There must be no phone numbers, email addresses, usernames, or any external identifiers anywhere in the codebase. Not in structs, not in comments, not in examples, not in tests.

### 2. Zeroize all key material

Every struct that holds secret key bytes must derive `Zeroize` and `ZeroizeOnDrop`. When the struct is dropped, key material is overwritten in memory. No exceptions.

### 3. All messages must be padded

No unpadded message may reach the transport layer. Use the `PaddingStrategy` trait. If you add a new message type, it must go through padding before transmission.

### 4. No compression before encryption

Never compress plaintext before encrypting it. This prevents CRIME/BREACH-style side-channel attacks.

### 5. Constant-time cryptographic operations

Use the `subtle` crate for all secret-dependent comparisons. ChaCha20-Poly1305 is the default AEAD because it is constant-time without requiring AES-NI hardware support.

### 6. No C dependencies for cryptography

All cryptographic code must be pure Rust. No OpenSSL, no system crypto libraries, no C bindings. This is required for auditability and WASM compatibility.

## Protocol Specifications

The `specs/` directory contains protocol specifications. They are the design target; [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) records which pieces are actually wired into the current application path.

| Spec | Name |
|------|------|
| PNP-001 | Wire Protocol |
| PNP-002 | Handshake Protocol |
| PNP-003 | Bootstrap Protocol |
| PNP-004 | Relay Circuit Protocol |
| PNP-005 | Gossip/Mesh Protocol |
| PNP-006 | Traffic Shaping Protocol |
| PNP-007 | Media and File Transfer Protocol |
| PNP-008 | Relay Federation and Network Resilience |
| PNP-009 | Group Communication Protocol |

When code intentionally implements only part of a spec, update [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and avoid user-facing claims that imply the whole spec is live. If you believe a spec needs to change, update the spec document first and get it reviewed, then update the code to match.

## Submitting a Pull Request

### Before you start

- Check existing issues and PRs to avoid duplicate work.
- For large changes, open an issue first to discuss the approach.

### PR guidelines

- **One logical change per PR.** A bug fix, a new feature, or a refactor -- not all three at once.
- **Include tests.** New functionality needs tests. Bug fixes need a regression test.
- **Run clippy.** `cargo clippy --workspace` must produce zero warnings.
- **Describe what and why.** The PR description should explain what changed and why. Link to relevant issues or specs.
- **Update documentation.** If your change affects the public API, architecture, or build process, update README.md and/or CHANGELOG.md.

### Review process

All PRs require at least one review. Security-sensitive changes (crypto, transport, protocol) require additional scrutiny. Be patient -- thorough review protects the people who depend on this software.

## Reporting Security Vulnerabilities

If you find a security vulnerability, **do not open a public issue.**

Please report it privately by emailing the maintainers. Include:

- A description of the vulnerability
- Steps to reproduce it
- The potential impact
- A suggested fix, if you have one

We will acknowledge receipt within 48 hours and work with you on a fix before any public disclosure. We follow responsible disclosure practices.

If you are unsure whether something is a security issue, err on the side of reporting it privately.

## Code of Conduct

ParolNet is built for people whose safety depends on the quality of this software. We hold ourselves to a high standard -- both in code and in how we treat each other.

- Be respectful and constructive in all interactions.
- Welcome newcomers. Not everyone has the same level of experience, and that is fine.
- Remember that contributors may be members of the communities this software is designed to protect. Be mindful of that context.
- Harassment, discrimination, and hostile behavior will not be tolerated.
- Technical disagreements should focus on the merits of the approach, not the person proposing it.

## License

ParolNet is dual-licensed under **MIT OR Apache-2.0**. By contributing, you agree that your contributions will be licensed under the same terms.
