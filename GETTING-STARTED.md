# Getting Started with ParolNet

ParolNet is a secure, private communication app prototype designed for people who need to speak freely without being tracked. The current code supports encrypted sessions and a calculator-disguised PWA, but it is not yet a production-ready safety tool. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what is implemented today.

The app disguises itself as a calculator. To anyone looking at your phone, it appears to be a simple calculator app. Only you know the secret code that opens the real messenger inside.

This guide covers two things:
- **For Users** -- how to install and use ParolNet, even if you are not a technical person
- **For Developers** -- how to build, test, and contribute to the project

---

## For Users (Non-Technical)

### What You Need to Know First

- ParolNet can be installed with a **calculator** name and icon. Decoy mode must be enabled and configured in the app to require a calculator unlock code.
- You unlock the hidden messenger by typing your configured secret code on the calculator keypad and pressing the **=** button.
- Development/no-WASM fallback builds may accept **00000** (five zeros). Do not rely on this default; configure your own code before using decoy mode.
- **Be careful**: make sure no one is watching when you enter your unlock code. If someone sees you type a code and a messenger appears, the disguise is broken.
- After you install and open the app once, cached app assets and stored local data can remain available offline. Sending new messages still depends on an available relay, WebRTC connection, or future mesh support.

---

### Installing ParolNet as a Web App

ParolNet is a web app that you install from your browser. It does not come from the Google Play Store or Apple App Store -- this is by design, so it cannot be censored or removed by those companies.

Someone will give you a web address (URL) to open. It may look like a normal website link.

#### Android (Chrome)

1. Open the ParolNet URL in **Chrome**.
2. The page loads and looks like a calculator.
3. Tap the **three-dot menu** (top right corner) and select **"Add to Home Screen"** or **"Install App"**.
4. Confirm the installation. The app appears on your home screen as **"Calculator"**.
5. Open it from your home screen. You will see a calculator.
6. If decoy mode is enabled, type your unlock code and press **=**.
7. The messenger opens.

#### iPhone or iPad (Safari)

1. Open the ParolNet URL in **Safari**. (This does not work in Chrome on iPhone -- you must use Safari.)
2. The page loads and looks like a calculator.
3. Tap the **Share button** (the square with an arrow pointing up, at the bottom of the screen).
4. Scroll down and tap **"Add to Home Screen"**.
5. It installs as **"Calculator"**.
6. Open it from your home screen.
7. If decoy mode is enabled, type your unlock code and press **=**.
8. The messenger opens.

#### Windows, Mac, or Linux (Chrome or Edge)

1. Open the ParolNet URL in **Chrome** or **Edge**.
2. The page loads and looks like a calculator.
3. Look for the **install icon** in the address bar (it looks like a monitor with a down arrow), or go to the browser menu and select **"Install ParolNet"** or **"Install app"**.
4. The app installs as a standalone window.
5. Open it from your Start menu, Applications folder, or desktop.
6. If decoy mode is enabled, type your unlock code and press **=**.
7. The messenger opens.

---

### Installing as a Disguised Calculator

By default, the app already appears as "Calculator" with a calculator icon. For maximum disguise, you can install using the calculator-specific mode:

- If your ParolNet URL is `https://example.com/`, open `https://example.com/?mode=calc` instead. This uses a dedicated calculator manifest so the app name, icon, and appearance match a real calculator even more closely.
- After installation, there is no visible difference between this and a normal calculator app on your device.

#### Changing Your Unlock Code

1. Open the messenger (type the current code and press **=**).
2. Tap the **gear icon** (Settings) in the top right corner.
3. Under **"Decoy Mode"**, you will see the **Unlock Code** field.
4. Change it to something you will remember. Use only numbers.
5. Tap **"Enable Decoy Mode"** to save.

**Choose a code that is easy for you to remember but hard for others to guess.** Do not use your birthday, phone number, or PIN. A random 5-6 digit number is a good choice.

---

### First Contact

To start messaging someone, you need to exchange keys with them. ParolNet never uses phone numbers or email addresses -- your identity is a cryptographic key that exists only on your device.

There are three ways to add a contact:

#### In Person (QR Code) -- Safest Method

1. Open the messenger and tap the **+** button.
2. You will see a **"Show QR"** tab. This displays your personal QR code.
3. The other person opens their ParolNet, taps **+**, and selects **"Scan QR"**.
4. They point their camera at your QR code.
5. Then you switch -- they show their QR code, and you scan it.
6. Both devices confirm the connection.

This is the safest method because no information travels over the internet. You exchange keys directly, face to face.

#### Over the Phone (Passphrase)

If you cannot meet in person, you can connect by sharing a secret passphrase:

1. Agree on a passphrase with the other person (over a phone call, for example). Use a phrase that is hard to guess -- several random words work well.
2. Both of you open ParolNet, tap **+**, and select the **"Passphrase"** tab.
3. Both of you type the same passphrase and tap **"Connect"**.
4. The app searches the network for a matching passphrase and establishes the connection.

**Important**: Say the passphrase over a voice call or in person. Do not send it in a text message or email -- those can be monitored.

#### Verifying Your Contact (SAS)

After connecting, the app shows a **Short Authentication String (SAS)** -- a short sequence of numbers or emoji. Read this out loud to each other (in person or over the phone) to confirm that no one intercepted the connection. If the codes match, you are securely connected.

---

### Sending Messages

Once you have a contact:

1. Tap their name in the contact list.
2. Type your message and tap **Send** (or press Enter).
3. You can also tap the **paperclip icon** to attach a file.
4. For voice or video calls, tap the **phone** or **camera** icons at the top of the chat.

All messages are end-to-end encrypted. No one -- not even the people who built ParolNet -- can read them.

---

### If You Lose Internet

- **Your messages are safe.** Everything is encrypted and stored on your device. You can still read old messages offline.
- **Mesh networking.** The codebase has local discovery and store-forward primitives, but the browser app does not yet provide a complete offline mesh over Wi-Fi or Bluetooth.
- **Messages queue up.** Delivery after reconnect depends on the relay, WebRTC peer, or future mesh path becoming available.

---

### Emergency: Panic Wipe

If you are in danger and need to destroy all evidence of using ParolNet:

#### From the Calculator Screen

Type **999999** and press **=**. This happens **instantly** with no confirmation prompt. The screen goes blank and shows "0" -- it looks like the calculator just cleared itself.

#### From Inside the Messenger

Go to **Settings** (gear icon) then scroll to **Emergency** and tap **Panic Wipe**. You will be asked to confirm.

#### What Gets Destroyed

- All encryption keys
- All messages and chat history
- All contacts
- All session data
- The app's offline cache and service worker
- All data stored in the browser

**This cannot be undone.** There is no backup, no recovery, no way to get your data back. That is the point -- if your device is seized, there is nothing to find.

**Tip**: Practice the panic wipe once so you know how it works. You can always reinstall the app and start fresh.

---

## For Developers

### Prerequisites

You need Rust and wasm-pack installed on your system.

#### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

Verify your Rust version:

```bash
rustc --version
# Must be >= 1.91 (Rust edition 2024, MSRV 1.91)
```

If your version is too old, update with:

```bash
rustup update stable
```

#### Install wasm-pack

wasm-pack is required to build the WASM module that runs in the browser.

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Verify:

```bash
wasm-pack --version
```

#### Install clippy (for linting)

```bash
rustup component add clippy
```

---

### Clone and Build

```bash
git clone https://github.com/parolnet/parolnet.git
cd parolnet

# Check that everything compiles
cargo check --workspace

# Run all tests
cargo test --workspace

# Lint -- must pass with zero warnings
cargo clippy --workspace

# Build the WASM module and PWA
cd pwa && bash build.sh
```

---

### Running Locally

After building the PWA, you need to serve it over HTTP. The Service Worker requires either HTTPS or `localhost` to function.

#### Using Docker (Recommended)

```bash
docker compose up -d
# Open http://localhost:1411
```

This serves the distribution landing page at `/` and the PWA at `/pwa/`. To stop:

```bash
docker compose down
```

#### Using Node.js

```bash
npx serve pwa -l 1411
# Open http://localhost:1411
```

#### Testing on Other Devices

The Service Worker will not register on non-localhost HTTP connections. To test on a phone or another computer on your network, you have two options:

1. **ngrok** -- exposes your local server over HTTPS:
   ```bash
   ngrok http 1411
   ```
2. **Self-signed certificate** -- set up HTTPS on your local server. The browser will show a warning, but the Service Worker will work.

---

### Project Structure

```
parolnet/
├── crates/                        # Rust workspace (9 crates)
│   ├── parolnet-crypto/           # Cryptographic primitives (X3DH, Double Ratchet,
│   │                              #   ChaCha20-Poly1305, HKDF). WASM-compatible.
│   ├── parolnet-protocol/         # Wire format, CBOR serialization, envelope
│   │                              #   encoding. WASM-compatible.
│   ├── parolnet-transport/        # TLS streams, WebSocket, DPI evasion, traffic
│   │                              #   shaping. Native only (uses tokio).
│   ├── parolnet-mesh/             # Gossip protocol, bloom filters, PoW anti-spam,
│   │                              #   store-and-forward for offline delivery.
│   ├── parolnet-relay/            # Onion routing, 3-hop circuits, relay node,
│   │                              #   directory service.
│   ├── parolnet-core/             # Public client API: bootstrap, sessions, send/recv,
│   │                              #   panic wipe, calls, file transfer.
│   ├── parolnet-wasm/             # Browser WASM bindings via wasm-bindgen.
│   ├── parolnet-relay-server/     # Axum WebSocket relay server.
│   └── parolnet-authority-cli/    # Authority key and relay endorsement CLI.
├── pwa/                           # Progressive Web App shell
│   ├── index.html                 # App shell (calculator + messenger views)
│   ├── app.js                     # Application logic (vanilla JS, zero dependencies)
│   ├── styles.css                 # Messenger styles
│   ├── calculator.css             # Calculator decoy styles
│   ├── sw.js                      # Service Worker (offline caching, push notifications)
│   ├── build.sh                   # Build script (wasm-pack + copy to pwa/pkg/)
│   ├── manifest.json              # PWA manifest (standard)
│   ├── manifest-calculator.json   # PWA manifest (calculator disguise)
│   └── icons/                     # App icons (standard + calculator variants per OS)
│       ├── icon.svg               # Standard ParolNet icon
│       ├── calc-ios.svg           # Calculator icon for iOS
│       ├── calc-android.svg       # Calculator icon for Android
│       └── calc-windows.svg       # Calculator icon for Windows
├── specs/                         # Protocol specifications (design target)
│   ├── PNP-001-wire-protocol.md
│   ├── PNP-002-handshake-protocol.md
│   ├── PNP-003-bootstrap-protocol.md
│   ├── PNP-004-relay-circuit.md
│   ├── PNP-005-gossip-mesh.md
│   ├── PNP-006-traffic-shaping.md
│   ├── PNP-007-media-file-transfer.md
│   ├── PNP-008-relay-federation.md
│   └── PNP-009-group-communication.md
├── Cargo.toml                     # Workspace configuration
├── rust-toolchain.toml            # Rust toolchain (stable channel)
├── CLAUDE.md                      # AI assistant instructions
├── CONTRIBUTING.md                # Contributor guide
├── THREAT_MODEL.md                # STRIDE security analysis
├── STRATEGIES.md                  # Adoption and distribution playbook
├── ROADMAP.md                     # Development roadmap
├── CHANGELOG.md                   # Version history
├── IMPLEMENTATION_STATUS.md       # Current code vs protocol design target
└── README.md                      # Project overview
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
parolnet-relay-server  (relay server binary)
parolnet-authority-cli (authority operations)
```

`parolnet-crypto` and `parolnet-protocol` must remain WASM-compatible. They cannot depend on `tokio` or any system-level libraries.

---

### Running Tests

```bash
# Run all tests across the workspace
cargo test --workspace

# Run tests for a specific crate
cargo test -p parolnet-crypto
cargo test -p parolnet-protocol
cargo test -p parolnet-transport
cargo test -p parolnet-mesh
cargo test -p parolnet-relay
cargo test -p parolnet-core

# Run a specific test by name
cargo test -p parolnet-crypto -- test_name_here

# Run tests with output (see println! in tests)
cargo test --workspace -- --nocapture

# Generate a coverage report (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --exclude parolnet-wasm --out Html --output-dir coverage/
open coverage/tarpaulin-report.html
```

---

### Building for Distribution

ParolNet is designed to be distributed through many channels, including ones that are resistant to censorship.

#### 1. Static Web Hosting

Any static file server works. No backend, no database, no server-side logic.

```bash
cd pwa && bash build.sh
# Upload the entire pwa/ directory to your web server
```

#### 2. ZIP for USB / Sneakernet Distribution

For offline distribution -- copy the app onto USB drives, SD cards, or share it over local file transfer.

```bash
cd pwa && bash build.sh
zip -r parolnet-pwa.zip .
# Share parolnet-pwa.zip however you can
```

Recipients extract the ZIP and open `index.html` in a browser. Some browser features, especially Service Worker installation, require HTTPS or `localhost`; a direct `file://` launch is useful for inspection or limited local use, not a complete PWA deployment.

#### 3. IPFS (Censorship-Resistant Hosting)

IPFS distributes content across a decentralized network. No single server can be taken down.

```bash
cd pwa && bash build.sh
ipfs add -r .
# Returns a CID (content hash) that anyone can use to access the app
```

#### 4. Tor Hidden Service

Host the PWA as a Tor `.onion` site for anonymous access.

```bash
# Place the pwa/ directory in your Tor hidden service directory
# Configure torrc to point to pwa/
# Users access it via the .onion address in Tor Browser
```

---

### Key Commands Reference

| Command | Purpose |
|---------|---------|
| `cargo check --workspace` | Verify all crates compile |
| `cargo test --workspace` | Run all workspace tests |
| `cargo clippy --workspace` | Lint (must produce zero warnings) |
| `cargo doc --workspace --no-deps` | Generate API documentation |
| `cargo doc --workspace --no-deps --open` | Generate and open docs in browser |
| `wasm-pack build crates/parolnet-wasm` | Build WASM bindings |
| `wasm-pack build crates/parolnet-wasm --target web --release` | Build WASM for production |
| `cd pwa && bash build.sh` | Build WASM + copy to PWA directory |
| `cargo test -p parolnet-crypto` | Test a specific crate |
| `cargo tarpaulin --workspace --exclude parolnet-wasm --out Html` | Coverage report |

---

### Troubleshooting

#### WASM module not loading

- Make sure `wasm-pack` built successfully: check for errors in the `cd pwa && bash build.sh` output.
- Verify the `pwa/pkg/` directory exists and contains `.wasm` and `.js` files.
- Check the browser console (F12) for error messages.

#### Service Worker not registering

- The Service Worker requires **HTTPS** or **localhost**. It will not register on plain HTTP served from a network IP address.
- If testing locally, use `http://localhost:1411`, not `http://192.168.x.x:1411`.
- For testing on other devices, use ngrok or set up HTTPS.

#### Calculator not showing on launch

- The calculator (decoy mode) is shown by default when the WASM module is not available, or when decoy mode is explicitly enabled in Settings.
- If the app goes straight to the messenger, go to Settings and tap "Enable Decoy Mode".

#### Push notifications not working

- Check that the browser has granted notification permissions. Go to your browser's site settings for the ParolNet URL.
- Push notifications require an active Service Worker. Make sure it registered successfully (check the browser console).
- Some browsers block notifications by default. The user must explicitly allow them.

#### Rust version too old

```bash
rustup update stable
rustc --version
# Must be >= 1.91
```

#### wasm-pack not found

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
# Or install via cargo:
cargo install wasm-pack
```

---

### Security Invariants

If you are contributing code, these rules are non-negotiable. Every pull request is reviewed against them. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide.

1. **No identifying information.** No phone numbers, emails, or usernames anywhere in the codebase. Identity is `PeerId = SHA-256(Ed25519_pubkey)`.
2. **Zeroize all key material.** Every struct holding secret keys must derive `Zeroize` and `ZeroizeOnDrop`.
3. **All messages must be padded.** No unpadded message may reach the transport layer.
4. **No compression before encryption.** Prevents CRIME/BREACH-style attacks.
5. **Constant-time crypto only.** Use the `subtle` crate for comparisons. ChaCha20-Poly1305 is the default AEAD.
6. **No C dependencies for crypto.** Pure Rust only. No OpenSSL, no system crypto libraries.

---

### Further Reading

- [README.md](README.md) -- Project overview, architecture diagram, security model
- [CONTRIBUTING.md](CONTRIBUTING.md) -- How to submit pull requests, coding conventions, review process
- [THREAT_MODEL.md](THREAT_MODEL.md) -- STRIDE security analysis
- [STRATEGIES.md](STRATEGIES.md) -- Adoption and distribution strategy
- [ROADMAP.md](ROADMAP.md) -- Development roadmap and milestones
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) -- What the current code actually implements
- [specs/](specs/) -- Protocol specifications (PNP-001 through PNP-009), the design target for wire formats and behavior
