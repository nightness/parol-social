# ParolNet

> **Parol** — *parole* (speech/word) in French, *пароль* (password) in Russian, *parola* (password) in Turkish, *parola* (word) in Italian. It embodies the dual mission: **free speech protected by strong security**.

A secure, decentralized communication platform promoting free expression and open access to information. Designed for citizens in countries with oppressive authoritarian regimes who still have internet access. But usable for secure communication in general.

---

## Why ParolNet Exists

Billions of people live under governments that monitor their communications, block access to information, and punish dissent. Existing tools have gaps:

- **Signal** requires a phone number — a government-issued identifier that links your identity to your messages. In many countries, SIM cards require ID registration.
- **Tor** anonymizes browsing but its traffic is recognizable to deep packet inspection. Many authoritarian states block Tor entirely.
- **VPNs** are centralized — governments pressure providers, block known VPN IPs, or simply outlaw them.
- **Telegram** stores messages on servers and has a history of cooperating with governments under pressure.

ParolNet is built from the ground up to solve these problems together:

### How ParolNet Protects You

**Your identity is invisible.** There is no registration. No phone number, no email, no username, no account. Your identity is a cryptographic key that exists only on your device. You connect with others by scanning a QR code in person or sharing a passphrase — no server ever learns who you are.

**Your traffic is undetectable.** To anyone watching your internet connection — your ISP, a national firewall, a government monitoring system — ParolNet traffic looks identical to normal web browsing. The same encryption protocols, the same packet sizes, the same traffic patterns. There is nothing to block because there is nothing to distinguish.

**Your conversations are untraceable.** Messages travel through a chain of three volunteer relay nodes, each encrypted in layers like an onion. No single relay knows both who sent a message and who received it. Even if a relay is compromised, your privacy is maintained.

**Your metadata is protected.** It's not enough to encrypt message content — governments map social networks by analyzing who talks to whom, when, and how often. ParolNet pads all messages to fixed sizes, sends constant cover traffic, and uses decoy messages so that even traffic patterns reveal nothing.

**Your device is safe if seized.** A single panic button securely erases all keys, messages, and contacts from your device. A decoy mode makes the app appear as a calculator or notepad. Deniable encryption means you cannot be forced to prove what you sent — even to a court.

**You can communicate without internet.** When the government shuts down the internet — as has happened in Iran, Myanmar, Belarus, and elsewhere — ParolNet's mesh networking allows nearby devices to relay messages over Bluetooth and Wi-Fi, forming a local communication network that doesn't depend on any infrastructure.

---

## Who This Is For

ParolNet is for anyone who needs to communicate privately in a hostile environment:

- **Journalists** investigating corruption or human rights abuses
- **Activists** organizing peaceful protests or documenting state violence
- **Lawyers** communicating with clients about sensitive cases
- **Ordinary citizens** who simply want to speak freely without fear
- **Whistleblowers** exposing wrongdoing within governments or corporations
- **Aid workers** coordinating in conflict zones
- **Minority communities** facing persecution for their identity, beliefs, or ethnicity

---

## How ParolNet Is Different

| Feature | Signal | Tor | VPN | ParolNet |
|---------|--------|-----|-----|----------|
| No phone/email required | No | Yes | No | **Yes** |
| Traffic looks like normal browsing | No | No | Partially | **Yes** |
| Metadata protection | Partial | Yes | No | **Yes** |
| Works without internet | No | No | No | **Yes** (mesh) |
| Panic wipe / decoy mode | No | No | No | **Yes** |
| Decentralized (no company to pressure) | No | Yes | No | **Yes** |
| End-to-end encrypted | Yes | No* | No | **Yes** |

*Tor encrypts transport but is not a messaging protocol.

---

## Mission Statement — In Your Language

### English
ParolNet is free, open-source software that protects your right to private communication. No government, corporation, or individual can read your messages, track who you talk to, or shut down the network. Your voice matters. Your privacy is non-negotiable.

### Chinese (Simplified) / 中文（简体）
ParolNet 是一款免费开源软件，旨在保护您的私人通信权利。任何政府、企业或个人都无法阅读您的消息、追踪您的通信对象或关闭网络。您的声音至关重要。您的隐私不容协商。

ParolNet 专为生活在审查和监控环境下的用户设计。它不需要手机号码或电子邮件注册。您的网络流量看起来与普通网页浏览完全相同——没有什么可以被封锁，因为没有什么可以被识别。即使互联网被关闭，设备之间的网状网络通信仍然可以继续工作。如果您的设备被没收，一键紧急清除功能可以安全地销毁所有密钥和消息。

### Russian / Русский
ParolNet — это бесплатное программное обеспечение с открытым исходным кодом, которое защищает ваше право на конфиденциальную связь. Ни правительство, ни корпорация, ни отдельное лицо не могут прочитать ваши сообщения, отследить, с кем вы общаетесь, или отключить сеть. Ваш голос важен. Ваша конфиденциальность не подлежит обсуждению.

ParolNet разработан для людей, живущих в условиях цензуры и слежки. Для регистрации не нужен номер телефона или электронная почта. Ваш интернет-трафик выглядит как обычный просмотр веб-страниц — блокировать нечего, потому что отличить невозможно. Даже при отключении интернета связь между устройствами продолжается через mesh-сеть. Если ваше устройство изъято, функция экстренного уничтожения данных безопасно удалит все ключи и сообщения.

### Persian (Farsi) / فارسی
پارولنت یک نرم‌افزار رایگان و متن‌باز است که از حق شما برای ارتباطات خصوصی محافظت می‌کند. هیچ دولت، شرکت یا فردی نمی‌تواند پیام‌های شما را بخواند، ردیابی کند که با چه کسی صحبت می‌کنید، یا شبکه را خاموش کند. صدای شما اهمیت دارد. حریم خصوصی شما قابل مذاکره نیست.

پارولنت برای افرادی طراحی شده که در شرایط سانسور و نظارت زندگی می‌کنند. نیازی به شماره تلفن یا ایمیل برای ثبت‌نام نیست. ترافیک اینترنت شما دقیقاً مانند مرور عادی وب به نظر می‌رسد — چیزی برای مسدود کردن وجود ندارد چون چیزی قابل تشخیص نیست. حتی زمانی که اینترنت قطع شود، ارتباط بین دستگاه‌ها از طریق شبکه مش ادامه می‌یابد. اگر دستگاه شما مصادره شود، دکمه پاکسازی اضطراری تمام کلیدها و پیام‌ها را به‌طور امن از بین می‌برد.

### Kurdish (Kurmanji) / Kurdî
ParolNet nermalava belaş û çavkaniya vekirî ye ku mafê te yê danûstendinên taybet diparêze. Tu hukumet, pargîdanî an kesek nikare peyamên te bixwîne, bişopîne ku tu bi kê re diaxivî, an torê bigire. Dengê te girîng e. Nepenîtiya te nayê danûstandin.

ParolNet ji bo kesên ku di bin sansur û çavdêriyê de dijîn hatiye çêkirin. Ji bo tomarkirinê ne jimareya têlefonê û ne jî e-nameyek hewce ye. Seyrûsefera te ya înternetê wekî gerandina webê ya normal xuya dike. Tiştek tune ku were asteng kirin ji ber ku tiştek tune ku were nasîn. Dema ku înternet were qutkirin jî, pêwendiya di navbera amûran de bi tora mesh-ê didome.

### Azerbaijani / Azərbaycanca
ParolNet pulsuz və açıq mənbəli proqram təminatıdır ki, sizin şəxsi ünsiyyət hüququnuzu qoruyur. Heç bir hökumət, şirkət və ya şəxs mesajlarınızı oxuya, kiminlə danışdığınızı izləyə və ya şəbəkəni bağlaya bilməz. Səsiniz vacibdir. Məxfiliyiniz danışıq mövzusu deyil.

ParolNet senzura və nəzarət altında yaşayan insanlar üçün hazırlanıb. Qeydiyyat üçün telefon nömrəsi və ya e-poçt tələb olunmur. İnternet trafikiniz adi veb-baxışa bənzəyir — heç nə bloklanmır, çünki heç nə fərqləndirilə bilməz. İnternet kəsildikdə belə, cihazlar arası əlaqə mesh şəbəkə vasitəsilə davam edir.

### Arabic / العربية
بارولنت هو برنامج مجاني ومفتوح المصدر يحمي حقك في التواصل الخاص. لا يمكن لأي حكومة أو شركة أو فرد قراءة رسائلك أو تتبع من تتحدث إليه أو إغلاق الشبكة. صوتك مهم. خصوصيتك غير قابلة للتفاوض.

صُمم بارولنت للأشخاص الذين يعيشون في ظل الرقابة والمراقبة. لا حاجة لرقم هاتف أو بريد إلكتروني للتسجيل. تبدو حركة الإنترنت الخاصة بك مطابقة تماماً لتصفح الويب العادي — لا يوجد شيء يمكن حجبه لأنه لا يوجد شيء يمكن تمييزه. حتى عند قطع الإنترنت، يستمر التواصل بين الأجهزة عبر الشبكة المتداخلة. إذا تمت مصادرة جهازك، فإن زر المسح الطارئ يدمر جميع المفاتيح والرسائل بشكل آمن.

### Korean / 한국어
ParolNet은 사적인 통신에 대한 귀하의 권리를 보호하는 무료 오픈소스 소프트웨어입니다. 어떤 정부, 기업, 개인도 귀하의 메시지를 읽거나 누구와 대화하는지 추적하거나 네트워크를 차단할 수 없습니다. 귀하의 목소리는 중요합니다. 귀하의 프라이버시는 협상의 대상이 아닙니다.

ParolNet은 검열과 감시 환경에서 살아가는 사람들을 위해 설계되었습니다. 등록에 전화번호나 이메일이 필요하지 않습니다. 귀하의 인터넷 트래픽은 일반 웹 브라우징과 완전히 동일하게 보입니다 — 구별할 수 있는 것이 없기 때문에 차단할 수 있는 것도 없습니다. 인터넷이 차단되더라도 메시 네트워크를 통해 기기 간 통신이 계속됩니다. 기기가 압수되면 긴급 삭제 버튼이 모든 키와 메시지를 안전하게 파괴합니다.

### Turkish / Turkce
ParolNet, ozel iletisim hakkinizi koruyan ucretsiz ve acik kaynakli bir yazilimdir. Hicbir hukumet, sirket veya birey mesajlarinizi okuyamaz, kiminle konustugunuzu izleyemez veya agi kapatamaz. Sesiniz onemlidir. Gizliliginiz pazarlik konusu degildir.

ParolNet, sansur ve gozetim altinda yasayan insanlar icin tasarlanmistir. Kayit icin telefon numarasi veya e-posta gerekmez. Internet trafiginiz normal web taramasina benzer — engellenecek bir sey yoktur cunku ayirt edilecek bir sey yoktur. Internet kesildiginde bile, cihazlar arasi iletisim mesh agi uzerinden devam eder. Cihaziniz el konulursa, acil silme dugmesi tum anahtarlari ve mesajlari guvenli bir sekilde yok eder.

---

## Core Principles

- **Untrackable**: Traffic is indistinguishable from normal HTTPS browsing
- **Zero-trust**: Assume the network and all servers are compromised
- **Decentralized**: No single point of failure or control
- **Metadata-minimal**: Protect who talks to whom, not just content
- **No registration**: No phone, email, or username — identity is a cryptographic key
- **Offline-first**: Works in degraded network conditions via mesh networking
- **Open source**: Auditable, forkable, community-owned

## Architecture

```
                  +-----------------+
                  |  parolnet-core  |  Public API: bootstrap, send, recv, panic_wipe
                  +--------+--------+
                           |
          +----------------+----------------+
          |                |                |
+---------+--+  +----------+--+  +----------+--+
| parolnet-  |  | parolnet-   |  | parolnet-   |
| relay      |  | mesh        |  | wasm        |
| (onion     |  | (gossip,    |  | (browser    |
|  circuits) |  |  offline)   |  |  bindings)  |
+-----+------+  +------+------+  +------+------+
      |                |                |
+-----+----------------+------+        |
|    parolnet-transport       |        |
|    (TLS, WebSocket, DPI     |        |
|     evasion, traffic shape) |        |
+-------------+---------------+        |
              |                        |
      +-------+--------+      +-------+------+
      | parolnet-       |      | parolnet-    |
      | protocol        +------+ crypto       |
      | (wire format,   |      | (X3DH, DR,   |
      |  envelope, CBOR)|      |  AEAD, KDF)  |
      +-----------------+      +--------------+
```

## Protocol Specifications

Six formal RFC-style protocol specifications define the system:

| Spec | Name | Purpose |
|------|------|---------|
| [PNP-001](specs/PNP-001-wire-protocol.md) | Wire Protocol | Envelope format, bucket padding, message types |
| [PNP-002](specs/PNP-002-handshake-protocol.md) | Handshake Protocol | X3DH key agreement, Double Ratchet initialization |
| [PNP-003](specs/PNP-003-bootstrap-protocol.md) | Bootstrap Protocol | QR code / passphrase peer introduction, zero breadcrumbs |
| [PNP-004](specs/PNP-004-relay-circuit.md) | Relay Circuit Protocol | 3-hop onion routing, 512-byte fixed cells |
| [PNP-005](specs/PNP-005-gossip-mesh.md) | Gossip/Mesh Protocol | Epidemic propagation, store-and-forward, PoW anti-spam |
| [PNP-006](specs/PNP-006-traffic-shaping.md) | Traffic Shaping Protocol | DPI evasion, TLS fingerprint mimicry, constant-rate padding |

## Tech Stack

- **Language**: Rust (2024 edition, memory-safe, no runtime)
- **Crypto**: x25519-dalek, ed25519-dalek, ChaCha20-Poly1305, HKDF-SHA-256
- **Transport**: Custom TLS over rustls (no QUIC — maximum fingerprint control)
- **Serialization**: CBOR (RFC 8949) via ciborium
- **Async**: tokio
- **WASM**: wasm-bindgen for browser PWA delivery
- **Relay**: Built-in WebTorrent tracker for WebRTC peer discovery
- **Storage**: AES-256-GCM encrypted IndexedDB with PBKDF2 key derivation
- **License**: MIT OR Apache-2.0

## Building

```bash
# Check all crates compile
cargo check --workspace

# Run tests
cargo test --workspace

# Build WASM bindings
wasm-pack build crates/parolnet-wasm

# Generate documentation
cargo doc --workspace --no-deps --open
```

## Development

### Full deploy (relay server + PWA)

```bash
./deploy.sh        # Builds WASM, compiles relay, rebuilds Docker image, restarts container
```

### Live PWA development

For iterating on the PWA without rebuilding the Docker container:

```bash
# 1. Deploy once to get the container running
./deploy.sh

# 2. Restart with volume mounts (docker-compose.override.yml binds ./pwa into the container)
docker compose down && docker compose up -d

# 3. Edit HTML/CSS/JS files — refresh browser to see changes instantly

# 4. If you change Rust/WASM code:
./build.sh          # Rebuilds WASM only, no Docker rebuild
```

The `docker-compose.override.yml` file bind-mounts `./pwa` into the running nginx container. It's gitignored and created automatically — remove it when you want production behavior.

## Security Model

### What observers see
To a passive network observer (ISP, national firewall), ParolNet traffic appears as a user maintaining HTTPS/2 connections to CDN-hosted websites with normal browsing patterns.

### What observers cannot determine
- That the traffic is ParolNet rather than web browsing
- The identity of communicating parties
- Message content
- Which traffic is real vs. cover traffic

### Threat model
- Assumes network is fully compromised (DPI, traffic analysis)
- Assumes any individual relay may be compromised (zero-trust)
- Protects against: censorship, surveillance, metadata collection, device seizure (panic wipe + encrypted storage)
- Does NOT protect against: global passive adversary with simultaneous control of all relay hops

## Project Status

**Phase**: Core implementation complete. Crypto primitives (X3DH, Double Ratchet, AEAD), wire format, transport layer, onion routing, gossip mesh, and relay server all implemented with 390+ tests passing. PWA with offline support, encrypted local storage, and decoy mode deployed.

See [ROADMAP.md](ROADMAP.md) for the full development plan.
See [STRATEGIES.md](STRATEGIES.md) for the adoption and distribution strategy.
