<div align="center">

# ⚡ ChaosChat

Theme B Screenshot (Needs theme work still):
![ImageA](./Screenshot%20from%202026-04-03%2012-41-30.png)
![ImageB](./Screenshot%20from%202026-04-03%2012-35-43.png)


**Cryptographic peer-to-peer chat. No servers. No accounts. No traces(?)**

![C](https://img.shields.io/badge/Language-C11-blue?style=flat-square&logo=c)
![GTK3](https://img.shields.io/badge/GUI-GTK3-green?style=flat-square)
![OpenSSL](https://img.shields.io/badge/Crypto-OpenSSL-red?style=flat-square&logo=openssl)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat-square&logo=linux)

*Messages dissolved into cryptographic noise. Invisible unless you hold the key.*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
  - [Connection & Setup](#connection--setup)
  - [X25519 Handshake — Perfect Forward Secrecy](#x25519-handshake--perfect-forward-secrecy)
  - [The SHA-256 Ratchet](#the-sha-256-ratchet)
  - [The ChaCha20 Noise Stream](#the-chacha20-noise-stream)
  - [Message Encryption — AES-256-CTR](#message-encryption--aes-256-ctr)
  - [Message Reception & Extraction](#message-reception--extraction)
  - [Replay Protection](#replay-protection)
  - [The Display](#the-display)
- [Security Stack](#security-stack)
- [Build](#build)
- [Honest Limitations](#honest-limitations)

---

## Overview

ChaosChat is a direct **peer-to-peer encrypted chat application** written in C with a GTK3 graphical interface. It requires no servers, no accounts, no cloud infrastructure, and no third-party services of any kind.

Two instances of the binary connect directly over a raw TCP socket and communicate through a **continuous cryptographic noise stream**. Messages are invisible inside that stream unless you hold the correct shared key and have observed the stream from the beginning.

```
┌──────────────────────────────────────────────────────────────────────┐
│  zF2jd69Xj...⚡TAG⚡...qLi7XPgC8v...⚡TAG⚡...O08MWsA/Lp...          │
│                  ↑                      ↑                            │
│             Alice → Bob            Bob → Alice                       │
│           (AES-256-CTR)           (AES-256-CTR)                      │
│                                                                      │
│  Everything else: ChaCha20 keystream encoded as base64               │
│  Passive observers see: HTTP traffic                                 │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Dependencies

```bash
# Debian / Ubuntu
sudo apt install libgtk-3-dev libssl-dev build-essential

# Arch
sudo pacman -S gtk3 openssl base-devel

# Fedora / RHEL
sudo dnf install gtk3-devel openssl-devel gcc make
```

### Build

```bash
make
```

### Run — Two Terminals (or Two Machines)

**Peer A — listen side:**
```
Port:       5050
Connect To: (leave blank)
Chat Key:   KKs245ff*
Username:   Alice
```

**Peer B — connecting side:**
```
Port:       5051
Connect To: 192.168.1.x:5050
Chat Key:   KKs245ff*
Username:   Bob
```

> [!IMPORTANT]
> The **Chat Key** must match exactly on both sides. Exchange it securely out-of-band — in person, by phone, or via a separate trusted channel.

Both peers bind to their chosen **My Port** — including the connecting side. A passive `tcpdump` or `ss` observer will see both chosen ports, not a random OS-assigned ephemeral port on one side.

---

## How It Works

### Connection & Setup

When launched, each user fills in four fields:

| Field | Description |
|---|---|
| **My Port** | Local TCP port to bind on — used by both listener and connector |
| **Connect To** | Peer's `IP:port` — leave blank to wait for incoming connection |
| **Chat Key** | Shared secret, must match exactly on both sides |
| **Username** | Display name, sent encrypted inside each message. Defaults to `"User"` |

One peer leaves *Connect To* blank and clicks **Connect / Listen** — the application binds the port and waits. The other peer fills in the first peer's address and clicks **Connect** — a standard TCP connection is established. From this point both sides are equal participants. The server/client distinction only determines who initiates the cryptographic handshake.

---

### X25519 Handshake — Perfect Forward Secrecy

Before the noise stream starts, the two peers perform a cryptographic handshake over the raw TCP socket. This happens in the background while the spinner is showing.

```
Alice                                          Bob
  │                                             │
  │── [X25519 ephemeral public key] ──────────► │
  │◄─ [X25519 ephemeral public key] ────────── │
  │                                             │
  │  ECDH(alice_priv, bob_pub)    ECDH(bob_priv, alice_pub)
  │        └─────────────────────────────────────┘
  │                    shared_secret (identical)
  │                           │
  │         master_seed = HMAC-SHA256(shared_secret, chat_key)
  │                           │
  │              ┌────────────┴────────────┐
  │          TX Ratchet                RX Ratchet
  │         (seeded from master_seed)
```

1. Each side independently generates a fresh **X25519 ephemeral keypair**
2. Public keys are exchanged over the socket
3. Each side performs **ECDH key derivation** — the same 32-byte shared secret is produced on both sides without it ever being transmitted
4. The shared secret is passed through **HMAC-SHA256** keyed with the chat key: `master_seed = HMAC-SHA256(key=shared_secret, data=chat_key)`
5. The master seed initialises both ratchets

**The forward secrecy guarantee:** The ephemeral X25519 keypairs are generated fresh for every connection and discarded immediately. If someone records an entire session and later obtains the chat key, they still cannot derive the master seed because the private keys no longer exist anywhere.

---

### The SHA-256 Ratchet

Both peers maintain **two ratchet states** — one for their transmit direction, one for receive — both seeded from the master seed. Each ratchet state holds:

| Field | Size | Purpose |
|---|---|---|
| `current_key` | 32 bytes | AES-256 encryption key + tag source |
| `hex_tag` | 64 chars | Hex representation of `current_key`, used as stream search tag |
| `bytes_processed` | `size_t` | Bytes fed into the current 16KB window |
| `chaff_step_buf` | 16,384 bytes | Rolling accumulator of stream data |

Every byte that travels over the wire — noise, tags, payloads, everything — is fed into the appropriate ratchet buffer. When the buffer reaches **16,384 bytes**, the ratchet evolves:

```
new_key = SHA256(current_key || 16384_bytes_of_stream_data)
```

The new key replaces the old one, the hex tag updates, and the buffer resets. Because **TCP guarantees ordered, lossless delivery**, A's transmit ratchet and B's receive ratchet are fed identical data — they evolve to the same state at the same moment, with zero synchronisation messages.

> At the current stream rate, the ratchet evolves approximately **once per second** — the AES-256 key and the 64-char stream tag rotate roughly every second.

---

### The ChaCha20 Noise Stream

The send thread runs continuously for the lifetime of the connection, firing approximately every **30 milliseconds** with deliberate timing jitter.

```c
// One-time setup before the loop:
RAND_bytes(chacha_key, 32);   // OS entropy — getrandom() on Linux
RAND_bytes(chacha_iv,  16);
EVP_CIPHER_CTX *noise_ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(noise_ctx, EVP_chacha20(), NULL, chacha_key, chacha_iv);

// Each tick — continue the stream, never reset:
EVP_EncryptUpdate(noise_ctx, noise_bytes, &outlen, zeros, chunk_size);

// Map bytes → base64 via lookup table:
chunk[i] = B64_CHARS[noise_bytes[i] & 63];
```

The ChaCha20 context is created **once** and lives for the entire session. Each `EVP_EncryptUpdate` call continues the keystream from where the last one ended — the entire session's background noise is **one infinite non-repeating cryptographic stream**.

The keystream bytes are mapped to the standard base64 alphabet (`A-Z`, `a-z`, `0-9`, `+`, `/`). This means the wire traffic is statistically indistinguishable from base64-encoded binary data — the kind produced by TLS sessions and websocket connections. A passive `tcpdump` observer classifies the stream as **HTTP**.

Timing and volume are further obscured by two jitter mechanisms:

| Property | Value |
|---|---|
| Base interval | 30 ms |
| Timing jitter | ±5 ms per tick (from `RAND_bytes`) |
| Base chunk size | 512 bytes |
| Chunk size jitter | ±64 bytes per tick (from `RAND_bytes`) |

| Property | `rand()` (old) | ChaCha20 (current) |
|---|---|---|
| Algorithm | Linear congruential | Stream cipher |
| Period | Short, predictable | 2^64 blocks |
| Distinguishable from random? | Yes | No |
| Seeding | `time(NULL)` | OS entropy pool |
| Wire appearance | Uppercase hex | Base64 / HTTP |

The ChaCha20 key and nonce are **local only** — never sent over the wire. The receiver ignores all noise and only scans for message tags.

---

### Message Encryption — AES-256-CTR

When a message is sent, the entire process happens locally before any bytes leave the machine:

#### Step 1 — Assemble Payload

```
Alice\x1FHello there
└───┘ └─┘ └─────────┘
 name  ↑    body
  Unit Separator (0x1F)
  Non-typeable, unambiguous
```

The username and message body are joined with `\x1F` (ASCII Unit Separator) into a single buffer and treated as one unit. The username encrypts alongside the body — **it is never visible in the stream in any form**.

#### Step 2 — Derive a Unique IV

```
IV = first 16 bytes of SHA256(ratchet_key || seq_as_4_bytes_big_endian)
```

The sequence number is monotonically increasing and embedded in the tag. Both sides derive the identical IV independently — no additional exchange needed.

#### Step 3 — AES-256-CTR Encryption

```
ciphertext = AES-256-CTR(key=ratchet_key, iv=derived_iv, plaintext=payload)
```

CTR mode generates a keystream by encrypting successive counter values, then XORs against the plaintext. Even identical messages produce completely different ciphertext because the seq changes the IV which changes the entire keystream. **Encryption and decryption are the same operation.**

#### Step 4 — Encode & Embed

The encrypted bytes are hex-encoded and stamped with a fixed-width tag — **no delimiters, no separators**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  64-char ratchet tag  │  8-char seq  │  8-char length  │  hex payload  │
│  (SHA256 of key, hex) │  (hex, zero- │  (hex, zero-    │  (AES-256-CTR │
│                       │   padded)    │   padded)        │   encrypted)  │
└─────────────────────────────────────────────────────────────────────────┘
```

The tag characters (`0-9`, `A-F`) are a valid subset of the base64 alphabet, so the embedded message is visually indistinguishable from surrounding noise.

All fields are fixed width — parsing requires no delimiter searching and field boundary collision is **mathematically impossible** regardless of content.

---

### Message Reception & Extraction

The receive thread maintains a **512KB rolling buffer**. After every network read:

1. Incoming bytes are fed into the **rx ratchet**
2. Bytes are appended to the rolling buffer
3. `scan_and_consume` is called

The scanner uses `memmem` to search for the current 64-char ratchet tag. On a match:

```
Buffer: ...zF2jd69X...⟨TAG⟩⟨SEQ⟩⟨LEN⟩⟨ENCRYPTED_HEX_PAYLOAD⟩...qLi7XPg...
                       ↑
                     Found!
                       │
                       ├─ Check seq against dedup table → already seen? Discard.
                       ├─ Hex-decode payload → binary ciphertext
                       ├─ AES-256-CTR decrypt (same key+IV derivation as sender)
                       ├─ memchr('\x1F') → split into peer_name + body
                       ├─ First message? Store peer_name, update header bar
                       ├─ Post message to GTK display thread
                       └─ memmove() — erase tag+payload from buffer. Gone.
```

> Messages lost in a trimmed buffer window are **gone permanently** — no retransmission, no history, no persistence anywhere.

---

### Replay Protection

Every message carries a monotonically increasing sequence number. The receiver maintains a table of up to **65,536 previously seen sequence numbers**. Any duplicate arrival is silently discarded.

Because CTR mode produces a unique ciphertext for every seq value, replaying a captured block with a modified seq would produce garbage on decryption — the IV is derived from seq, so the keystream would be completely different.

---

### The Display

- **Cyan** — your own messages
- **Red-pink** — peer's messages
- **Dim italic** — system events (connected, ratchet seeded, peer disconnected)
- **Timestamps** — `[HH:MM]` prefix on every message

Colouring is driven by an `is_self` boolean on the message struct — not by comparing usernames — so it works correctly regardless of what either party calls themselves.

The **header bar** transitions as the session progresses:

```
Before first peer message:
  ⚡ Alice · port: 5050 · key: KKs245ff* · listening

After first peer message arrives:
  ⚡ Alice ↔ Bob · port: 5050 · key: KKs245ff*
```

---

## Security Stack

| Layer | Mechanism | Strength |
|---|---|---|
| **Key exchange** | X25519 ECDH + HMAC-SHA256 | 128-bit equivalent, full PFS |
| **Message encryption** | AES-256-CTR | 256-bit, unique IV per message |
| **IV uniqueness** | SHA256(ratchet\_key \|\| seq) | Cannot repeat within a session |
| **Key rotation** | SHA-256 ratchet, every 16 KB | New key ~every 1 second |
| **Tag rotation** | Derived from ratchet key | Rotates with key, ~every 1 second |
| **Noise generation** | ChaCha20 via OpenSSL EVP | Infinite non-repeating keystream |
| **Noise seeding** | `RAND_bytes` → `getrandom()` | OS entropy pool |
| **Traffic camouflage** | Base64 encoding of keystream | Classified as HTTP by passive observers |
| **Timing camouflage** | ±5 ms jitter per tick | Breaks automated timing fingerprints |
| **Volume camouflage** | ±64 byte chunk size jitter | No fixed bitrate fingerprint |
| **Port visibility** | Both peers bind chosen port | No OS-assigned ephemeral ports |
| **Replay protection** | Seq dedup table, 65,536 entries | Per-session |
| **Username privacy** | Encrypted with message body | Never in plaintext on the wire |

---

## Build

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install libgtk-3-dev libssl-dev build-essential

# Build
make

# Manual compile
gcc -D_GNU_SOURCE -Wall -Wextra -O2 chaoschat.c \
    $(pkg-config --cflags --libs gtk+-3.0) \
    -lpthread -lcrypto -o chaoschat
```

---

## Honest Limitations

> These are not bugs — they are architectural decisions worth understanding.

**The chat key is a pre-shared secret.**
It must be exchanged out-of-band before connecting. There is no public key infrastructure, no certificate authority, and no way to cryptographically verify the peer's identity beyond the fact that they knew the chat key. A man-in-the-middle who intercepts the TCP connection *before the handshake completes* and who also knows the chat key could relay and read traffic.

**The ratchet does not re-seed from message content.**
It advances strictly on stream volume. This is not a Double Ratchet (as used in Signal) — it does not provide the break-in recovery property where a compromised session key heals itself after future messages. Forward secrecy here comes from the X25519 handshake only, not from ongoing message exchange.

**The "one-shot" session.**
The ratchet's synchronisation depends on every byte being observed in order from the start. A dropped connection cannot be resumed — both sides must reconnect and perform a fresh handshake, generating a new master seed. Any traffic captured from the dead session becomes permanently undecipherable, even to the original participants.

**No message history.**
There is no log file, no persistent storage, no way to recover a message after it has been extracted from the buffer and displayed. This is a feature by design.

**TCP only.**
The ratchet synchronisation mechanism depends entirely on TCP's guarantee of ordered, lossless delivery. The design cannot be ported to UDP without replacing the ratchet synchronisation entirely.

---

<div align="center">

*Built with C11 · GTK3 · OpenSSL · pthreads*

</div>
