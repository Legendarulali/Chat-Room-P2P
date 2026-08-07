# EnDa Chat

Ephemeral, end-to-end encrypted, peer-to-peer chat rooms. Text, files, and voice
go browser to browser. The server helps two browsers find each other and then
has no further part in the conversation.

No accounts, no database, no history. A room exists while people are in it and
stops existing when they leave.

```
        ┌──────────┐   SDP / ICE only    ┌──────────┐
        │ browser  │◄───────────────────►│  relay   │
        │  (peer)  │                     │ FastAPI  │
        └────┬─────┘                     └────┬─────┘
             │                                │  ▲
             │   DTLS + AES-GCM-256           │  └── in-memory dict,
             │   text · files · voice         │      deleted when empty
             │        (server is not here)    │
        ┌────▼─────┐   SDP / ICE only         │
        │ browser  │◄─────────────────────────┘
        │  (peer)  │
        └──────────┘
```

---

## Run it

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m server.main
```

Open <http://127.0.0.1:8000>. To talk to yourself, open it in two tabs and enter
the same room name and passkey in both.

Environment variables:

| Variable            | Default     | Meaning                                            |
| ------------------- | ----------- | -------------------------------------------------- |
| `ENDA_HOST`         | `127.0.0.1` | Bind address. Use `0.0.0.0` to serve a LAN.         |
| `ENDA_PORT`         | `8000`      | Port.                                              |
| `ENDA_DEBUG_STATS`  | unset       | `1` exposes `/api/debug/stats`. Development only.   |

### Web Crypto needs a secure context

Browsers only expose `crypto.subtle` on a secure origin. `http://127.0.0.1` and
`http://localhost` count, so local development works as-is. **A plain-http LAN
address does not** — open `http://192.168.1.20:8000` and the app will refuse to
start rather than pretend to encrypt. For anything beyond localhost, put it
behind HTTPS:

```
# Caddyfile — terminates TLS and forwards websockets untouched
chat.example.com {
    reverse_proxy 127.0.0.1:8000
    log {
        output discard      # otherwise your reverse proxy keeps the log this app refuses to
    }
}
```

---

## Layout

```
server/main.py            the entire server (~330 lines)
client/index.html         markup, design tokens, component CSS
client/app.js             crypto, mesh, protocol, audio, UI
tests/signaling_test.py   black-box checks against a running relay
tests/browser_e2e_test.py two headless browsers, driven over DevTools Protocol
legacy/                   the 2022-2023 prototype this replaced, kept intact
```

No npm, no bundler, no build step. The client uses WebRTC, Web Crypto, and the
DOM directly; the only runtime dependency it pulls is Tailwind, from a CDN
(see [Removing the CDN](#removing-the-cdn)).

---

## The key schedule

```
passkey ──PBKDF2-SHA256, 600 000 iters, salt = SHA256("endachat/v1|room|" + roomName)──► master (256 bit)

master ──HKDF-SHA256, info "endachat/v1/aes-gcm"──► AES-GCM-256 key   (non-extractable)
       ──HKDF-SHA256, info "endachat/v1/room-id"──► 32 bytes → hex    (sent to the relay)
       ──HKDF-SHA256, info "endachat/v1/seal"───► 16 bytes            (the visible seal)
```

One expensive PBKDF2 pass, then three cheap domain-separated HKDF expansions.
Design notes, in order of how much they matter:

- **The AES key is non-extractable.** It comes from `deriveKey(..., extractable=false, ...)`,
  so its bytes never exist in any JavaScript-reachable object. `exportKey` on it
  throws. That is a stronger position than deriving raw bytes and trying to be
  careful with them.
- **The master secret exists in exactly one place, briefly.** `deriveBits`
  returns a `Uint8Array`; it is passed straight to `importKey` and then
  zero-filled on the next line.
- **Publishing the room id is safe.** The id and the key come from the same
  master under different HKDF `info` strings, so the id is independent of the
  key. Handing the relay a room id tells it nothing about how to decrypt.
- **The salt is deterministic**, derived from the room name, because peers who
  share only a name and a passkey have no channel to agree on a random salt.
  The cost is that identical passkeys in identically-named rooms derive
  identical keys, and that a precomputation attack against a *known* room name
  is possible. 600 000 iterations is the mitigation. Use a passkey with real
  entropy — this is a shared secret, not a login password.

### Message format

```
plaintext frame   [type:1][metaLen:2 BE][meta JSON][payload bytes]
sealed frame      [ver:1][iv:12][AES-GCM ciphertext ‖ 128-bit tag]
```

A fresh random 96-bit IV per frame. Random GCM nonces stay comfortable below
about 2³² frames on one key; at the 16 KiB chunk size that is roughly 64 TiB,
and a key never outlives its room.

### Why encrypt inside DTLS at all

WebRTC already encrypts every hop with DTLS-SRTP, and in a full mesh every hop
is peer to peer, so the relay is already outside the data path. The AES-GCM
layer buys two specific things:

1. **It defeats a malicious relay.** The relay forwards the SDP that carries
   DTLS fingerprints. A hostile one could substitute its own, terminate DTLS on
   both sides, and read everything. It cannot forge the room key, so with this
   layer it gets ciphertext.
2. **It is the admission check.** There is no membership list. A peer proves it
   belongs by sending a frame the others can decrypt; a peer whose first frame
   fails to decrypt is disconnected. Knowing the passkey *is* membership.

### Verify with the session seal

Each room renders a 4×4 mark and a 64-bit code, both derived from the master
secret. Everyone who derived the same key sees the same mark and code.

Read the code aloud. **If it matches, no one is in the middle.** This is the
out-of-band check that closes threat 1 above — the relay can lie about
fingerprints, but it cannot make two different keys produce one code.

---

## Zero-log guarantees

What the server enforces, and how you can confirm it:

| Claim | Mechanism | Check |
| --- | --- | --- |
| No request logging | `logging.disable()`, every uvicorn/starlette/websockets logger detached, `access_log=False`, `log_config=None` | Run the relay with stdout piped to a file. After any amount of traffic it contains only the 3-line startup banner. |
| No database, no files | There is no storage code. The only session state is one `dict`. | `grep -rE "open\(|sqlite|write|Path\(" server/main.py` |
| Rooms die when empty | `Rooms.leave` does `del self._rooms[room_id]` on the last departure | `tests/signaling_test.py` asserts it against `/api/debug/stats` |
| Server never sees room names | It rejects anything that is not 64 lowercase hex, so a plaintext name cannot even be submitted | `tests/signaling_test.py` tries five malformed ids |
| Server never sees messages | Payloads are relayed as opaque JSON; chat never touches the relay at all | `tests/signaling_test.py` asserts byte-identical relay |
| Health endpoint leaks nothing | Returns `{"ok": true}` — deliberately not a room count, which would itself be metadata | `tests/signaling_test.py` |
| Client stores nothing | No `localStorage`, `sessionStorage`, `indexedDB`, `caches`, or `document.cookie` anywhere | `tests/signaling_test.py` greps the served `app.js` for API *use* |

On the client: received files are `Blob`s in memory, their object URLs revoked
on leave; the chat log is DOM only; leaving clears the log, stops every track,
closes the `AudioContext`, and drops the key handle.

**On "keys discarded":** leaving drops the `CryptoKey` reference so it becomes
unreachable and collectable. Because the key was created non-extractable, its
raw bytes were never in JavaScript memory, so there is nothing a zero-fill
could reach. JavaScript cannot order the browser to scrub its own key store.
What it can do is never hold the material and stop referring to the handle,
which is what happens.

---

## What this does not protect against

Read this part. Every one of these is a real limitation, not a hypothetical.

**Peers learn each other's IP addresses.** This is inherent to peer-to-peer:
direct connections are exactly what keeps the server out of your conversation,
and the cost is that the people in your room see your address. Encryption does
not change it. Routing through a TURN relay would hide peers from each other,
but it hands both addresses to the relay operator instead — a different trust
assumption, not a smaller one. This app ships with STUN only and discloses IP
visibility on the join screen. The transport panel shows `direct` or `relayed`
so you always know which you got.

**The relay sees metadata.** Even knowing nothing about content, it observes:
which IPs connected, when, how long they stayed, which opaque room id they
grouped under, and how many peers were in each group. Room names and passkeys
are never on the wire; the pattern of connections is.

**A shared room key authenticates membership, not individuals.** Everyone in the
room holds the same key, so any member can send a frame claiming any display
name. It is not possible to prove *which* member sent a message. Fixing this
needs per-peer signing keys, which is not implemented. Treat display names as a
convenience among people who already trust each other.

**The browser is not a clean room.** `chrome://webrtc-internals` records SDP and
connection stats locally, DevTools can inspect a live page, and OS memory can be
paged to disk. The app avoids every storage API and sets `no-store` and a strict
CSP, but "nothing is retained" is a server-side guarantee and a client-side
best effort.

**Eight peers, maximum.** In a full mesh each peer uploads its audio to every
other peer, so upload and CPU cost grow with N. Past about eight, voice
degrades. The server enforces the cap and refuses a ninth peer. Raising it means
introducing an SFU, which puts a server back in the media path and gives up the
architecture's main property. Text and files scale much further; the cap exists
for voice.

**No forward secrecy across a passkey's life.** The room key is a pure function
of room name and passkey. Anyone who learns the passkey and captured earlier
ciphertext can decrypt it. Rotate by changing the passkey, which creates a
different room.

**Denial of service is out of scope.** The relay caps peers per room, frame
size, and per-connection message rate, and never allocates on behalf of an
unjoined socket. It is not hardened against a distributed flood; put it behind
something that is.

---

## Removing the CDN

The one third-party request this page makes is Tailwind, from
`cdn.tailwindcss.com`. That host learns your IP and that you loaded the page —
not who you spoke to or anything you said. It is still the weakest point in an
otherwise self-contained app, and it is why the CSP has to allow an external
script host and `'unsafe-inline'`.

To close it:

1. Build the stylesheet once and drop it in `client/`:
   ```
   npx tailwindcss@3 -i input.css -o client/tailwind.css --minify
   ```
2. In `client/index.html`, replace the CDN `<script>` and its `tailwind.config`
   block with `<link rel="stylesheet" href="tailwind.css">`.
3. In `server/main.py`, tighten `CSP` to:
   ```python
   "default-src 'self'", "script-src 'self'", "style-src 'self'", ...
   ```
   Dropping `'unsafe-inline'` from `script-src` and the external host is the
   actual win here.

The design deliberately uses no webfonts for the same reason — a font CDN would
be a second host learning the same thing. Type is set in system faces
(Segoe UI Variable and Cascadia Mono on Windows 11) and given its character
through scale, weight, and tracking instead.

---

## Tests

Both suites run against a live relay. Start it first:

```powershell
$env:ENDA_DEBUG_STATS = "1"
.venv\Scripts\python.exe -m server.main
```

```powershell
# 50 assertions: protocol, validation, isolation, peer cap, room deletion,
# rate limiting, security headers, zero-storage grep
.venv\Scripts\python.exe tests\signaling_test.py

# 40 assertions in two real headless browsers: key agreement, mesh formation,
# encrypted chat, file integrity, voice tracks, mute/deafen, teardown
.venv\Scripts\python.exe tests\browser_e2e_test.py
```

`browser_e2e_test.py` finds Chrome or Edge on its own and drives it over the
DevTools Protocol — no extension or driver binary needed. It uses a synthetic
capture device, so it exercises the real voice path without a microphone or a
permission prompt. If no browser is found it skips rather than fails.

---

## Protocol reference

Client → relay:

| Message | Meaning |
| --- | --- |
| `{"type":"join","room":"<64 hex>"}` | Enter a room. Answered with `welcome` or `error`. |
| `{"type":"signal","to":"<peerId>","data":{…}}` | Relay `data` verbatim to one peer in your room. |
| `{"type":"leave"}` | Disconnect. |
| `{"type":"ping"}` | Answered with `pong`. |

Relay → client:

| Message | Meaning |
| --- | --- |
| `{"type":"welcome","peerId","peers":[…],"limit":8}` | Admitted. `peers` lists who was already there. |
| `{"type":"peer-join","peerId"}` | Someone arrived. |
| `{"type":"peer-leave","peerId"}` | Someone left. |
| `{"type":"signal","from":"<peerId>","data":{…}}` | A relayed payload. |
| `{"type":"error","code":"…"}` | `bad_room_id`, `room_full`, `not_joined`, `already_joined`, `no_such_peer`, `bad_json`, `bad_request`, `unknown_type`, `frame_too_large`, `rate_limited`. |

Inside `data`, peers exchange `{"kind":"desc","description":{…}}` and
`{"kind":"ice","candidate":{…}}`. The relay does not parse either.

Peer negotiation follows the WebRTC spec's perfect-negotiation pattern. The
lexicographically smaller peer id opens the DataChannel and offers first; the
larger is the polite side and rolls back on collision. An audio transceiver is
created up front, so enabling a microphone later or muting never requires
renegotiation.

---

## License

MIT — see [License](License).
