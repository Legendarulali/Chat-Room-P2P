# Chat Room P2P

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

| Variable | Default | Meaning |
| --- | --- | --- |
| `HOST` | `127.0.0.1`, or `0.0.0.0` when `RENDER_EXTERNAL_URL` is set | Bind address. Loopback locally so a dev server is not exposed by accident; all interfaces behind a platform router, where loopback would make the service unreachable. |
| `PORT` | `8000` | Port. Most platforms inject this. |
| `DEBUG_STATS` | unset | `1` exposes `/api/debug/stats`. Development only. |
| `RENDER_EXTERNAL_URL` | unset | Public base URL. Sets the keep-alive target and flips the `HOST` default. Render exports it automatically; anywhere else, set it by hand. |
| `DISCORD_WEBHOOK_URL` | unset | If set, keep-alive notices are posted to Discord. **This is the one thing that sends data off the machine** — see [below](#the-keep-alive-loop-is-the-one-thing-that-phones-home). |
| `KEEPALIVE_INTERVAL_SECONDS` | `600` | Seconds between self-pings. Mainly a testing hook. |
| `EXTRA_CONNECT_SRC` | unset | Extra origins appended to this server's `connect-src`. Needed only when this server serves the page but the client signals to a different relay. |
| `CAPACITY_CEILING` | `16` | Hard cap on what a host may set. Capacity comes from a client, so this is the bound that keeps it from being unlimited. |

Note that `HOST` and `PORT` are deliberately unprefixed, which makes them
generic: an unrelated `PORT` already exported in your shell will change the bind
port. That is usually what you want on a hosting platform and occasionally a
surprise locally.

### Endpoints

| Route | Purpose |
| --- | --- |
| `GET /health` | `{"status": "ok", "timestamp": "…"}`. For platform health checks and the keep-alive loop. Status and clock only. |
| `GET /api/health` | `{"ok": true}`. Older liveness probe, kept for the test suite. |
| `GET /api/debug/stats` | Room and peer counts. Only mounted when `DEBUG_STATS=1`. |
| `WS /ws` | Signaling. See [Protocol reference](#protocol-reference). |

### Split deployment: static frontend, separate relay

The default assumption is that the relay serves the page, so the client derives
its websocket address from `location.host`. Put the page on a static host and
that assumption breaks: Vercel has no `/ws`, so the client tries
`wss://your-project.vercel.app/ws` and nothing connects.

**One line fixes it.** In `client/index.html`, uncomment and set:

```js
window.SIGNALING_URL = 'wss://chat-room-p2p.onrender.com/ws';
```

Accepted forms — the scheme and `/ws` are filled in when omitted:

| You write | Resolves to |
| --- | --- |
| `wss://relay.example.com/ws` | unchanged |
| `wss://relay.example.com` | `wss://relay.example.com/ws` |
| `relay.example.com` | `wss://relay.example.com/ws` (on an https page) |
| `https://relay.example.com` | `wss://relay.example.com/ws` |

Leave it unset and the client falls back to `FALLBACK_SIGNALING_URL` in
`app.js` whenever the page is on a recognised static host (`*.vercel.app`,
`*.netlify.app`, `*.github.io`, `*.pages.dev`, `*.surge.sh`). Local development
is unaffected either way, since `127.0.0.1` is not one of those.

The room's transport panel shows which relay is in use, with a `*` when it is
not the page's own origin.

#### The part that is easy to miss

**`connect-src` has to allow the relay's origin, and the CSP comes from whoever
serves the page — not from the relay.** Vercel would otherwise send no security
headers at all, so `vercel.json` in the repo root reproduces every header
`server/main.py` sets, with the relay added to `connect-src`:

```
connect-src 'self' wss://chat-room-p2p.onrender.com
```

Change that host when you change `SIGNALING_URL`, or the browser refuses the
socket and reports it only to the console. Vercel also needs its **Output
Directory** set to `client` — `vercel.json` declares it, but check the project
settings if you get a 404.

The reverse case: if the *relay* serves the page while the client points
somewhere else, set `EXTRA_CONNECT_SRC="wss://other-relay.example.com"` so the
relay's own CSP allows it.

Note that WebSocket handshakes are not subject to CORS, so nothing extra is
needed there — cross-origin signaling works without it.

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
server/main.py            the entire server (~900 lines, ~40% comment)
client/index.html         markup, design tokens, component CSS
client/app.js             crypto, mesh, protocol, audio, UI (~2500 lines)
tests/signaling_test.py   black-box checks against a running relay
tests/browser_e2e_test.py two headless browsers, driven over DevTools Protocol
tests/keepalive_test.py   the self-ping loop and its Discord notice
vercel.json               static-host headers for a split deployment
```

No npm, no bundler, no build step. The client uses WebRTC, Web Crypto, and the
DOM directly; the only runtime dependency it pulls is Tailwind, from a CDN
(see [Removing the CDN](#removing-the-cdn)).

---

## The key schedule

```
passkey ──PBKDF2-SHA256, 600 000 iters, salt = SHA256("chatroom-p2p/v1|room|" + roomName)──► master (256 bit)

master ──HKDF-SHA256, info "chatroom-p2p/v1/aes-gcm"──► AES-GCM-256 key   (non-extractable)
       ──HKDF-SHA256, info "chatroom-p2p/v1/room-id"──► 32 bytes → hex    (sent to the relay)
       ──HKDF-SHA256, info "chatroom-p2p/v1/seal"───► 16 bytes            (the visible seal)
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
| No request logging | `logging.disable()`, every uvicorn/starlette/websockets logger detached, `access_log=False`, `log_config=None` | Run the relay with stdout piped to a file. After any amount of traffic it still contains only the startup banner — 3 lines, up to 6 when the keep-alive, Discord, and CORS notices apply. `tests/keepalive_test.py` asserts the loop adds no per-ping output. |
| No database, no files | There is no storage code. The only session state is one `dict`. | `grep -rE "open\(|sqlite|write|Path\(" server/main.py` |
| Rooms die when empty | `Rooms.leave` does `del self._rooms[room_id]` on the last departure | `tests/signaling_test.py` asserts it against `/api/debug/stats` |
| Server never sees room names | It rejects anything that is not 64 lowercase hex, so a plaintext name cannot even be submitted | `tests/signaling_test.py` tries five malformed ids |
| Server never sees messages | Payloads are relayed as opaque JSON; chat never touches the relay at all | `tests/signaling_test.py` asserts byte-identical relay |
| Server never sees display names | Names ride the encrypted `HELLO` frame on the peers' DataChannel. The relay has no field for one, which is why de-duplication is a client's job | `grep -niE "nick\|display.?name" server/main.py` — every hit is a comment |
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

## Room ownership and capacity

**Whoever opens a room hosts it.** The first peer to reach a given room id gets
the crown (👑 in the roster, amber name) and the only control panel in the app:
a stepper for the room's size.

- **Capacity is set at creation.** The joiner who creates the room supplies it;
  the relay clamps it to `[2, CAPACITY_CEILING]` and defaults to 8. A later
  joiner's requested capacity is ignored outright — otherwise anyone with the
  passkey could overrule the host by reconnecting.
- **Only the host can resize.** Anyone else asking gets `not_host` back, and
  every occupant is told the new number via `room-meta`.
- **Lowering never evicts anyone.** A decrease clamps at the current headcount.
  Throwing people out of a conversation because a number moved would be a
  hostile way to resize a room; the lower limit governs new joins instead.
- **The crown is inherited, not lost.** When the host disconnects, the oldest
  remaining peer becomes host and everyone is told. The stepper appears for
  them and disappears for the peer who no longer has it.
- **Rooms are still ephemeral, so hosting is too.** The room dies when the last
  peer leaves, which means the next person to open that room id is its new host
  and sets a fresh capacity. There is no persistent ownership, because there is
  nothing persistent.

Read [Host controls are not a security boundary](#what-this-does-not-protect-against)
before treating any of this as enforcement.

---

## Reconnects: repaired, not rebuilt

The common cause of a dropped signaling socket is a network change — a phone
moving from wifi to 5G. That kills the socket and every ICE candidate pair at
once, but leaves the DTLS/SCTP association above them intact. So the mesh is
kept and repaired rather than torn down:

- **Surviving peers get an ICE restart.** `restartIce()` where the browser has it,
  `createOffer({ iceRestart: true })` otherwise. Only the route is renegotiated,
  so open DataChannels, the room key, and each peer's verified status all carry
  through — no re-handshake, no re-verification, no `X left`/`X joined` churn.
- **Peers past repair are rebuilt individually.** A connection that never got
  established, or whose channel actually closed, is replaced. An ICE restart
  fixes routing; it cannot revive a dead SCTP association.
- **The relay's roster is the authority on membership.** Anyone it no longer lists
  is dropped however live the connection looks locally, so a reconnect cannot
  leave a ghost behind.
- **Backoff with jitter** (1s doubling to 15s, eight attempts) so a relay restart
  does not bring every client back in the same instant.
- **The room key is kept.** Reconnecting never re-derives anything or asks for the
  passkey again; PBKDF2 runs once per session.

While a reconnect is pending, a peer connection reporting `failed` is *not*
treated as a lost peer. That state is what a network change looks like from the
inside, and dropping the peer there would discard the only thing a restart can
repair.

### What makes the identity survive

Each connection used to get a fresh peer id, which caused two problems. The
visible one: a client that reconnected appeared *beside* its own previous entry,
and the room inflated — `1/6` becoming `6/6` as a phone changed network a few
times — until the stale socket timed out. The subtler one: to everyone else a
reconnect looked like a departure followed by an arrival, so they tore their side
down and an ICE restart had nothing left to talk to.

Both are fixed by a **session id**: 16 random bytes generated per page load, sent
with `join`. A room that already holds that session hands the returning client
back the *same peer id*, and does not count it against capacity — it was already
counted. So a reconnect reclaims its own slot, keeps the crown if it had it
(the crown points at a peer id that never changed), and the rest of the room hears
`peer-resumed` instead of a leave and a join.

The relay also sends the room's **ordered roster** in `welcome`, including the
recipient. Clients need an arrival order they all agree on — it is what decides
duplicate display names — and `peers` alone cannot give it, because it does not
say where the recipient sits. Without it, two clients that both rebuilt would each
place themselves first, and two people called the same thing would both keep the
plain name.

The session id is random per page load, never persisted, and not derived from
anything identifying. It does let the relay link a reconnect to a prior connection
for as long as the room lives — that is the metadata cost of not counting people
twice.

### Where this stops working

A resume needs the relay to still be holding the old socket when the new one
arrives. Two cases where it is not, both of which fall back to a full rebuild:

- **A graceful close.** If a close frame actually reaches the relay, the peer is
  removed at once and the room is told. A network change does not do this — the
  route is gone, so nothing arrives and the relay keeps the peer until its own
  websocket ping times out, which is far longer than a reconnect takes.
- **The relay restarting.** Rooms live in memory, so a restart loses every session
  mapping. There is nothing to resume and everyone gets new ids.

Both end in a working mesh. Only the first path keeps the DataChannels.

---

## Display names

Two people in a room must never render identically, or a newcomer can pass for
someone the others already trust. So names are de-duplicated: the first claim on a
name keeps it, and a later claim takes the next free counter — `dan`, then
`dan (2)`. Arrival order decides, so nobody already in the room is renamed by a
newcomer.

*Next free* rather than *nth occurrence*, because counting occurrences leaves a
hole: with two people called `dan`, a third could claim the literal string
`dan (2)` and wear the label the second one had been given. Taking the next free
label instead makes them `dan (2) (2)` — inelegant and unambiguous, in that order
of priority.

Claimed names are also stripped of characters that let two different names *look*
the same: C0/C1 controls, the soft hyphen, zero-width spaces and joiners, bidi
marks and overrides, the invisible operators, and the BOM. Tab through carriage
return are deliberately left in and collapsed to a space instead, so a control
character cannot silently join two words. Comparison folds case and spacing, so
`Dan`, `dan`, and `dan ` are one name rather than three.

### Why the relay does not enforce this

**Display names never reach the relay.** They travel inside the encrypted `HELLO`
frame on the peers' own DataChannel, sealed with a room key the relay cannot
derive, so there is nothing there to compare. Enforcing uniqueness server-side
would mean putting every nickname in the `join` message in the clear, which would
hand the relay the one thing it currently cannot have: a roster of who is in which
room.

So the check runs on the clients, where the names actually exist and where every
peer already sees every other peer's claim. It is deterministic — arrival order,
then peer id to break a tie that should not happen — so every client derives the
same answer with nothing coordinating them. The test suite asserts that agreement
directly across three clients, because a mechanism where each client picked its
own answer would be worse than the duplicate it replaced.

A peer may also rename itself mid-session; nothing in the protocol can prevent
that. It is announced in the log rather than absorbed silently, because a silent
rename onto someone else's name is exactly how impersonation would work.

---

## The keep-alive loop is the one thing that phones home

Free hosting tiers idle a service out when nothing calls it. A background task
therefore pings `RENDER_EXTERNAL_URL + /health` every 600 seconds, and if
`DISCORD_WEBHOOK_URL` is set, posts a short notice to Discord afterwards.

Two things this loop cannot do:

- **It cannot wake a sleeping instance.** Once the platform has stopped the
  process, nothing is running to make a request. It prevents idling out while
  alive; it is not a resurrection mechanism. Use an external cron-style pinger
  if you need that.
- **It is not necessarily allowed.** Some providers treat self-pinging as
  working around the free tier they designed. Check the terms for wherever you
  deploy.

### What the Discord notice contains

Only that the process answered, and when:

```json
{
  "username": "Chat Room P2P",
  "embeds": [{
    "title": "Keep-alive ping OK",
    "description": "`GET https://your-host/health` returned **200**.",
    "color": 4513435,
    "timestamp": "2026-08-07T13:14:17+00:00",
    "footer": { "text": "Signaling relay is awake. No session data is reported." }
  }]
}
```

No room ids, no peer ids, no counts, no addresses. `tests/keepalive_test.py`
asserts each of those absences against a captured payload rather than trusting
the code to stay that way.

Be clear-eyed about what enabling it costs, though: a Discord channel
accumulating a ping every ten minutes **is** a retained log of when your relay
was up. It says nothing about who used it, but it is a record, and it lives on
someone else's server. Leave `DISCORD_WEBHOOK_URL` unset and nothing leaves the
machine at all.

---

## What this does not protect against

Read this part. Every one of these is a real limitation, not a hypothetical.

**Peers learn each other's IP addresses.** This is inherent to peer-to-peer:
direct connections are exactly what keeps the server out of your conversation,
and the cost is that the people in your room see your address. Encryption does
not change it. The transport panel shows `direct` or `relayed`, so you always
know which you got.

**A TURN relay is used as a fallback, and it sees both addresses.** Two peers
behind symmetric NAT — the ordinary case for 4G/5G carrier-grade NAT against
home wifi — cannot connect directly at all, so the app falls back to relaying
through TURN. ICE prefers direct paths, so this only happens when nothing else
works, but when it does a third party carries your traffic and observes both
endpoints. It **cannot read anything**: what passes through is DTLS, and inside
that, AES-GCM frames it has no key for. The default servers use the public
OpenRelay credentials, which are shared, rate-limited, and not guaranteed to be
up; set `window.ICE_SERVERS` in `index.html` to use your own coturn instead. To
refuse relaying entirely, set `window.ICE_SERVERS` to STUN-only entries and
accept that some pairs will not connect.

**The relay sees metadata.** Even knowing nothing about content, it observes:
which IPs connected, when, how long they stayed, which opaque room id they
grouped under, and how many peers were in each group. Room names and passkeys
are never on the wire; the pattern of connections is.

**A shared room key authenticates membership, not individuals.** Everyone in the
room holds the same key, so any member can send a frame claiming any display
name. It is not possible to prove *which* member sent a message. Fixing this
needs per-peer signing keys, which is not implemented. Treat display names as a
convenience among people who already trust each other.

Display names are de-duplicated and stripped of invisible characters (see
[Display names](#display-names)), which guarantees something narrower and worth
being precise about: **you can always tell two people apart.** Two occupants can
never render as the same string, and a name cannot be dressed up to look like
another one. That is not the same as knowing who anyone is. A peer claiming your
name still gets into the room — it just shows up as `you (2)` rather than as a
second, indistinguishable you.

**The browser is not a clean room.** `chrome://webrtc-internals` records SDP and
connection stats locally, DevTools can inspect a live page, and OS memory can be
paged to disk. The app avoids every storage API and sets `no-store` and a strict
CSP, but "nothing is retained" is a server-side guarantee and a client-side
best effort.

**Eight peers by default, sixteen at the absolute most.** In a full mesh each
peer uploads its audio to every other peer, so cost grows with the square of the
room. Past about eight, voice degrades — the host can raise the limit anyway,
and the UI says what it costs when they do. `CAPACITY_CEILING` is the hard stop,
because capacity arrives from a client and unbounded client-controlled state is
how one room exhausts a process. Going genuinely large means an SFU, which puts
a server back in the media path and gives up the architecture's main property.
Text and files scale much further; the cap exists for voice.

**Host controls are not a security boundary.** The relay assigns the host and
enforces the cap, so a hostile relay could name the wrong peer host, ignore the
limit, or admit a ninth guest. Host status is deliberately carried on the
signaling channel rather than in encrypted peer frames — a peer could claim
anything there, whereas the relay is at least the party that actually enforces
it. Treat the crown as a way for a group to organise itself, not as a defence.
What a hostile relay still cannot do is read a message.

**No forward secrecy across a passkey's life.** The room key is a pure function
of room name and passkey. Anyone who learns the passkey and captured earlier
ciphertext can decrypt it. Rotate by changing the passkey, which creates a
different room.

**Denial of service is out of scope.** The relay caps peers per room, frame
size, and per-connection message rate, and never allocates on behalf of an
unjoined socket. It is not hardened against a distributed flood; put it behind
something that is.

**CORS is open to every origin.** `allow_origins=["*"]` lets any website's
JavaScript read this origin's HTTP responses. Today those are `/health` and
`/api/health`, which carry no session data, so the practical exposure is small —
but it is a door held open for no functional gain, and it contradicts the CSP.
Note also that it does nothing for `/ws`: WebSocket handshakes are not subject
to CORS, so a permissive policy neither helps nor hinders peers. To close it,
replace `["*"]` in `server/main.py` with your own origin. Relatedly, the
WebSocket endpoint performs no `Origin` check, so any page can open a signaling
socket — it cannot read a room without the passkey, but it can occupy a slot.

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

320 assertions across three suites. The first two need a live relay; start it
first:

```powershell
$env:DEBUG_STATS = "1"
.venv\Scripts\python.exe -m server.main
```

```powershell
# 119 assertions: protocol, validation, isolation, host assignment and
# reassignment, custom capacity and its clamps, host-only resize, room deletion,
# rate limiting, security headers, CORS, and the reconnect contract -- that a
# resume reclaims its own peer id, holds its place in the ordered roster, is
# admitted into a room already at capacity, and that the socket it displaced
# cannot evict it on the way out
.venv\Scripts\python.exe tests\signaling_test.py

# 178 assertions in real headless browsers: key agreement, mesh formation,
# encrypted chat, file integrity, voice tracks, mute/deafen, the crown and
# host stepper, capacity refusal, crown inheritance, teardown, and signaling
# address resolution -- including a page served from a static host, to prove
# it does not signal to its own origin. Three clients all claiming the same
# name check that every one of them derives the same labels for the same
# people. Two clients on a private relay cover both outages: a moved
# signaling path, where the DataChannel object itself must survive, and a
# relay restart, where both peers must come back with new ids and no ghosts
.venv\Scripts\python.exe tests\browser_e2e_test.py
```

```powershell
# 23 assertions, self-contained — starts its own relay and its own mock
# endpoint, so it needs neither a running server nor a Discord account:
# the loop fires, targets the right URL, keeps cycling, survives a dead
# target, adds no log output, and leaks no session data to the webhook
.venv\Scripts\python.exe tests\keepalive_test.py
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
| `{"type":"join","room":"<64 hex>","capacity":8,"sessionId":"<32 hex>"}` | Enter a room. `capacity` is optional and only honoured if this join creates the room. `sessionId` is optional; when it matches an existing occupant the relay treats this as a reconnect, hands back that occupant's peer id, and does not count it against capacity. Answered with `welcome` or `error`. |
| `{"type":"signal","to":"<peerId>","data":{…}}` | Relay `data` verbatim to one peer in your room. |
| `{"type":"set-capacity","capacity":10}` | Host only. Answered with a broadcast `room-meta`, or `not_host`. |
| `{"type":"leave"}` | Disconnect. |
| `{"type":"ping"}` | Answered with `pong`. |

Relay → client:

| Message | Meaning |
| --- | --- |
| `{"type":"welcome","peerId","peers":[…],"roster":[…],"hostId","capacity","ceiling","minCapacity"}` | Admitted. `peers` lists who was already there. `roster` is the whole room in arrival order, **including you** — clients need a shared ordering to resolve duplicate display names. `hostId` equals `peerId` if you opened the room. |
| `{"type":"room-meta","hostId","capacity"}` | The host or the capacity changed. Sent on a resize and on host reassignment. |
| `{"type":"peer-join","peerId"}` | Someone arrived. |
| `{"type":"peer-leave","peerId"}` | Someone left. |
| `{"type":"peer-resumed","peerId"}` | That peer's signaling socket came back on the same id. The connection you hold is still addressed correctly; restart its ICE rather than rebuilding it. |
| `{"type":"signal","from":"<peerId>","data":{…}}` | A relayed payload. |
| `{"type":"error","code":"…"}` | `bad_room_id`, `room_full`, `not_host`, `not_joined`, `already_joined`, `no_such_peer`, `bad_json`, `bad_request`, `unknown_type`, `frame_too_large`, `rate_limited`. |

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
