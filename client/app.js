/*
 * Chat Room P2P — client.
 *
 * Everything that matters happens here. The server helps two browsers find
 * each other and then has no further part in the conversation.
 *
 * Key schedule
 *   passkey ──PBKDF2-SHA256(600k, salt=SHA256("…|room|"+roomName))──> master
 *   master ──HKDF-SHA256(info="…/aes-gcm")──> AES-GCM-256  (non-extractable)
 *          ──HKDF-SHA256(info="…/room-id")──> 32 bytes, hex → sent to relay
 *          ──HKDF-SHA256(info="…/seal")────> 16 bytes → the visible seal
 *
 *   One PBKDF2 pass, then cheap domain-separated HKDF for each output. The AES
 *   key is produced by deriveKey with extractable=false, so its bytes never
 *   exist anywhere JavaScript can read them. The 32 master bytes do exist, in
 *   exactly one Uint8Array, which is zero-filled the moment HKDF has imported
 *   it. The room id and seal are derived under different info strings, so
 *   publishing them tells an observer nothing about the encryption key.
 *
 * Message path
 *   plaintext frame  [type:1][metaLen:2 BE][meta JSON][payload]
 *   sealed frame     [ver:1][iv:12][AES-GCM ciphertext‖tag]
 *
 *   Sealed frames ride a WebRTC DataChannel, which is itself inside DTLS. The
 *   AES-GCM layer is not redundant: it is what makes a malicious relay that
 *   swapped DTLS fingerprints unable to read anything, and it is how a peer
 *   proves it knows the passkey — a peer whose first frame will not decrypt is
 *   dropped.
 *
 * Persistence
 *   None. No localStorage, no sessionStorage, no IndexedDB, no cookies, no
 *   cache API. Received files are held as Blobs in memory until you save them,
 *   and their object URLs are revoked on leave.
 */

'use strict';

/* ==========================================================================
   0. Configuration
   ========================================================================== */

const PBKDF2_ITERATIONS = 600_000;
const KDF_DOMAIN = 'chatroom-p2p/v1';
const WIRE_VERSION = 1;

/* Defaults only. The relay is authoritative for all three and sends its own
   values in `welcome`; these just populate the join form before we've asked. */
const DEFAULT_CAPACITY = 8;
const MIN_CAPACITY = 2;
const DEFAULT_CEILING = 16;

/* Past this, full-mesh voice starts to fall apart. The host may still raise the
   limit -- it is their room -- but they get told what it costs. */
const MESH_SAFE_CAPACITY = 8;

/** Interop-safe SCTP payload. Encryption adds 13 header + 16 tag bytes. */
const FILE_CHUNK_BYTES = 16 * 1024;
/** Received files live in RAM, so this is a real ceiling, not a policy. */
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const DC_HIGH_WATER = 1024 * 1024;
const DC_LOW_WATER = 256 * 1024;

/**
 * How long a peer has to prove it holds the room key, counted from the moment
 * its DataChannel opens -- not from when we learned it existed.
 *
 * The old version started this clock at peer creation, so ICE gathering and
 * connection ate the budget. A phone on 5G negotiating through TURN could spend
 * longer than that just getting a channel, and then be dropped for "never
 * proved they hold the room key" without ever having had the chance. Once a
 * channel is open, HELLO is one frame, so this only has to cover latency.
 */
const VERIFY_TIMEOUT_MS = 20_000;

/**
 * Separate, much longer budget for reaching a connected state at all. TURN
 * allocation on a slow mobile link is not quick, and the failure this guards
 * against is a peer that hangs in 'connecting' forever rather than one that
 * cannot decrypt.
 */
const CONNECT_TIMEOUT_MS = 90_000;

/* RMS thresholds for the activity ring, tuned against typical mic levels. */
const VAD_FLOOR = 0.018;
const VAD_CEIL = 0.22;
const VAD_TALKING = 0.14;

/*
 * ICE servers.
 *
 * STUN alone works when at least one side can be reached directly. It fails
 * between two symmetric NATs, which is exactly the 4G/5G carrier-grade NAT case:
 * a phone and a laptop on home wifi gather candidates that neither can use, ICE
 * exhausts them, and the connection never comes up.
 *
 * The TURN entries below are the fallback for that. A TURN server forwards the
 * traffic, so it works where nothing else does, at the cost of routing your
 * media through a third party. Two things about that cost:
 *
 *   * It does not weaken encryption. A relay carries DTLS, and inside that,
 *     AES-GCM frames it has no key for. It sees ciphertext and two addresses.
 *   * It does see both addresses. That is a real disclosure, and it is why TURN
 *     is a fallback: ICE prefers host and server-reflexive candidates, so a
 *     relay is used only when nothing direct works. The transport panel says
 *     `relayed` when it happens, so you are never guessing.
 *
 * These are the public OpenRelay credentials, shared by everyone who uses them
 * and therefore rate-limited and not guaranteed to be up. For anything you
 * depend on, run coturn or buy a TURN service and set window.ICE_SERVERS in
 * index.html -- that override replaces this list wholesale.
 */
const DEFAULT_ICE_SERVERS = [
  { urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] },
  // Port 80/443 and the TCP/TLS variants are what survive restrictive networks
  // that allow only what looks like web traffic.
  {
    urls: [
      'turn:openrelay.metered.ca:80',
      'turn:openrelay.metered.ca:443',
      'turn:openrelay.metered.ca:443?transport=tcp',
      'turns:openrelay.metered.ca:443',
    ],
    username: 'openrelayproject',
    credential: 'openrelayproject',
  },
];

/** window.ICE_SERVERS, when set in index.html, replaces the defaults entirely. */
const ICE_SERVERS = Array.isArray(window.ICE_SERVERS) && window.ICE_SERVERS.length
  ? window.ICE_SERVERS
  : DEFAULT_ICE_SERVERS;

/* Used when the page is served from a static host, which cannot itself be the
   relay. Override per-deployment with window.SIGNALING_URL in index.html rather
   than editing this. */
const FALLBACK_SIGNALING_URL = 'wss://chat-room-p2p.onrender.com/ws';

/* Hosts that serve files and nothing else, so the page's own origin is never a
   relay. Matched as suffixes against location.hostname. */
const STATIC_ONLY_HOSTS = [
  '.vercel.app',
  '.netlify.app',
  '.github.io',
  '.pages.dev',
  '.surge.sh',
];

/** Frame types on the encrypted channel. */
const F = {
  HELLO: 1,
  CHAT: 2,
  STATE: 3,
  FILE_START: 4,
  FILE_CHUNK: 5,
  FILE_END: 6,
  FILE_ABORT: 7,
};

/* One clearly separated hue per slot. Earlier versions of this list held both a
   mint and a lime, and two people in the same room read as the same colour. */
const AVATAR_COLORS = [
  '#4ade9b', // mint
  '#7dd3fc', // sky
  '#f2b544', // amber
  '#c084fc', // violet
  '#fb923c', // orange
  '#f472b6', // pink
  '#818cf8', // indigo
  '#2dd4bf', // teal
];
/* The seal draws from a fixed four-colour subset so the mark stays readable. */
const SEAL_COLORS = ['#4ade9b', '#7dd3fc', '#f2b544', '#5c6577'];

/* ==========================================================================
   1. Helpers
   ========================================================================== */

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

const utf8 = (s) => enc.encode(s);
const noop = () => {};

function hex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function randomHex(byteLength) {
  return hex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

function clockTime() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/** Stable colour per display name, so the same person looks the same to everyone. */
function colorFor(text) {
  let h = 0;
  for (let i = 0; i < text.length; i += 1) h = (h * 31 + text.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

function initialsOf(nick) {
  const trimmed = (nick || '?').trim();
  return (trimmed[0] || '?').toUpperCase();
}

/** Longest display name we will render. Also the join field's maxlength. */
const NICK_MAX = 24;

/*
 * Characters that let two different names render identically. Written as escapes
 * on purpose: a literal zero-width space in this source would be invisible to
 * the next person reading it, which is the very trick being defended against.
 *
 *   0000-0008, 000e-001f   C0 controls, except the whitespace ones
 *   007f-009f              delete and the C1 controls
 *   00ad                   soft hyphen
 *   200b-200f              zero-width space and joiners, LTR and RTL marks
 *   2028-202e              line/paragraph separators, bidi embedding, overrides
 *   2060-2064              word joiner and the invisible operators
 *   2066-2069              bidi isolates
 *   feff                   byte order mark
 *
 * Tab through carriage return (0009-000d) are deliberately left out. They are
 * whitespace, not invisible formatting, so they belong to the space-collapsing
 * step below -- deleting them would turn "dan\nsmith" into one word, letting a
 * control character change the visible text rather than merely disappear.
 *
 * Stripping the rest is the first half of stopping impersonation: without it, a
 * name carrying a zero-width space renders exactly like the name without one,
 * so it would never be detected as a collision.
 */
const NICK_INVISIBLES = new RegExp(
  '[\\u0000-\\u0008\\u000e-\\u001f\\u007f-\\u009f\\u00ad\\u200b-\\u200f'
  + '\\u2028-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]',
  'g',
);

/**
 * Reduce a claimed name to something safe to show.
 *
 * Applied to our own input at join time as well as to every incoming HELLO, so
 * that what a peer sees for us is what we see for ourselves.
 */
function cleanNick(raw) {
  const cleaned = String(raw == null ? '' : raw)
    .replace(NICK_INVISIBLES, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, NICK_MAX)
    .trim();
  return cleaned || 'peer';
}

/** Names that differ only in case or spacing are the same name to a reader. */
function foldNick(nick) {
  return cleanNick(nick).toLocaleLowerCase();
}

/* ==========================================================================
   2. Crypto
   ========================================================================== */

/**
 * Turn a room name and passkey into the room's key material.
 * Nothing here touches the network.
 */
async function deriveSession(roomName, passkey) {
  const pbkdf2Key = await crypto.subtle.importKey('raw', utf8(passkey), 'PBKDF2', false, ['deriveBits']);
  const salt = await sha256(utf8(`${KDF_DOMAIN}|room|${roomName}`));

  const masterBits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      pbkdf2Key,
      256,
    ),
  );
  const master = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveKey', 'deriveBits']);
  // The only copy of the master secret in JS memory, gone as soon as HKDF has it.
  masterBits.fill(0);

  const hkdf = (info) => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(0),
    info: utf8(`${KDF_DOMAIN}/${info}`),
  });

  const roomKey = await crypto.subtle.deriveKey(
    hkdf('aes-gcm'), master, { name: 'AES-GCM', length: 256 },
    false, // non-extractable: exportKey on this will throw, by design
    ['encrypt', 'decrypt'],
  );
  const roomId = hex(new Uint8Array(await crypto.subtle.deriveBits(hkdf('room-id'), master, 256)));
  const seal = new Uint8Array(await crypto.subtle.deriveBits(hkdf('seal'), master, 128));

  return { roomKey, roomId, seal };
}

/**
 * Encrypt one plaintext frame.
 * A fresh 96-bit random IV per frame. At 16 KiB chunks, staying under the
 * ~2^32 frame birthday bound for random GCM nonces means ~64 TiB on one key,
 * and a key only lives as long as the room does.
 */
async function sealFrame(key, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plain),
  );
  const out = new Uint8Array(13 + ct.length);
  out[0] = WIRE_VERSION;
  out.set(iv, 1);
  out.set(ct, 13);
  return out;
}

async function openFrame(key, buffer) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 14 || bytes[0] !== WIRE_VERSION) throw new Error('malformed frame');
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.subarray(1, 13), tagLength: 128 },
    key,
    bytes.subarray(13),
  );
  return new Uint8Array(plain);
}

/* ==========================================================================
   3. Frame codec
   ========================================================================== */

function encodeFrame(type, meta, payload) {
  const metaBytes = meta ? utf8(JSON.stringify(meta)) : new Uint8Array(0);
  if (metaBytes.length > 0xffff) throw new Error('frame metadata too large');
  const body = payload || new Uint8Array(0);
  const out = new Uint8Array(3 + metaBytes.length + body.length);
  out[0] = type;
  out[1] = (metaBytes.length >> 8) & 0xff;
  out[2] = metaBytes.length & 0xff;
  out.set(metaBytes, 3);
  out.set(body, 3 + metaBytes.length);
  return out;
}

function decodeFrame(bytes) {
  if (bytes.length < 3) throw new Error('short frame');
  const metaLen = (bytes[1] << 8) | bytes[2];
  if (3 + metaLen > bytes.length) throw new Error('bad metadata length');
  const meta = metaLen ? JSON.parse(dec.decode(bytes.subarray(3, 3 + metaLen))) : {};
  return { type: bytes[0], meta, payload: bytes.subarray(3 + metaLen) };
}

/* ==========================================================================
   4. State
   ========================================================================== */

const state = {
  roomName: '',
  roomId: '',
  roomKey: null,
  seal: null,
  /** What we claim to be called. Sent in HELLO, never rewritten by anyone else. */
  nick: '',
  /** What we are *displayed* as, which is nick plus a counter if it collided. */
  label: '',
  peerId: '',
  /**
   * Arrival order, ours and each peer's.
   *
   * Seeded from the ordered roster in `welcome` and extended by a local counter
   * for anyone who joins after. Everyone therefore agrees, which is what lets the
   * display-name tiebreak be decided independently and still come out the same
   * everywhere -- see resolveLabels().
   *
   * The roster has to come from the relay rather than being counted locally.
   * `welcome.peers` lists the others but not where we sit among them, so after a
   * full mesh rebuild every client would place itself at its own counter's
   * position, two peers called the same thing would both think they were first,
   * and both would keep the plain name.
   */
  arrivalSeq: 0,
  selfOrder: 0,
  // Room coordination state, all of it server-assigned. Deliberately not taken
  // from DataChannel frames: a peer could claim anything there, whereas these
  // arrive over the signaling socket from the party that actually enforces them.
  hostId: '',
  capacity: DEFAULT_CAPACITY,
  ceiling: DEFAULT_CEILING,
  minCapacity: MIN_CAPACITY,
  // Resolved once at boot so the join screen can report a misconfiguration
  // before anyone spends a second on key derivation.
  signalingUrl: '',
  signalingSource: '',
  socket: null,
  /**
   * Stable across reconnects, random per page load, never persisted. The relay
   * uses it to recognise a returning connection and evict the entry it left
   * behind, which is what stops a phone changing network from showing up as a
   * second occupant. It is not derived from anything identifying, and it dies
   * with the tab.
   */
  sessionId: '',
  reconnectAttempt: 0,
  reconnectTimer: null,
  /**
   * True from the moment the signaling socket drops until we are back in (or
   * have given up). While it is set, a peer connection going to 'failed' is not
   * treated as a lost peer: an ICE restart may still revive it, and tearing it
   * down here would throw away the only thing a restart can repair.
   */
  reconnecting: false,
  peers: new Map(),      // peerId -> Peer
  incoming: new Map(),   // transferId -> { from, meta, parts, received }
  blobUrls: new Set(),
  statsTimer: null,
  levelFrame: null,
  live: false,
};

const audio = {
  ctx: null,
  stream: null,
  track: null,
  meters: new Map(),     // 'self' | peerId -> { source, analyser, buffer }
  sinks: new Map(),      // peerId -> HTMLAudioElement
  muted: false,
  deafened: false,
};

/* ==========================================================================
   5. Signaling
   ========================================================================== */

/**
 * Work out where the relay lives.
 *
 * Same-origin is the right answer whenever the page came from the relay itself,
 * which covers local development and a single-host deploy. It is the wrong
 * answer on a static host: Vercel and friends serve files and have no websocket
 * endpoint, so deriving the URL from location.host points the client at a /ws
 * that does not exist.
 *
 * Priority:
 *   1. window.SIGNALING_URL, set in index.html. Always wins.
 *   2. FALLBACK_SIGNALING_URL, when the page is on a known static host.
 *   3. Same origin as the page.
 *
 * Returns { url, source, error }. `error` is a human-readable reason the
 * resolved URL cannot work, which is better than letting the browser refuse the
 * connection with nothing but a console message.
 */
function resolveSignalingUrl() {
  const override = typeof window.SIGNALING_URL === 'string' ? window.SIGNALING_URL.trim() : '';
  const onStaticHost = STATIC_ONLY_HOSTS.some((suffix) => location.hostname.endsWith(suffix));

  let raw;
  let source;
  if (override) {
    raw = override;
    source = 'configured';
  } else if (onStaticHost) {
    raw = FALLBACK_SIGNALING_URL;
    source = 'fallback';
  } else {
    raw = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`;
    source = 'same-origin';
  }

  const url = normalizeSignalingUrl(raw);
  if (!url) {
    return { url: null, source, error: `Could not read "${raw}" as a signaling address.` };
  }

  // A secure page cannot open an insecure socket; the browser blocks it outright.
  if (location.protocol === 'https:' && url.protocol === 'ws:') {
    return {
      url: url.href,
      source,
      error: `This page is on https, so the relay address must use wss://, not ws:// (${url.href}).`,
    };
  }
  if (onStaticHost && url.host === location.host) {
    return {
      url: url.href,
      source,
      error: `${location.hostname} only serves files, so it has no relay. `
        + 'Set window.SIGNALING_URL in index.html to your relay address.',
    };
  }
  return { url: url.href, source, error: null };
}

/**
 * Accept the forms someone would plausibly write: a full wss:// URL, an
 * https:// URL, a bare host, or a host with a path. Fills in /ws when no path
 * is given, since that is the only endpoint there is.
 */
function normalizeSignalingUrl(raw) {
  let value = String(raw || '').trim();
  if (!value) return null;

  if (/^https:\/\//i.test(value)) value = value.replace(/^https:\/\//i, 'wss://');
  else if (/^http:\/\//i.test(value)) value = value.replace(/^http:\/\//i, 'ws://');
  else if (!/^wss?:\/\//i.test(value)) {
    value = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${value}`;
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (!url.hostname) return null;
  if (url.pathname === '/' || url.pathname === '') url.pathname = '/ws';
  url.hash = '';
  return url;
}

function sendToRelay(message) {
  const sock = state.socket;
  if (sock && sock.readyState === WebSocket.OPEN) {
    sock.send(JSON.stringify(message));
  }
}

/** Resolves once the relay has admitted us, rejects with a reason code. */
function connectRelay(roomId, requestedCapacity) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let sock;
    try {
      sock = new WebSocket(state.signalingUrl);
    } catch {
      reject(new Error('relay_unreachable'));
      return;
    }
    state.socket = sock;

    // Capacity is a request, not an instruction: the relay honours it only when
    // this join creates the room, and clamps it to its own bounds either way.
    // sessionId is how the relay recognises a reconnect and reclaims our slot.
    sock.onopen = () => sendToRelay({
      type: 'join',
      room: roomId,
      capacity: requestedCapacity,
      sessionId: state.sessionId,
    });

    sock.onmessage = (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }

      if (message.type === 'welcome') {
        state.peerId = message.peerId;
        settled = true;
        resolve(message);
        return;
      }
      if (message.type === 'error' && !settled) {
        settled = true;
        reject(new Error(message.code || 'relay_error'));
        return;
      }
      handleRelayMessage(message);
    };

    sock.onerror = () => {
      if (!settled) { settled = true; reject(new Error('relay_unreachable')); }
    };

    sock.onclose = () => {
      if (!settled) { settled = true; reject(new Error('relay_unreachable')); return; }
      if (state.live && state.socket === sock) scheduleReconnect();
    };
  });
}

/* --- Reconnect ------------------------------------------------------------
   A dropped signaling socket was once terminal, and then it was a full mesh
   rebuild. Neither is right for the common cause, which is a network change:
   moving from wifi to 5G kills the socket and every ICE candidate pair at once,
   but leaves the DTLS/SCTP association above them intact.

   So the mesh is kept and repaired. On the way back in, each surviving peer gets
   an ICE restart, which renegotiates only the route -- open DataChannels, the
   room key, and each peer's verified status all carry through untouched. Peers
   that cannot be repaired are rebuilt individually, and the relay's roster is
   the authority on who is still there.

   This works because the relay hands a reconnecting session back its *own* peer
   id, so nobody else sees a departure and an arrival. Without that, everyone
   else would tear their side down and the restart would have nothing to talk to.

   The condition, stated plainly: the relay must not have finished tearing our
   old socket down before the new one arrives. A network change satisfies it --
   the phone's route disappears, so no close frame ever reaches the relay and it
   keeps the peer until its own websocket ping times out, which is far longer
   than a reconnect takes. A *graceful* close does not: the relay is told at once,
   removes the peer, and tells the room. Then there is nothing to resume and this
   falls back to a full rebuild, which is correct, just slower. Both paths end in
   a working mesh; only the first one keeps the DataChannels.
   -------------------------------------------------------------------------- */

const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 15_000;
const RECONNECT_MAX_ATTEMPTS = 8;

/**
 * Drop every peer connection and all per-connection state, keeping the room key
 * and identity.
 *
 * Only for the paths where reconnecting has stopped being possible: out of
 * attempts, or the room filled up while we were away. A recoverable drop keeps
 * the mesh and repairs it -- see syncRoster.
 */
function resetMesh() {
  for (const peer of state.peers.values()) peer.close();
  state.peers.clear();

  for (const peerId of [...audio.sinks.keys()]) detachRemoteAudio(peerId);
  // Partial transfers cannot be resumed across a reconnect; half a file is not
  // worth the memory it is sitting in.
  state.incoming.clear();

  state.hostId = '';
  capacityIntent = null;
  renderPeers();
  renderTransport();
}

function scheduleReconnect() {
  if (!state.live || state.reconnectTimer !== null) return;

  // Set before anything else: it is what stops peers being torn down while their
  // paths are failing, so there is still something to restart ICE on.
  state.reconnecting = true;

  if (state.reconnectAttempt >= RECONNECT_MAX_ATTEMPTS) {
    // Out of attempts. Now the mesh really is unrecoverable, because nothing
    // will be signaling for it again.
    state.reconnecting = false;
    resetMesh();
    setStatus('degraded', 'Disconnected');
    systemMessage(
      `Gave up reconnecting to the relay after ${RECONNECT_MAX_ATTEMPTS} attempts. Reload to try again.`,
      'warn',
    );
    return;
  }

  const attempt = state.reconnectAttempt;
  state.reconnectAttempt += 1;
  // Exponential with jitter, so a relay restart does not get every client back
  // at the same instant.
  const delay = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** attempt)
    * (0.75 + Math.random() * 0.5);

  setStatus('degraded', `Reconnecting in ${Math.round(delay / 1000)}s`);
  if (attempt === 0) {
    systemMessage('Lost the connection to the relay. Holding the room together…', 'warn');
  }

  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    rejoin().catch(() => scheduleReconnect());
  }, delay);
}

async function rejoin() {
  if (!state.live) return;
  setStatus('connecting', 'Reconnecting');

  let welcome;
  try {
    welcome = await connectRelay(state.roomId, state.capacity);
  } catch (err) {
    if (err.message === 'room_full') {
      // Someone took the slot while we were away. Retrying would just fail
      // again, so stop and say so.
      state.reconnectAttempt = RECONNECT_MAX_ATTEMPTS;
      state.reconnecting = false;
      resetMesh();
      setStatus('degraded', 'Room full');
      systemMessage('The room filled up while you were disconnected. Reload to try rejoining.', 'warn');
      return;
    }
    throw err;
  }

  // Back in, and holding the same peer id as before, so every peer still has us
  // at the address it knows.
  state.reconnectAttempt = 0;
  state.reconnecting = false;
  applyWelcome(welcome);

  const { resumed, rebuilt, dropped } = syncRoster(welcome);
  const parts = [];
  if (resumed) parts.push(`${resumed} ${resumed === 1 ? 'connection' : 'connections'} kept`);
  if (rebuilt) parts.push(`${rebuilt} rebuilding`);
  if (dropped) parts.push(`${dropped} gone`);
  systemMessage(parts.length ? `Reconnected — ${parts.join(', ')}.` : 'Reconnected. Waiting for others.');
}

/**
 * Make our roster match the relay's, which is the only authority on who is
 * actually in the room.
 *
 * Three cases, and the last two are what stop a reconnect from leaving ghosts:
 * a peer the relay still lists is repaired in place, one it no longer lists is
 * dropped however connected it looks to us, and one we have never heard of is
 * built fresh. addPeer refuses ids we already hold and refuses our own, so no
 * path through here can double an entry.
 */
function syncRoster(welcome) {
  const peerIds = Array.isArray(welcome.peers) ? welcome.peers : [];
  const present = new Set(peerIds);
  let resumed = 0;
  let rebuilt = 0;
  let dropped = 0;

  // Gone from the relay's list means gone, even if our side still shows a live
  // connection -- that peer left and its socket has not finished dying yet.
  for (const id of [...state.peers.keys()]) {
    if (!present.has(id)) {
      removePeer(id, 'stale');
      dropped += 1;
    }
  }

  for (const id of peerIds) {
    const peer = state.peers.get(id);
    if (!peer) {
      addPeer(id);
      rebuilt += 1;
    } else if (peer.resume()) {
      resumed += 1;
    } else {
      // Past repair: drop and rebuild this one connection.
      removePeer(id, 'stale');
      addPeer(id);
      rebuilt += 1;
    }
  }

  // The relay's ordering is authoritative and replaces whatever the local counter
  // produced above, so a rebuild cannot leave two clients disagreeing about who
  // arrived first.
  applyRoster(welcome.roster);
  applyLabels();
  renderTransport();
  return { resumed, rebuilt, dropped };
}

/** Adopt the relay's view of the room. Shared by the first join and every rejoin. */
function applyWelcome(welcome) {
  state.peerId = welcome.peerId;
  state.hostId = welcome.hostId || '';
  if (typeof welcome.capacity === 'number') state.capacity = welcome.capacity;
  if (typeof welcome.ceiling === 'number') state.ceiling = welcome.ceiling;
  if (typeof welcome.minCapacity === 'number') state.minCapacity = welcome.minCapacity;
  capacityIntent = null;
  renderPeers();
  renderCapacityControl();
  renderTransport();
}

function handleRelayMessage(message) {
  switch (message.type) {
    case 'peer-join':
      // A newcomer. Both sides create the connection; the lexicographically
      // smaller peer id opens the DataChannel and makes the first offer, which
      // is what keeps the two sides from offering at once.
      addPeer(message.peerId);
      break;

    case 'peer-resumed': {
      // That peer's signaling came back on a new socket. It kept its id, so the
      // connection we hold is still addressed correctly and only needs its route
      // renegotiated. No join, no leave, no name churn in the log.
      const peer = state.peers.get(message.peerId);
      if (!peer) {
        addPeer(message.peerId);
      } else if (!peer.resume()) {
        const order = peer.order;
        removePeer(message.peerId, 'stale');
        addPeer(message.peerId);
        const fresh = state.peers.get(message.peerId);
        if (fresh) fresh.order = order;
      }
      renderTransport();
      break;
    }

    case 'peer-leave':
      removePeer(message.peerId, 'left');
      break;

    case 'signal': {
      const peer = state.peers.get(message.from);
      if (peer) peer.handleSignal(message.data);
      break;
    }

    case 'room-meta': {
      const gainedCrown = message.hostId === state.peerId && state.hostId !== state.peerId;
      const hostChanged = message.hostId !== state.hostId;
      const previousCapacity = state.capacity;

      state.hostId = message.hostId || state.hostId;
      if (typeof message.capacity === 'number') {
        state.capacity = message.capacity;
        // A burst of clicks produces a confirmation per click. Hold the intent
        // until the relay catches up to it, otherwise the number visibly walks
        // backwards through every intermediate value. Give up on the intent
        // only once it is confirmed or the relay has clamped it out of reach.
        const floor = Math.max(state.minCapacity, state.peers.size + 1);
        const clampedOut = state.capacity >= state.ceiling || state.capacity <= floor;
        if (capacityIntent === state.capacity || clampedOut) capacityIntent = null;
      }

      if (gainedCrown) {
        systemMessage('You are the host now — the previous host left. You can change the room size.');
      } else if (hostChanged) {
        const host = state.peers.get(state.hostId);
        systemMessage(`${host?.nick || 'Someone else'} is the host now.`);
      }
      if (state.capacity !== previousCapacity && !hostChanged) {
        systemMessage(`Room size is now ${state.capacity}.`);
      }
      renderPeers();
      renderCapacityControl();
      break;
    }

    case 'error':
      if (message.code === 'room_full') {
        systemMessage('This room is full.', 'warn');
      } else if (message.code === 'not_host') {
        // The crown moved between the click and the relay reading it.
        systemMessage("You're not the host, so the room size didn't change.", 'warn');
        renderCapacityControl();
      }
      break;

    default:
      break;
  }
}

/* ==========================================================================
   6. Peer mesh
   ========================================================================== */

class Peer {
  constructor(peerId) {
    this.id = peerId;
    /** What this peer claims to be called, straight from its HELLO. */
    this.nick = null;
    /** What we display it as: nick, plus a counter if the name was taken. */
    this.label = null;
    /** Arrival index, assigned by addPeer. Decides display-name collisions. */
    this.order = 0;
    this.muted = false;
    this.deafened = false;
    this.verified = false;
    this.dead = false;
    /** Set when the transport died for good, so resume() rebuilds rather than
     *  trying to restart ICE on a connection that has nothing left to restart. */
    this.stale = false;

    // One side must lead. Ordering peer ids gives both sides the same answer
    // without another round trip.
    this.initiator = state.peerId < peerId;
    this.polite = !this.initiator;

    this.makingOffer = false;
    this.ignoreOffer = false;
    this.canOffer = this.initiator;
    this.pendingCandidates = [];

    this.channel = null;
    this.stats = null;

    this.pc = new RTCPeerConnection({ iceServers: ICE_SERVERS, bundlePolicy: 'max-bundle' });

    // Creating the audio transceiver up front means the audio m-line always
    // exists, so enabling a mic later or muting never needs renegotiation.
    this.audioTx = this.pc.addTransceiver('audio', { direction: 'sendrecv' });
    if (audio.track) this.audioTx.sender.replaceTrack(audio.track).catch(noop);

    this.pc.onnegotiationneeded = () => this.negotiate();
    this.pc.onicecandidate = ({ candidate }) => {
      if (candidate) this.signal({ kind: 'ice', candidate: candidate.toJSON() });
    };
    this.pc.ontrack = (event) => attachRemoteAudio(this.id, event.track);
    this.pc.onconnectionstatechange = () => {
      const s = this.pc.connectionState;
      if (s === 'closed') {
        removePeer(this.id, 'closed');
        return;
      }
      if (s === 'failed') {
        // While signaling is away this is not a lost peer, it is a lost path:
        // switching from wifi to 5G invalidates every candidate pair, and ICE
        // reports that as failure. An ICE restart fixes it once we can signal
        // again, so keep the connection and let resume() deal with it.
        if (state.reconnecting) {
          this.stale = !this.channel || this.channel.readyState !== 'open';
          renderTransport();
          return;
        }
        removePeer(this.id, 'failed');
        return;
      }
      renderTransport();
    };

    if (this.initiator) {
      this.bindChannel(this.pc.createDataChannel('chat', { ordered: true }));
    } else {
      this.pc.ondatachannel = (event) => this.bindChannel(event.channel);
    }

    // Two separate clocks. This one only asks "did we ever connect", and is
    // generous enough for a TURN allocation on a slow mobile link. The key-proof
    // clock does not start until a channel is actually open.
    this.verifyTimer = null;
    this.connectTimer = setTimeout(() => {
      const s = this.pc.connectionState;
      if (s !== 'connected' && s !== 'closed') this.reject('unreachable');
    }, CONNECT_TIMEOUT_MS);
  }

  signal(data) {
    sendToRelay({ type: 'signal', to: this.id, data });
  }

  async negotiate(options) {
    if (!this.canOffer || this.dead) return;
    try {
      this.makingOffer = true;
      if (options?.iceRestart) {
        // Explicit form, for engines without pc.restartIce(). Both produce an
        // offer carrying fresh ICE credentials; restartIce() is just the one
        // that cooperates with perfect negotiation on its own.
        await this.pc.setLocalDescription(await this.pc.createOffer({ iceRestart: true }));
      } else {
        await this.pc.setLocalDescription();
      }
      this.signal({ kind: 'desc', description: this.pc.localDescription.toJSON() });
    } catch {
      /* A failed offer surfaces through connectionstatechange. */
    } finally {
      this.makingOffer = false;
    }
  }

  /**
   * Bring this connection back after the signaling socket was away.
   *
   * Returns false if it is past saving and the caller should build a fresh peer.
   *
   * The case this exists for is a network change: the phone moves from wifi to
   * 5G, every candidate pair dies, and the signaling socket dies with them. The
   * DTLS and SCTP association on top is *not* renegotiated by an ICE restart, so
   * an open DataChannel survives one -- which means the room key, the verified
   * flag, and the peer's identity all carry through. Rebuilding from scratch
   * would discard all of that to fix what is only a routing problem.
   */
  resume() {
    if (this.dead || this.stale) return false;
    if (this.pc.signalingState === 'closed') return false;

    const s = this.pc.connectionState;
    if (s === 'connected') {
      // Only signaling had dropped. The media path never noticed, so restarting
      // ICE here would tear down a working connection to rebuild the same one.
      return true;
    }
    if (s === 'new' || s === 'connecting') {
      // Never established. Offers and candidates went missing while the socket
      // was down, so there is no agreed state to restart from.
      return false;
    }

    // 'disconnected' or 'failed': the pair is gone but the transport above it is
    // intact. This is exactly what an ICE restart is for.
    this.canOffer = true;
    clearTimeout(this.connectTimer);
    this.connectTimer = setTimeout(() => {
      if (this.pc.connectionState !== 'connected') this.reject('lost');
    }, CONNECT_TIMEOUT_MS);

    if (typeof this.pc.restartIce === 'function') {
      // Fires negotiationneeded, so negotiate() sends the offer. Glare with the
      // peer restarting at the same instant is what perfect negotiation handles.
      this.pc.restartIce();
    } else {
      this.negotiate({ iceRestart: true }).catch(noop);
    }
    return true;
  }

  /** Perfect negotiation, per the WebRTC spec's reference pattern. */
  async handleSignal(data) {
    if (this.dead) return;
    try {
      if (data.kind === 'desc') {
        const description = data.description;
        const collision = description.type === 'offer'
          && (this.makingOffer || this.pc.signalingState !== 'stable');

        this.ignoreOffer = !this.polite && collision;
        if (this.ignoreOffer) return;

        await this.pc.setRemoteDescription(description); // implicit rollback if polite
        await this.flushCandidates();

        if (description.type === 'offer') {
          await this.pc.setLocalDescription();
          this.signal({ kind: 'desc', description: this.pc.localDescription.toJSON() });
        }
        // Past the first exchange either side may renegotiate.
        this.canOffer = true;
      } else if (data.kind === 'ice') {
        if (!this.pc.remoteDescription) {
          this.pendingCandidates.push(data.candidate);
          return;
        }
        try {
          await this.pc.addIceCandidate(data.candidate);
        } catch (err) {
          if (!this.ignoreOffer) throw err;
        }
      }
    } catch {
      /* Malformed or out-of-order signaling; ICE state reporting covers it. */
    }
  }

  async flushCandidates() {
    const queued = this.pendingCandidates;
    this.pendingCandidates = [];
    for (const candidate of queued) {
      try { await this.pc.addIceCandidate(candidate); } catch { /* stale */ }
    }
  }

  bindChannel(channel) {
    this.channel = channel;
    channel.binaryType = 'arraybuffer';
    channel.bufferedAmountLowThreshold = DC_LOW_WATER;

    channel.onopen = () => {
      // Now, and only now, does the key-proof deadline start.
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
      if (!this.verified && this.verifyTimer === null) {
        this.verifyTimer = setTimeout(() => {
          if (!this.verified) this.reject('timeout');
        }, VERIFY_TIMEOUT_MS);
      }
      this.send(F.HELLO, {
        nick: state.nick,
        muted: audio.muted,
        deafened: audio.deafened,
      }).catch(noop);
    };
    channel.onmessage = (event) => this.receive(event.data);
    channel.onclose = () => {
      if (this.dead) return;
      // A closed channel is unrecoverable -- an ICE restart repairs routing, not
      // a dead SCTP association. Mark it so resume() rebuilds instead of trying.
      if (state.reconnecting) { this.stale = true; return; }
      removePeer(this.id, 'closed');
    };
  }

  async send(type, meta, payload) {
    if (this.dead || !this.channel || this.channel.readyState !== 'open') return;
    const sealed = await sealFrame(state.roomKey, encodeFrame(type, meta, payload));
    this.channel.send(sealed);
  }

  /** Send an already-sealed frame — lets a broadcast encrypt once for all peers. */
  sendSealed(sealed) {
    if (this.dead || !this.channel || this.channel.readyState !== 'open') return false;
    this.channel.send(sealed);
    return true;
  }

  async waitForDrain() {
    const channel = this.channel;
    if (!channel || channel.bufferedAmount < DC_HIGH_WATER) return;
    await new Promise((resolve) => {
      const done = () => { channel.removeEventListener('bufferedamountlow', done); resolve(); };
      channel.addEventListener('bufferedamountlow', done);
      setTimeout(done, 4000); // don't wedge a transfer on a stalled channel
    });
  }

  async receive(buffer) {
    let plain;
    try {
      plain = await openFrame(state.roomKey, buffer);
    } catch {
      // Cannot decrypt. On the very first frame that means the wrong passkey.
      if (!this.verified) this.reject('passkey');
      return;
    }
    if (!this.verified) {
      this.verified = true;
      clearTimeout(this.verifyTimer);
      renderPeers();
      renderTransport();
    }
    try {
      routeFrame(this, decodeFrame(plain));
    } catch {
      /* A peer sent us something we don't understand. Ignore that frame. */
    }
  }

  /** Refuse this peer, saying which of the two failures it was. */
  reject(reason) {
    if (this.dead) return;
    const label = this.label || this.nick || `peer ${this.id.slice(0, 6)}`;
    const reasons = {
      passkey: `Dropped ${label}: their passkey doesn't match this room.`,
      timeout: `Dropped ${label}: they never proved they hold the room key.`,
      unreachable: `Couldn't reach ${label}. Both sides may be behind networks that `
        + 'block direct connections, and the fallback relay did not answer either.',
      lost: `Lost the connection to ${label} and couldn't rebuild the route to them.`,
    };
    systemMessage(reasons[reason] || reasons.timeout, 'warn');
    removePeer(this.id, reason);
  }

  close() {
    this.dead = true;
    clearTimeout(this.verifyTimer);
    clearTimeout(this.connectTimer);
    if (this.channel) {
      this.channel.onmessage = null;
      this.channel.onclose = null;
      try { this.channel.close(); } catch { /* already gone */ }
    }
    this.pc.onicecandidate = null;
    this.pc.ontrack = null;
    this.pc.onnegotiationneeded = null;
    this.pc.onconnectionstatechange = null;
    try { this.pc.close(); } catch { /* already gone */ }
  }
}

function addPeer(peerId) {
  if (peerId === state.peerId || state.peers.has(peerId)) return;
  const peer = new Peer(peerId);
  peer.order = state.arrivalSeq;
  state.arrivalSeq += 1;
  state.peers.set(peerId, peer);
  renderPeers();
}

function removePeer(peerId, reason) {
  const peer = state.peers.get(peerId);
  if (!peer) return;
  state.peers.delete(peerId);
  peer.close();
  detachRemoteAudio(peerId);

  // Drop any partial transfer from this peer: half a file is not worth keeping.
  for (const [id, transfer] of state.incoming) {
    if (transfer.from === peerId) state.incoming.delete(id);
  }

  if (peer.verified && peer.nick && reason === 'left') {
    systemMessage(`${peer.label || peer.nick} left.`);
  }
  // Their name is free again, so whoever was carrying a counter because of them
  // may not need it any more.
  applyLabels();
  renderTransport();
}

/* --- Display names --------------------------------------------------------

   Two people in one room must never render identically, or a newcomer can pass
   for someone the others already trust. The relay cannot arbitrate this: it
   never sees a display name, because names ride the encrypted HELLO frame. So
   every client works it out independently and they all land on the same answer.

   The rule: peers are ordered by arrival, and the first claim on a name keeps
   it. A later claim on a name already taken renders with a counter -- "dan",
   then "dan (2)". Nobody who is already here is ever renamed by someone else
   arriving, which is what keeps the log stable.

   What this is *not*: proof of identity. Everyone in the room shares one key, so
   a peer can put any name it likes in its HELLO -- see README, "What this does
   not protect against". What it guarantees is that you can always tell two
   people apart, which is what the confusion depended on.
   ------------------------------------------------------------------------- */

/**
 * Adopt the relay's ordering of the room.
 *
 * Called once every peer in the roster exists, so each one can be given its
 * index. Anyone arriving later is numbered from arrivalSeq, and since the relay
 * broadcasts joins in one order to everybody, those numbers agree too.
 */
function applyRoster(roster) {
  if (!Array.isArray(roster) || !roster.length) return;
  roster.forEach((id, index) => {
    if (id === state.peerId) state.selfOrder = index;
    else {
      const peer = state.peers.get(id);
      if (peer) peer.order = index;
    }
  });
  state.arrivalSeq = roster.length;
}

/** The label currently shown for a peer id, ours included. */
function labelFor(peerId) {
  if (peerId && peerId === state.peerId) return state.label;
  return state.peers.get(peerId)?.label || null;
}

/** Recompute every label from the claims we hold. Pure; renders nothing. */
function resolveLabels() {
  const claims = [{ order: state.selfOrder, id: state.peerId, nick: state.nick, self: true }];
  for (const peer of state.peers.values()) {
    // A peer that has not sent HELLO has claimed nothing, so there is nothing
    // for it to collide with. It renders as "connecting…" until it does.
    if (peer.nick) claims.push({ order: peer.order, id: peer.id, nick: peer.nick, peer });
  }
  // Arrival order decides it. The peer id only breaks a tie that should not
  // happen, and does so the same way on every client.
  claims.sort((a, b) => a.order - b.order || (a.id < b.id ? -1 : 1));

  // Keyed on the label actually handed out, not on the claimed name. Counting
  // occurrences of the name would leave a hole: with two people called "dan", a
  // third could claim the literal string "dan (2)" and wear the label the second
  // one had been given. Taking the next *free* label closes that -- they get
  // "dan (2) (2)", which is inelegant and unambiguous, in that order of priority.
  const used = new Set();
  for (const claim of claims) {
    let label = claim.nick;
    let counter = 1;
    while (used.has(foldNick(label))) {
      counter += 1;
      label = `${claim.nick} (${counter})`;
    }
    used.add(foldNick(label));
    if (claim.self) state.label = label;
    else claim.peer.label = label;
  }
}

/** Recompute labels and push them everywhere a name is already on screen. */
function applyLabels() {
  resolveLabels();
  renderPeers();
  renderSelf();
  relabelLog();
}

/* ==========================================================================
   7. Encrypted application protocol
   ========================================================================== */

function routeFrame(peer, frame) {
  const { type, meta, payload } = frame;

  switch (type) {
    case F.HELLO: {
      const previous = peer.nick;
      const myLabelBefore = state.label;
      peer.nick = cleanNick(meta.nick);
      peer.muted = Boolean(meta.muted);
      peer.deafened = Boolean(meta.deafened);
      applyLabels();

      if (!previous) {
        systemMessage(`${peer.nick} joined.`);
        if (peer.label !== peer.nick) {
          systemMessage(
            `There is already a "${peer.nick}" here, so this one shows as "${peer.label}".`,
            'warn',
          );
        }
        if (state.label !== myLabelBefore) {
          // Only reachable if their HELLO reached us before we had ours resolved
          // against theirs -- rare, but say so rather than silently renaming.
          systemMessage(`You are now shown as "${state.label}" to tell you apart.`, 'warn');
        }
      } else if (previous !== peer.nick) {
        // A peer may rename itself at any time; nothing in the protocol can stop
        // that. Saying so out loud is the point -- a silent rename onto someone
        // else's name is exactly how impersonation would work.
        systemMessage(`"${previous}" is now calling themselves "${peer.label}".`, 'warn');
      }
      break;
    }

    case F.STATE:
      peer.muted = Boolean(meta.muted);
      peer.deafened = Boolean(meta.deafened);
      renderPeers();
      break;

    case F.CHAT:
      appendChat(peer.id, String(meta.text || '').slice(0, 4000), false);
      break;

    case F.FILE_START: {
      const size = Number(meta.size) || 0;
      if (size > MAX_FILE_BYTES) {
        systemMessage(`Refused ${meta.name} from ${peer.label}: over the ${formatBytes(MAX_FILE_BYTES)} in-memory limit.`, 'warn');
        break;
      }
      state.incoming.set(String(meta.id), {
        from: peer.id,
        meta: {
          name: String(meta.name || 'file').slice(0, 180),
          size,
          mime: String(meta.mime || 'application/octet-stream').slice(0, 120),
        },
        parts: [],
        received: 0,
      });
      break;
    }

    case F.FILE_CHUNK: {
      const transfer = state.incoming.get(String(meta.id));
      if (!transfer || transfer.from !== peer.id) break;
      transfer.received += payload.byteLength;
      if (transfer.received > transfer.meta.size + FILE_CHUNK_BYTES) {
        // Sender is exceeding what it declared. Stop buying memory for it.
        state.incoming.delete(String(meta.id));
        systemMessage(`Aborted ${transfer.meta.name}: the sender exceeded the size it declared.`, 'warn');
        break;
      }
      // subarray is a view on the frame buffer, so copy before holding it.
      transfer.parts.push(payload.slice().buffer);
      break;
    }

    case F.FILE_END: {
      const key = String(meta.id);
      const transfer = state.incoming.get(key);
      if (!transfer || transfer.from !== peer.id) break;
      state.incoming.delete(key);
      appendFileCard(peer.id, transfer, false);
      break;
    }

    case F.FILE_ABORT:
      state.incoming.delete(String(meta.id));
      break;

    default:
      break;
  }
}

function verifiedPeers() {
  return [...state.peers.values()].filter((p) => p.verified || p.channel?.readyState === 'open');
}

async function broadcastState() {
  const meta = { muted: audio.muted, deafened: audio.deafened };
  await Promise.allSettled([...state.peers.values()].map((p) => p.send(F.STATE, meta)));
}

async function sendChat(text) {
  const targets = verifiedPeers();
  appendChat(state.peerId, text, true);
  await Promise.allSettled(targets.map((p) => p.send(F.CHAT, { text })));
}

async function sendFile(file) {
  if (file.size > MAX_FILE_BYTES) {
    systemMessage(`${file.name} is ${formatBytes(file.size)}. The in-memory limit is ${formatBytes(MAX_FILE_BYTES)}.`, 'warn');
    return;
  }
  const targets = verifiedPeers();
  if (!targets.length) {
    systemMessage('Nobody to send to yet.', 'warn');
    return;
  }

  const id = randomHex(8);
  const meta = { id, name: file.name, size: file.size, mime: file.type || 'application/octet-stream' };
  const card = appendFileCard(state.peerId, { meta, parts: [], received: 0 }, true);

  await Promise.allSettled(targets.map((p) => p.send(F.FILE_START, meta)));

  let sent = 0;
  let seq = 0;
  try {
    while (sent < file.size) {
      const slice = file.slice(sent, Math.min(sent + FILE_CHUNK_BYTES, file.size));
      const chunk = new Uint8Array(await slice.arrayBuffer());

      // One key for the room, so one encryption serves every peer.
      const sealed = await sealFrame(state.roomKey, encodeFrame(F.FILE_CHUNK, { id, seq }, chunk));
      await Promise.all(targets.map(async (peer) => {
        await peer.waitForDrain();
        peer.sendSealed(sealed);
      }));

      sent += chunk.byteLength;
      seq += 1;
      updateFileProgress(card, sent / file.size);
    }
    await Promise.allSettled(targets.map((p) => p.send(F.FILE_END, { id })));
    finishFileCard(card, meta, null);
  } catch {
    await Promise.allSettled(targets.map((p) => p.send(F.FILE_ABORT, { id })));
    updateFileProgress(card, 0);
    systemMessage(`Couldn't finish sending ${file.name}.`, 'warn');
  }
}

/* ==========================================================================
   8. Audio
   ========================================================================== */

function ensureAudioContext() {
  if (!audio.ctx) audio.ctx = new (window.AudioContext || window.webkitAudioContext)();
  if (audio.ctx.state === 'suspended') audio.ctx.resume().catch(noop);
  return audio.ctx;
}

async function initMicrophone() {
  try {
    audio.stream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: false,
    });
    audio.track = audio.stream.getAudioTracks()[0] || null;
    if (audio.track) attachMeter('self', audio.stream);
    return true;
  } catch {
    audio.stream = null;
    audio.track = null;
    return false;
  }
}

/**
 * Observe a stream's level. The analyser is intentionally not connected to the
 * context destination — playback belongs to the <audio> element, and wiring
 * both would double every remote voice.
 */
function attachMeter(key, stream) {
  try {
    const ctx = ensureAudioContext();
    const source = ctx.createMediaStreamSource(stream);
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 512;
    analyser.smoothingTimeConstant = 0.65;
    source.connect(analyser);
    audio.meters.set(key, { source, analyser, buffer: new Uint8Array(analyser.fftSize) });
  } catch {
    /* Metering is a nicety; losing it must not break the call. */
  }
}

function detachMeter(key) {
  const meter = audio.meters.get(key);
  if (!meter) return;
  try { meter.source.disconnect(); } catch { /* already disconnected */ }
  audio.meters.delete(key);
}

function attachRemoteAudio(peerId, track) {
  const stream = new MediaStream([track]);
  let element = audio.sinks.get(peerId);
  if (!element) {
    element = document.createElement('audio');
    element.autoplay = true;
    element.playsInline = true;
    $('sinks').appendChild(element);
    audio.sinks.set(peerId, element);
  }
  element.srcObject = stream;
  element.muted = audio.deafened;
  element.play().catch(noop); // the join click is our user activation
  attachMeter(peerId, stream);
}

function detachRemoteAudio(peerId) {
  detachMeter(peerId);
  const element = audio.sinks.get(peerId);
  if (element) {
    element.srcObject = null;
    element.remove();
    audio.sinks.delete(peerId);
  }
}

function levelLoop() {
  for (const [key, meter] of audio.meters) {
    meter.analyser.getByteTimeDomainData(meter.buffer);
    let sum = 0;
    for (let i = 0; i < meter.buffer.length; i += 1) {
      const v = (meter.buffer[i] - 128) / 128;
      sum += v * v;
    }
    const rms = Math.sqrt(sum / meter.buffer.length);
    let level = (rms - VAD_FLOOR) / (VAD_CEIL - VAD_FLOOR);
    level = Math.max(0, Math.min(1, level));

    // A muted mic and deafened ears both mean "no signal to show".
    if (key === 'self' && (audio.muted || audio.deafened)) level = 0;
    if (key !== 'self' && audio.deafened) level = 0;

    applyLevel(key, level);
  }
  state.levelFrame = requestAnimationFrame(levelLoop);
}

function applyLevel(key, level) {
  const el = key === 'self' ? $('self-avatar') : document.querySelector(`[data-avatar="${key}"]`);
  if (!el) return;
  el.style.setProperty('--level', level.toFixed(3));
  el.classList.toggle('is-talking', level > VAD_TALKING);
}

function setMuted(muted) {
  audio.muted = muted;
  if (audio.track) audio.track.enabled = !muted && !audio.deafened;
  renderSelf();
  broadcastState().catch(noop);
}

function setDeafened(deafened) {
  audio.deafened = deafened;
  for (const element of audio.sinks.values()) element.muted = deafened;
  // Deafening also closes your mic: it is the "I've stepped away" control.
  if (deafened) audio.muted = true;
  if (audio.track) audio.track.enabled = !audio.muted && !deafened;
  renderSelf();
  broadcastState().catch(noop);
}

/* ==========================================================================
   9. Transport stats
   ========================================================================== */

async function collectStats() {
  for (const peer of state.peers.values()) {
    try {
      const report = await peer.pc.getStats();
      let pair = null;
      report.forEach((entry) => {
        if (entry.type === 'candidate-pair' && entry.state === 'succeeded'
            && (entry.nominated || !pair)) pair = entry;
      });
      if (!pair) { peer.stats = null; continue; }
      const local = pair.localCandidateId ? report.get(pair.localCandidateId) : null;
      const remote = pair.remoteCandidateId ? report.get(pair.remoteCandidateId) : null;
      const relayed = local?.candidateType === 'relay' || remote?.candidateType === 'relay';
      peer.stats = {
        rtt: typeof pair.currentRoundTripTime === 'number' ? Math.round(pair.currentRoundTripTime * 1000) : null,
        relayed,
      };
    } catch {
      peer.stats = null;
    }
  }
  renderTransport();
}

/* ==========================================================================
   10. Rendering
   ========================================================================== */

/** Paint a 4x4 mirrored mark from 16 bytes of HKDF output. */
function paintSeal(container, sealBytes) {
  container.innerHTML = '';
  container.classList.remove('is-destroying', 'is-empty');

  if (!sealBytes) {
    container.classList.add('is-empty');
    for (let i = 0; i < 16; i += 1) {
      const cell = document.createElement('div');
      cell.className = 'seal-cell';
      cell.style.setProperty('--i', String(i)); // staggers the latent shimmer
      container.appendChild(cell);
    }
    return;
  }

  // Left half is derived; right half mirrors it, so the mark reads as a shape
  // rather than as noise.
  const half = [];
  for (let i = 0; i < 8; i += 1) {
    const byte = sealBytes[i];
    half.push({ filled: byte > 56, color: SEAL_COLORS[byte & 3] });
  }
  for (let row = 0; row < 4; row += 1) {
    const a = half[row * 2];
    const b = half[row * 2 + 1];
    for (const spec of [a, b, b, a]) {
      const cell = document.createElement('div');
      cell.className = 'seal-cell';
      cell.style.setProperty('--i', String(container.children.length));
      if (spec.filled) {
        cell.style.background = spec.color;
      } else {
        cell.style.background = 'var(--raise)';
        cell.style.opacity = '0.4';
      }
      container.appendChild(cell);
    }
  }
}

function sealCode(sealBytes) {
  if (!sealBytes) return '···· ···· ···· ····';
  return hex(sealBytes.subarray(8, 16)).toUpperCase().replace(/(.{4})(?=.)/g, '$1 ');
}

function renderSeal() {
  paintSeal($('room-seal'), state.seal);
  $('seal-code').textContent = sealCode(state.seal);
}

function renderSelf() {
  const avatar = $('self-avatar');
  avatar.textContent = initialsOf(state.label);
  avatar.style.background = colorFor(state.label);
  $('self-nick').textContent = state.label;

  const bits = [];
  if (!audio.track) bits.push('No microphone');
  else if (audio.muted) bits.push('Muted');
  else bits.push('Mic live');
  if (audio.deafened) bits.push('Deafened');
  $('self-state').textContent = bits.join(' · ');

  const mic = $('mic-btn');
  mic.setAttribute('aria-pressed', String(audio.muted));
  mic.style.color = audio.muted ? 'var(--ember)' : 'var(--signal)';
  $('mic-slash').classList.toggle('hidden', !audio.muted);

  const deaf = $('deaf-btn');
  deaf.setAttribute('aria-pressed', String(audio.deafened));
  deaf.style.color = audio.deafened ? 'var(--ember)' : 'var(--muted)';
  $('deaf-slash').classList.toggle('hidden', !audio.deafened);
}

function renderPeers() {
  const list = $('peer-list');
  const peers = [...state.peers.values()];
  const total = peers.length + 1;

  $('peer-count').textContent = `${total}/${state.capacity}`;
  $('room-sub').textContent = total === 1
    ? 'Just you so far'
    : `${total} people · end-to-end encrypted`;

  // Status follows the roster rather than a polling timer.
  if (state.live && state.socket?.readyState === WebSocket.OPEN) {
    setStatus(peers.length ? 'live' : 'connecting',
      peers.length ? 'In room' : 'Waiting for others');
  }

  // The stepper's note quotes the headcount, so it has to move with the roster.
  renderCapacityControl();

  list.innerHTML = '';

  list.appendChild(peerRow({
    id: 'self',
    nick: state.label,
    suffix: 'you',
    muted: audio.muted,
    deafened: audio.deafened,
    connected: true,
    isHost: state.hostId === state.peerId,
  }));

  for (const peer of peers) {
    list.appendChild(peerRow({
      id: peer.id,
      nick: peer.label || 'connecting…',
      suffix: '',
      muted: peer.muted,
      deafened: peer.deafened,
      connected: peer.verified,
      isHost: state.hostId === peer.id,
    }));
  }
}

function peerRow({ id, nick, suffix, muted, deafened, connected, isHost }) {
  const li = document.createElement('li');
  li.className = 'peer-row flex items-center gap-2.5 rounded-lg px-1.5 py-1.5';

  const avatar = document.createElement('div');
  avatar.className = 'avatar h-7 w-7 rounded-full grid place-items-center text-[11px] font-semibold text-ink';
  avatar.style.background = connected ? colorFor(nick) : 'var(--raise)';
  avatar.textContent = connected ? initialsOf(nick) : '·';
  if (id !== 'self') avatar.dataset.avatar = id;
  if (!connected) avatar.style.color = 'var(--faint)';
  li.appendChild(avatar);

  const label = document.createElement('div');
  label.className = 'min-w-0 flex-1';
  const name = document.createElement('p');
  name.className = 'text-[13px] truncate leading-tight flex items-center gap-1.5';
  // Amber marks the host. It is the same token the disclosure panel uses, so
  // keep this restrained -- a glyph and the name's colour, no filled badge.
  name.style.color = isHost ? 'var(--amber)' : (connected ? 'var(--text)' : 'var(--faint)');

  if (isHost) {
    const crown = document.createElement('span');
    crown.className = 'flex-none text-[11px] leading-none';
    crown.textContent = '👑';
    crown.title = 'Room host — sets the room size';
    crown.setAttribute('role', 'img');
    crown.setAttribute('aria-label', 'host');
    name.appendChild(crown);
  }

  const nameText = document.createElement('span');
  nameText.className = 'truncate';
  nameText.textContent = nick;
  name.appendChild(nameText);

  if (suffix) {
    const tag = document.createElement('span');
    // No left margin: the row is flex now, so the gap already spaces this.
    tag.className = 'text-faint text-[11px] flex-none';
    tag.textContent = suffix;
    name.appendChild(tag);
  }
  label.appendChild(name);
  li.appendChild(label);

  const icons = document.createElement('div');
  icons.className = 'flex-none flex items-center gap-1';
  if (muted) icons.appendChild(stateIcon('muted'));
  if (deafened) icons.appendChild(stateIcon('deafened'));
  li.appendChild(icons);

  return li;
}

function stateIcon(kind) {
  const span = document.createElement('span');
  span.title = kind === 'muted' ? 'Microphone off' : 'Not listening';
  span.className = 'leading-none';
  span.style.color = 'var(--ember)';
  span.innerHTML = kind === 'muted'
    ? '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 2a3 3 0 0 0-3 3v6a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"/><path d="M19 10v1a7 7 0 0 1-14 0v-1"/><path d="M3 3l18 18"/></svg>'
    : '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M4 14v-3a8 8 0 0 1 16 0v3"/><path d="M3 3l18 18"/></svg>';
  return span;
}

/**
 * Show the stepper to the host and nobody else, and keep it honest about what
 * each button will actually do.
 */
/** Pending stepper target, or null when the display matches the relay. */
let capacityIntent = null;

function renderCapacityControl() {
  const panel = $('capacity-control');
  const isHost = Boolean(state.peerId) && state.hostId === state.peerId;

  panel.classList.toggle('hidden', !isHost);
  if (!isHost) return;

  const occupied = state.peers.size + 1;
  const floor = Math.max(state.minCapacity, occupied);
  const shown = capacityIntent === null ? state.capacity : capacityIntent;

  $('capacity-value').textContent = `${occupied} / ${shown}`;
  // Lowering stops at the headcount: nobody gets evicted by a number change.
  $('capacity-down').disabled = shown <= floor;
  $('capacity-up').disabled = shown >= state.ceiling;

  let note;
  if (shown > MESH_SAFE_CAPACITY) {
    note = `Above ${MESH_SAFE_CAPACITY}, every peer uploads more audio than the mesh handles well. Text and files are fine.`;
  } else if (shown <= occupied) {
    note = 'At capacity. Raise the limit to let anyone else in.';
  } else {
    note = `Room for ${shown - occupied} more. Ceiling is ${state.ceiling}.`;
  }
  $('capacity-note').textContent = note;
}

/**
 * Step the limit by `delta`.
 *
 * Clicks accumulate against a local intent rather than against the confirmed
 * capacity. Reading state.capacity per click would silently drop every press
 * that landed before the relay's answer came back, so a quick double-tap on +
 * would move the number by one.
 */
function stepCapacity(delta) {
  const floor = Math.max(state.minCapacity, state.peers.size + 1);
  const from = capacityIntent === null ? state.capacity : capacityIntent;
  const target = Math.max(floor, Math.min(state.ceiling, from + delta));
  if (target === from) return;

  capacityIntent = target;
  renderCapacityControl(); // show the intent immediately; the relay confirms it
  sendToRelay({ type: 'set-capacity', capacity: target });
}

/** A range only when there is one. On loopback every value is 0, and "0–0 ms"
 *  reads like a broken readout rather than a fast link. */
function formatRtt(values) {
  if (!values.length) return 'measuring';
  const low = Math.min(...values);
  const high = Math.max(...values);
  if (low === high) return low < 1 ? '<1 ms' : `${low} ms`;
  return `${low < 1 ? '<1' : low}–${high} ms`;
}

function renderTransport() {
  const dl = $('transport');
  const peers = [...state.peers.values()];
  dl.innerHTML = '';

  const rows = [];
  if (!peers.length) {
    rows.push(['peers', '0 connected', 'var(--faint)']);
  } else {
    const connected = peers.filter((p) => p.pc.connectionState === 'connected').length;
    const rtts = peers.map((p) => p.stats?.rtt).filter((v) => typeof v === 'number');
    const relayed = peers.filter((p) => p.stats?.relayed).length;

    rows.push(['links', `${connected}/${peers.length} connected`,
      connected === peers.length ? 'var(--signal)' : 'var(--amber)']);
    rows.push(['rtt', formatRtt(rtts), 'var(--wire)']);
    rows.push(['path', relayed ? `${relayed} relayed` : 'direct',
      relayed ? 'var(--amber)' : 'var(--signal)']);
  }
  rows.push(['cipher', 'AES-GCM-256', 'var(--wire)']);
  rows.push(['store', 'none', 'var(--signal)']);
  // Where signaling actually went. On a split deploy this is the first thing
  // you want to see when nothing connects.
  if (state.signalingUrl) {
    let relayHost = state.signalingUrl;
    try { relayHost = new URL(state.signalingUrl).host; } catch { /* show it raw */ }
    rows.push([
      'relay',
      relayHost + (state.signalingSource === 'same-origin' ? '' : ' *'),
      state.signalingSource === 'same-origin' ? 'var(--muted)' : 'var(--wire)',
    ]);
  }

  for (const [key, value, color] of rows) {
    const row = document.createElement('div');
    row.className = 'flex items-baseline justify-between gap-2';
    const dt = document.createElement('dt');
    dt.className = 'text-faint';
    dt.textContent = key;
    const dd = document.createElement('dd');
    dd.className = 'text-right';
    dd.style.color = color;
    dd.textContent = value;
    row.append(dt, dd);
    dl.appendChild(row);
  }
}

/* --- Log ---------------------------------------------------------------- */

function atBottom(el) {
  return el.scrollHeight - el.scrollTop - el.clientHeight < 90;
}

function pushToLog(node) {
  const log = $('log');
  const wasAtBottom = atBottom(log);
  log.appendChild(node);
  if (wasAtBottom) log.scrollTop = log.scrollHeight;
}

/**
 * The avatar-plus-header frame every message shares.
 *
 * Takes a peer id rather than a name, and stamps it on the two nodes that show
 * one. A display name can move after the fact -- someone leaves and frees up a
 * name, or a second "dan" arrives -- and a log still showing the old one is the
 * confusion this whole mechanism exists to prevent. relabelLog() walks these
 * stamps.
 */
function messageShell(authorId, mine) {
  const label = labelFor(authorId) || 'peer';

  const wrap = document.createElement('div');
  wrap.className = 'msg-enter flex gap-3 py-1.5';

  const avatar = document.createElement('div');
  avatar.className = 'h-8 w-8 flex-none rounded-full grid place-items-center text-[12px] font-semibold text-ink mt-0.5';
  avatar.style.background = colorFor(label);
  avatar.textContent = initialsOf(label);
  avatar.dataset.author = authorId;
  avatar.dataset.field = 'avatar';
  wrap.appendChild(avatar);

  const column = document.createElement('div');
  column.className = 'min-w-0 flex-1';

  const head = document.createElement('div');
  head.className = 'flex items-baseline gap-2';
  const name = document.createElement('span');
  name.className = 'text-[13.5px] font-semibold';
  name.style.color = mine ? 'var(--text)' : colorFor(label);
  name.textContent = label;
  name.dataset.author = authorId;
  name.dataset.field = 'name';
  if (mine) name.dataset.mine = '1';
  const time = document.createElement('span');
  time.className = 'text-[11px] text-faint';
  time.textContent = clockTime();
  head.append(name, time);
  column.appendChild(head);

  wrap.appendChild(column);
  return { wrap, column };
}

/** Repaint author names already in the log after a label change. */
function relabelLog() {
  for (const node of $('log').querySelectorAll('[data-author]')) {
    const label = labelFor(node.dataset.author);
    if (!label) continue;
    if (node.dataset.field === 'avatar') {
      node.textContent = initialsOf(label);
      node.style.background = colorFor(label);
    } else {
      node.textContent = label;
      if (node.dataset.mine !== '1') node.style.color = colorFor(label);
    }
  }
}

function appendChat(authorId, text, mine) {
  if (!text) return;
  const { wrap, column } = messageShell(authorId, mine);
  const body = document.createElement('p');
  body.className = 'msg-body text-[14.5px] leading-relaxed mt-0.5';
  body.textContent = text; // textContent, never innerHTML: peer input is untrusted
  column.appendChild(body);
  pushToLog(wrap);
}

function systemMessage(text, tone) {
  const row = document.createElement('div');
  row.className = 'msg-enter flex items-start gap-2 py-1.5 pl-11';
  const dot = document.createElement('span');
  dot.className = 'mt-[7px] h-1.5 w-1.5 rounded-full flex-none';
  dot.style.background = tone === 'warn' ? 'var(--amber)' : 'var(--faint)';
  const body = document.createElement('p');
  body.className = 'msg-body text-[13px] leading-relaxed';
  body.style.color = tone === 'warn' ? 'var(--amber)' : 'var(--muted)';
  body.textContent = text;
  row.append(dot, body);
  pushToLog(row);
}

function appendFileCard(authorId, transfer, mine) {
  const { wrap, column } = messageShell(authorId, mine);

  const card = document.createElement('div');
  card.className = 'mt-1.5 rounded-lg border hairline bg-ink px-3 py-2.5 max-w-[420px]';

  const head = document.createElement('div');
  head.className = 'flex items-center gap-2.5';

  const icon = document.createElement('div');
  icon.className = 'h-8 w-8 flex-none rounded grid place-items-center';
  icon.style.background = 'var(--raise)';
  icon.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#8b95a7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>';
  head.appendChild(icon);

  const info = document.createElement('div');
  info.className = 'min-w-0 flex-1';
  const name = document.createElement('p');
  name.className = 'text-[13px] font-medium truncate';
  name.textContent = transfer.meta.name;
  const meta = document.createElement('p');
  meta.className = 'text-[11px] text-faint';
  meta.textContent = formatBytes(transfer.meta.size);
  info.append(name, meta);
  head.appendChild(info);

  const action = document.createElement('div');
  action.className = 'flex-none';
  head.appendChild(action);

  card.appendChild(head);

  // Geometry here is set inline rather than with utility classes. Tailwind's
  // Play CDN generates CSS by observing the DOM, and an <i> that never receives
  // its `block` class stays inline -- where a width is simply ignored, so the
  // bar renders at zero no matter what percentage it is told to be.
  const bar = document.createElement('div');
  bar.className = 'mt-2.5 rounded-full overflow-hidden';
  bar.style.height = '4px';
  bar.style.background = 'var(--raise)';
  const fill = document.createElement('i');
  fill.dataset.role = 'file-progress';
  fill.style.display = 'block';
  fill.style.height = '100%';
  fill.style.background = 'var(--signal)';
  fill.style.width = mine ? '0%' : '100%';
  // No width transition. It bought nothing on a bar that steps once per 16 KiB
  // chunk, and an in-flight transition meant the rendered width lagged the value
  // it had been given -- a finished transfer could sit showing an unfilled bar.
  bar.appendChild(fill);
  card.appendChild(bar);

  column.appendChild(card);
  pushToLog(wrap);

  const handle = { card, fill, action, meta };
  if (!mine) {
    bar.remove();
    finishFileCard(handle, transfer.meta, transfer.parts);
  }
  return handle;
}

function updateFileProgress(handle, ratio) {
  handle.fill.style.width = `${Math.round(ratio * 100)}%`;
}

/**
 * Turn a completed transfer into a save button, or mark an outgoing one sent.
 * `parts` is null for files we sent — there is nothing to hand back to us.
 */
function finishFileCard(handle, meta, parts) {
  if (!parts) {
    handle.fill.style.width = '100%';
    handle.meta.textContent = `${formatBytes(meta.size)} · sent`;
    return;
  }
  const blob = new Blob(parts, { type: meta.mime });
  const url = URL.createObjectURL(blob);
  state.blobUrls.add(url);

  const link = document.createElement('a');
  link.href = url;
  link.download = meta.name;
  link.textContent = 'Save';
  link.className = 'text-[12px] font-semibold rounded-md px-2.5 py-1.5 transition';
  link.style.background = 'var(--raise)';
  link.style.color = 'var(--signal)';
  handle.action.appendChild(link);
  handle.meta.textContent = `${formatBytes(meta.size)} · in memory only`;
}

/* --- Status ------------------------------------------------------------- */

function setStatus(kind, text) {
  const dot = $('status-dot');
  const colors = {
    connecting: 'var(--amber)',
    live: 'var(--signal)',
    degraded: 'var(--amber)',
    destroyed: 'var(--ember)',
  };
  dot.style.background = colors[kind] || 'var(--faint)';
  dot.classList.toggle('pulse-dot', kind === 'connecting');
  $('status-text').textContent = text;
}

/* ==========================================================================
   11. Lifecycle
   ========================================================================== */

function fatal(text) {
  $('fatal-text').textContent = text;
  $('fatal-screen').classList.remove('hidden');
  $('join-screen').classList.add('hidden');
}

function joinError(text) {
  const box = $('join-error');
  box.textContent = text;
  box.classList.remove('hidden');
  $('join-work').classList.add('hidden');
  $('join-btn').disabled = false;
}

const RELAY_ERRORS = {
  room_full: 'That room is full. Its host sets the limit, so ask them to raise it.',
  bad_room_id: 'The relay rejected the room identifier. Reload and try again.',
  rate_limited: 'The relay rate-limited this connection. Wait a moment and rejoin.',
};

/** Naming the address is the difference between a fixable error and a mystery. */
function unreachableMessage() {
  const where = state.signalingUrl || '(no address resolved)';
  if (state.signalingSource === 'fallback') {
    return `Can't reach the relay at ${where}. That address is this build's default `
      + 'for static hosting — set window.SIGNALING_URL in index.html to point at your own relay.';
  }
  if (state.signalingSource === 'configured') {
    return `Can't reach the relay at ${where}, which is the window.SIGNALING_URL `
      + 'configured in index.html. Check the address and that the relay is running.';
  }
  return `Can't reach the relay at ${where}. Check that the server is running.`;
}

async function join(roomName, passkey, nick, wantMic, requestedCapacity) {
  $('join-btn').disabled = true;
  $('join-error').classList.add('hidden');
  $('join-work').classList.remove('hidden');
  $('join-work-text').textContent =
    `deriving room key · PBKDF2-SHA256 · ${PBKDF2_ITERATIONS.toLocaleString('en-US')} iterations`;

  let session;
  try {
    // Yield once so the work state paints before PBKDF2 occupies the thread.
    // requestAnimationFrame alone is not safe here: a hidden or background tab
    // never fires it, which would strand the join forever. Race it against a
    // timer so the yield always completes.
    await new Promise((resolve) => {
      requestAnimationFrame(resolve);
      setTimeout(resolve, 50);
    });
    session = await deriveSession(roomName, passkey);
  } catch {
    joinError('Key derivation failed in this browser.');
    return;
  }

  state.roomName = roomName;
  // Cleaned here as well as on arrival, so what peers show for us is what we
  // show for ourselves.
  state.nick = cleanNick(nick);
  state.label = state.nick;
  state.roomKey = session.roomKey;
  state.roomId = session.roomId;
  state.seal = session.seal;
  // One identity for the life of this tab, so a reconnect is recognisable as
  // the same person rather than a new arrival.
  state.sessionId = randomHex(16);
  state.reconnectAttempt = 0;
  state.reconnecting = false;
  state.arrivalSeq = 0;

  let micReady = false;
  if (wantMic) {
    $('join-work-text').textContent = 'waiting for microphone permission';
    micReady = await initMicrophone();
  }

  $('join-work-text').textContent = `connecting to relay · room ${session.roomId.slice(0, 12)}…`;

  let welcome;
  try {
    welcome = await connectRelay(session.roomId, requestedCapacity);
  } catch (err) {
    state.roomKey = null;
    state.seal = null;
    joinError(
      err.message === 'relay_unreachable'
        ? unreachableMessage()
        : RELAY_ERRORS[err.message] || 'The relay refused the connection.',
    );
    return;
  }

  // We're in. Show the room.
  state.live = true;
  $('join-screen').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('room-label').textContent = roomName;

  // The relay is authoritative for all of this; adopt its answer, not our ask.
  applyWelcome(welcome);

  renderSeal();
  renderSelf();
  setStatus(welcome.peers.length ? 'live' : 'connecting',
    welcome.peers.length ? 'In room' : 'Waiting for others');

  if (wantMic && !micReady) {
    systemMessage('Joined without a microphone — the browser denied access. You can still read, type, and hear others.', 'warn');
  }
  if (state.hostId === state.peerId) {
    systemMessage(`You opened this room, so you're the host. Room size is ${state.capacity}.`);
  }
  systemMessage(
    welcome.peers.length
      ? `Connecting to ${welcome.peers.length} ${welcome.peers.length === 1 ? 'person' : 'people'}.`
      : 'Room open. Share the room name and passkey out of band, and whoever joins lands here.',
  );

  for (const peerId of welcome.peers) addPeer(peerId);
  // After the peers exist, so each one can be handed its position.
  applyRoster(welcome.roster);
  applyLabels();

  state.levelFrame = requestAnimationFrame(levelLoop);
  state.statsTimer = setInterval(collectStats, 2000);

  $('composer-input').focus();
}

/**
 * Tear the session down. Called on Leave and on page hide.
 *
 * Honest note on "keys discarded": dropping the CryptoKey reference makes the
 * key unreachable and eligible for collection. Because it was created
 * non-extractable, its raw bytes were never in JS memory to begin with, so
 * there is nothing here that a zero-fill could reach. JavaScript cannot force
 * the browser to scrub its own key store; what it can do is never hold the
 * material and stop referring to the handle, which is what happens here.
 */
function destroySession() {
  if (!state.live) return;
  state.live = false;

  sendToRelay({ type: 'leave' });

  for (const peer of state.peers.values()) peer.close();
  state.peers.clear();

  for (const peerId of [...audio.sinks.keys()]) detachRemoteAudio(peerId);
  detachMeter('self');
  if (audio.stream) for (const track of audio.stream.getTracks()) track.stop();
  audio.stream = null;
  audio.track = null;
  if (audio.ctx) { audio.ctx.close().catch(noop); audio.ctx = null; }

  if (state.socket) {
    state.socket.onclose = null;
    try { state.socket.close(); } catch { /* already closing */ }
    state.socket = null;
  }

  if (state.reconnectTimer) { clearTimeout(state.reconnectTimer); state.reconnectTimer = null; }
  if (state.statsTimer) { clearInterval(state.statsTimer); state.statsTimer = null; }
  if (state.levelFrame) { cancelAnimationFrame(state.levelFrame); state.levelFrame = null; }

  for (const url of state.blobUrls) URL.revokeObjectURL(url);
  state.blobUrls.clear();
  state.incoming.clear();

  state.roomKey = null;
  state.seal = null;
  state.roomId = '';
  state.hostId = '';
  state.sessionId = '';
  state.reconnectAttempt = 0;
  state.reconnecting = false;
  state.arrivalSeq = 0;
  state.selfOrder = 0;
  capacityIntent = null;
}

/** The one orchestrated moment: the room's mark comes apart. */
function showDestroyed() {
  const seal = $('room-seal');
  seal.classList.add('is-destroying');
  $('seal-code').textContent = '0000 0000 0000 0000';
  $('seal-code').style.color = 'var(--faint)';
  $('seal-note').textContent = 'Key discarded. This room no longer exists.';

  $('log').innerHTML = '';
  $('peer-list').innerHTML = '';
  $('peer-count').textContent = `0/${state.capacity}`;
  $('capacity-control').classList.add('hidden');
  $('room-sub').textContent = 'Session ended';
  setStatus('destroyed', 'Destroyed');
  renderTransport();

  // The self panel has to stop claiming a live microphone: the track is stopped
  // and the context is closed by now.
  const avatar = $('self-avatar');
  avatar.style.setProperty('--level', '0');
  avatar.style.background = 'var(--raise)';
  avatar.style.color = 'var(--faint)';
  $('self-state').textContent = 'Session ended';
  for (const id of ['mic-btn', 'deaf-btn']) {
    $(id).disabled = true;
    $(id).style.color = 'var(--faint)';
  }
  $('composer-input').disabled = true;
  $('send-btn').disabled = true;
  $('attach-btn').disabled = true;
  $('leave-btn').disabled = true;

  systemMessage('Room destroyed. The log is cleared and the key is discarded. Reload to open a new room.');
}

/* ==========================================================================
   12. Events
   ========================================================================== */

function wireEvents() {
  $('join-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const roomName = $('f-room').value.trim();
    const passkey = $('f-passkey').value;
    const nick = $('f-nick').value.trim();
    if (!roomName || !passkey || !nick) return;
    const capacity = Number.parseInt($('f-capacity').value, 10);
    join(
      roomName, passkey, nick, $('f-mic').checked,
      Number.isFinite(capacity) ? capacity : DEFAULT_CAPACITY,
    ).catch(() => {
      joinError('Something failed while joining. Reload and try again.');
    });
  });

  $('capacity-down').addEventListener('click', () => stepCapacity(-1));
  $('capacity-up').addEventListener('click', () => stepCapacity(1));

  $('leave-btn').addEventListener('click', () => {
    destroySession();
    showDestroyed();
  });

  // pagehide is the reliable one; beforeunload does not fire on mobile.
  window.addEventListener('pagehide', destroySession);
  window.addEventListener('beforeunload', destroySession);

  const input = $('composer-input');
  const submit = () => {
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    sendChat(text).catch(() => systemMessage("Couldn't send that message.", 'warn'));
  };

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      submit();
    }
  });
  $('send-btn').addEventListener('click', submit);

  $('attach-btn').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', (event) => {
    for (const file of event.target.files) sendFile(file).catch(noop);
    event.target.value = '';
  });

  $('mic-btn').addEventListener('click', () => {
    if (!audio.track) {
      systemMessage('No microphone in this session. Reload and join with the microphone enabled.', 'warn');
      return;
    }
    setMuted(!audio.muted);
  });
  $('deaf-btn').addEventListener('click', () => setDeafened(!audio.deafened));

  document.addEventListener('keydown', (event) => {
    if (!state.live) return;
    const typing = event.target.matches('input, textarea');
    if (typing || event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === 'm' || event.key === 'M') { if (audio.track) setMuted(!audio.muted); }
    if (event.key === 'd' || event.key === 'D') setDeafened(!audio.deafened);
  });

  // Drag and drop
  const veil = $('drop-veil');
  let dragDepth = 0;
  const isFileDrag = (event) => [...(event.dataTransfer?.types || [])].includes('Files');

  window.addEventListener('dragenter', (event) => {
    if (!state.live || !isFileDrag(event)) return;
    event.preventDefault();
    dragDepth += 1;
    veil.classList.add('is-active');
  });
  window.addEventListener('dragover', (event) => {
    if (state.live && isFileDrag(event)) event.preventDefault();
  });
  window.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) veil.classList.remove('is-active');
  });
  window.addEventListener('drop', (event) => {
    if (!state.live || !isFileDrag(event)) return;
    event.preventDefault();
    dragDepth = 0;
    veil.classList.remove('is-active');
    for (const file of event.dataTransfer.files) sendFile(file).catch(noop);
  });

  // Narrow-screen rail
  const rail = $('rail');
  const scrim = $('rail-scrim');
  const closeRail = () => { rail.classList.remove('is-open'); scrim.classList.add('hidden'); };
  $('rail-toggle').addEventListener('click', () => {
    const open = rail.classList.toggle('is-open');
    scrim.classList.toggle('hidden', !open);
  });
  scrim.addEventListener('click', closeRail);
  // Widening past the breakpoint puts the rail back in the layout, so a scrim
  // left over from the drawer would dim the app for no reason.
  window.addEventListener('resize', () => {
    if (window.innerWidth > 820) closeRail();
  });
}

/* ==========================================================================
   Boot
   ========================================================================== */

function boot() {
  paintSeal($('brand-seal'), null);

  if (!window.isSecureContext || !window.crypto?.subtle) {
    fatal(
      'This app needs the Web Crypto API, which browsers only expose in a secure context. '
      + 'Open it over https://, or on http://localhost or http://127.0.0.1 for local testing. '
      + 'A plain-http LAN address will not work.',
    );
    return;
  }
  if (!window.RTCPeerConnection) {
    fatal('This browser has no WebRTC support, so peer-to-peer connections are not possible here.');
    return;
  }

  // Resolve the relay address now. Finding out it is wrong after 600 000 PBKDF2
  // iterations is a worse experience than finding out before the form is usable.
  const signaling = resolveSignalingUrl();
  state.signalingUrl = signaling.url || '';
  state.signalingSource = signaling.source;

  wireEvents();

  if (signaling.error) {
    // Not fatal: the address is configuration, and someone may want to read the
    // page anyway. But say so up front rather than at submit time.
    joinError(signaling.error);
    $('join-btn').disabled = true;
    return;
  }

  $('f-room').focus();
}

boot();
