/*
 * EnDa Chat — client.
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
const KDF_DOMAIN = 'endachat/v1';
const WIRE_VERSION = 1;

const MAX_PEERS = 8;

/** Interop-safe SCTP payload. Encryption adds 13 header + 16 tag bytes. */
const FILE_CHUNK_BYTES = 16 * 1024;
/** Received files live in RAM, so this is a real ceiling, not a policy. */
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const DC_HIGH_WATER = 1024 * 1024;
const DC_LOW_WATER = 256 * 1024;

/** A peer that has not sent a decryptable frame by now does not know the passkey. */
const VERIFY_TIMEOUT_MS = 12_000;

/* RMS thresholds for the activity ring, tuned against typical mic levels. */
const VAD_FLOOR = 0.018;
const VAD_CEIL = 0.22;
const VAD_TALKING = 0.14;

const ICE_SERVERS = [
  { urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] },
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
  nick: '',
  peerId: '',
  socket: null,
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

function relayUrl() {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${location.host}/ws`;
}

function sendToRelay(message) {
  const sock = state.socket;
  if (sock && sock.readyState === WebSocket.OPEN) {
    sock.send(JSON.stringify(message));
  }
}

/** Resolves once the relay has admitted us, rejects with a reason code. */
function connectRelay(roomId) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const sock = new WebSocket(relayUrl());
    state.socket = sock;

    sock.onopen = () => sendToRelay({ type: 'join', room: roomId });

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
      if (state.live) {
        systemMessage('Lost the connection to the relay. Peers already connected stay connected; nobody new can join.', 'warn');
        setStatus('degraded', 'Relay offline');
      }
    };
  });
}

function handleRelayMessage(message) {
  switch (message.type) {
    case 'peer-join':
      // A newcomer. Both sides create the connection; the lexicographically
      // smaller peer id opens the DataChannel and makes the first offer, which
      // is what keeps the two sides from offering at once.
      addPeer(message.peerId);
      break;

    case 'peer-leave':
      removePeer(message.peerId, 'left');
      break;

    case 'signal': {
      const peer = state.peers.get(message.from);
      if (peer) peer.handleSignal(message.data);
      break;
    }

    case 'error':
      if (message.code === 'room_full') {
        systemMessage(`This room is full at ${message.limit || MAX_PEERS} people.`, 'warn');
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
    this.nick = null;
    this.muted = false;
    this.deafened = false;
    this.verified = false;
    this.dead = false;

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
      if (s === 'failed' || s === 'closed') removePeer(this.id, 'failed');
      renderTransport();
    };

    if (this.initiator) {
      this.bindChannel(this.pc.createDataChannel('enda', { ordered: true }));
    } else {
      this.pc.ondatachannel = (event) => this.bindChannel(event.channel);
    }

    this.verifyTimer = setTimeout(() => {
      if (!this.verified) this.reject('timeout');
    }, VERIFY_TIMEOUT_MS);
  }

  signal(data) {
    sendToRelay({ type: 'signal', to: this.id, data });
  }

  async negotiate() {
    if (!this.canOffer || this.dead) return;
    try {
      this.makingOffer = true;
      await this.pc.setLocalDescription();
      this.signal({ kind: 'desc', description: this.pc.localDescription.toJSON() });
    } catch {
      /* A failed offer surfaces through connectionstatechange. */
    } finally {
      this.makingOffer = false;
    }
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
      this.send(F.HELLO, {
        nick: state.nick,
        muted: audio.muted,
        deafened: audio.deafened,
      }).catch(noop);
    };
    channel.onmessage = (event) => this.receive(event.data);
    channel.onclose = () => { if (!this.dead) removePeer(this.id, 'closed'); };
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

  /** Refuse this peer: it cannot prove it holds the room key. */
  reject(reason) {
    if (this.dead) return;
    const label = this.nick || `peer ${this.id.slice(0, 6)}`;
    systemMessage(
      reason === 'passkey'
        ? `Dropped ${label}: their passkey doesn't match this room.`
        : `Dropped ${label}: they never proved they hold the room key.`,
      'warn',
    );
    removePeer(this.id, reason);
  }

  close() {
    this.dead = true;
    clearTimeout(this.verifyTimer);
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
  state.peers.set(peerId, new Peer(peerId));
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
    systemMessage(`${peer.nick} left.`);
  }
  renderPeers();
  renderTransport();
}

/* ==========================================================================
   7. Encrypted application protocol
   ========================================================================== */

function routeFrame(peer, frame) {
  const { type, meta, payload } = frame;

  switch (type) {
    case F.HELLO: {
      const first = !peer.nick;
      peer.nick = String(meta.nick || 'peer').slice(0, 24);
      peer.muted = Boolean(meta.muted);
      peer.deafened = Boolean(meta.deafened);
      if (first) systemMessage(`${peer.nick} joined.`);
      renderPeers();
      break;
    }

    case F.STATE:
      peer.muted = Boolean(meta.muted);
      peer.deafened = Boolean(meta.deafened);
      renderPeers();
      break;

    case F.CHAT:
      appendChat(peer.nick || 'peer', String(meta.text || '').slice(0, 4000), false);
      break;

    case F.FILE_START: {
      const size = Number(meta.size) || 0;
      if (size > MAX_FILE_BYTES) {
        systemMessage(`Refused ${meta.name} from ${peer.nick}: over the ${formatBytes(MAX_FILE_BYTES)} in-memory limit.`, 'warn');
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
      appendFileCard(peer.nick || 'peer', transfer, false);
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
  appendChat(state.nick, text, true);
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
  const card = appendFileCard(state.nick, { meta, parts: [], received: 0 }, true);

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
  avatar.textContent = initialsOf(state.nick);
  avatar.style.background = colorFor(state.nick);
  $('self-nick').textContent = state.nick;

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

  $('peer-count').textContent = `${total}/${MAX_PEERS}`;
  $('room-sub').textContent = total === 1
    ? 'Just you so far'
    : `${total} people · end-to-end encrypted`;

  // Status follows the roster rather than a polling timer.
  if (state.live && state.socket?.readyState === WebSocket.OPEN) {
    setStatus(peers.length ? 'live' : 'connecting',
      peers.length ? 'In room' : 'Waiting for others');
  }

  list.innerHTML = '';

  list.appendChild(peerRow({
    id: 'self',
    nick: `${state.nick}`,
    suffix: 'you',
    muted: audio.muted,
    deafened: audio.deafened,
    connected: true,
  }));

  for (const peer of peers) {
    list.appendChild(peerRow({
      id: peer.id,
      nick: peer.nick || `connecting…`,
      suffix: '',
      muted: peer.muted,
      deafened: peer.deafened,
      connected: peer.verified,
    }));
  }
}

function peerRow({ id, nick, suffix, muted, deafened, connected }) {
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
  name.className = 'text-[13px] truncate leading-tight';
  name.style.color = connected ? 'var(--text)' : 'var(--faint)';
  name.textContent = nick;
  if (suffix) {
    const tag = document.createElement('span');
    tag.className = 'text-faint text-[11px] ml-1.5';
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

function messageShell(author, mine) {
  const wrap = document.createElement('div');
  wrap.className = 'msg-enter flex gap-3 py-1.5';

  const avatar = document.createElement('div');
  avatar.className = 'h-8 w-8 flex-none rounded-full grid place-items-center text-[12px] font-semibold text-ink mt-0.5';
  avatar.style.background = colorFor(author);
  avatar.textContent = initialsOf(author);
  wrap.appendChild(avatar);

  const column = document.createElement('div');
  column.className = 'min-w-0 flex-1';

  const head = document.createElement('div');
  head.className = 'flex items-baseline gap-2';
  const name = document.createElement('span');
  name.className = 'text-[13.5px] font-semibold';
  name.style.color = mine ? 'var(--text)' : colorFor(author);
  name.textContent = author;
  const time = document.createElement('span');
  time.className = 'text-[11px] text-faint';
  time.textContent = clockTime();
  head.append(name, time);
  column.appendChild(head);

  wrap.appendChild(column);
  return { wrap, column };
}

function appendChat(author, text, mine) {
  if (!text) return;
  const { wrap, column } = messageShell(author, mine);
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

function appendFileCard(author, transfer, mine) {
  const { wrap, column } = messageShell(author, mine);

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

  const bar = document.createElement('div');
  bar.className = 'mt-2.5 h-1 rounded-full overflow-hidden';
  bar.style.background = 'var(--raise)';
  const fill = document.createElement('i');
  fill.className = 'block h-full';
  fill.style.background = 'var(--signal)';
  fill.style.width = mine ? '0%' : '100%';
  fill.style.transition = 'width 120ms linear';
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
  room_full: `This room is full at ${MAX_PEERS} people. Full-mesh audio gets unstable past that.`,
  relay_unreachable: "Can't reach the signaling relay. Check that the server is running.",
  bad_room_id: 'The relay rejected the room identifier. Reload and try again.',
  rate_limited: 'The relay rate-limited this connection. Wait a moment and rejoin.',
};

async function join(roomName, passkey, nick, wantMic) {
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
  state.nick = nick;
  state.roomKey = session.roomKey;
  state.roomId = session.roomId;
  state.seal = session.seal;

  let micReady = false;
  if (wantMic) {
    $('join-work-text').textContent = 'waiting for microphone permission';
    micReady = await initMicrophone();
  }

  $('join-work-text').textContent = `connecting to relay · room ${session.roomId.slice(0, 12)}…`;

  let welcome;
  try {
    welcome = await connectRelay(session.roomId);
  } catch (err) {
    state.roomKey = null;
    state.seal = null;
    joinError(RELAY_ERRORS[err.message] || 'The relay refused the connection.');
    return;
  }

  // We're in. Show the room.
  state.live = true;
  $('join-screen').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('room-label').textContent = roomName;

  renderSeal();
  renderSelf();
  renderPeers();
  renderTransport();
  setStatus(welcome.peers.length ? 'live' : 'connecting',
    welcome.peers.length ? 'In room' : 'Waiting for others');

  if (wantMic && !micReady) {
    systemMessage('Joined without a microphone — the browser denied access. You can still read, type, and hear others.', 'warn');
  }
  systemMessage(
    welcome.peers.length
      ? `Connecting to ${welcome.peers.length} ${welcome.peers.length === 1 ? 'person' : 'people'}.`
      : 'Room open. Share the room name and passkey out of band, and whoever joins lands here.',
  );

  for (const peerId of welcome.peers) addPeer(peerId);

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

  if (state.statsTimer) { clearInterval(state.statsTimer); state.statsTimer = null; }
  if (state.levelFrame) { cancelAnimationFrame(state.levelFrame); state.levelFrame = null; }

  for (const url of state.blobUrls) URL.revokeObjectURL(url);
  state.blobUrls.clear();
  state.incoming.clear();

  state.roomKey = null;
  state.seal = null;
  state.roomId = '';
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
  $('peer-count').textContent = '0/' + MAX_PEERS;
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
    join(roomName, passkey, nick, $('f-mic').checked).catch(() => {
      joinError('Something failed while joining. Reload and try again.');
    });
  });

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

  wireEvents();
  $('f-room').focus();
}

boot();
