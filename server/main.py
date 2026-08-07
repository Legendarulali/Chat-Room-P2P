"""
Chat Room P2P -- ephemeral E2EE peer-to-peer chat room.

This module is the *entire* server: a minimal WebSocket signaling relay whose
only job is to help browsers find each other and exchange SDP/ICE. It is
deliberately ignorant.

What this server knows about a session
--------------------------------------
  * A 64-hex room identifier, which the client derives locally via
    PBKDF2 -> HKDF from the room name and passkey. Neither the room name nor
    the passkey is recoverable from it.
  * A random per-connection peer id that this server itself invents.
  * Each room's capacity, and which of those invented peer ids currently hosts
    it. Both are coordination state: a number and a pointer, carrying nothing
    about who anyone is.
  * Opaque signaling blobs it copies from one socket to another.

Host and capacity are not security boundaries
---------------------------------------------
This server assigns the host and enforces the cap, so it could equally name
the wrong peer host or admit a ninth guest. Those controls exist to let a group
organise itself, not to defend against the relay. What the relay still cannot
do -- however it lies about hosts -- is read a message, because it never holds
the room key.

What this server never sees
---------------------------
  * Room names, passkeys, or key material.
  * Chat text, file contents, or audio. Those travel peer-to-peer over
    DTLS-protected DataChannels/SRTP, encrypted a second time with a room key
    this process has no way to derive.

Zero-log policy
---------------
  * All Python logging is silenced at import time (see _silence_logging).
  * uvicorn's access log and log config are disabled in main().
  * Rooms live in one in-memory dict and are deleted the moment the last peer
    disconnects. There is no database, no file writing, and no code path that
    persists a room id, peer id, or payload anywhere.
  * Nothing derived from a payload is ever printed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
import urllib.request
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocketState


# ---------------------------------------------------------------------------
# Zero-log enforcement
# ---------------------------------------------------------------------------

def _silence_logging() -> None:
    """Detach every logger that could write a request line to stdout or disk.

    Run at import time so nothing gets a chance to emit before we clamp down.
    """
    logging.disable(logging.CRITICAL)
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(logging.NullHandler())
    root.setLevel(logging.CRITICAL + 1)
    for name in (
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "uvicorn.asgi",
        "fastapi",
        "starlette",
        "websockets",
        "websockets.server",
        "asyncio",
        "watchfiles",
    ):
        log = logging.getLogger(name)
        log.handlers.clear()
        log.addHandler(logging.NullHandler())
        log.propagate = False
        log.setLevel(logging.CRITICAL + 1)


_silence_logging()


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

#: Default room capacity. Full-mesh audio degrades sharply past this: each peer
#: uploads N-1 streams, so cost grows with the square of the room.
MAX_PEERS_PER_ROOM = 8

#: A room needs two people to be a room.
MIN_CAPACITY = 2

#: Absolute ceiling on what a host may set. Capacity arrives from a client, so
#: without a bound it is attacker-controlled unbounded state -- one join
#: claiming a capacity of ten million would let one room exhaust the process.
#: Raising this past MAX_PEERS_PER_ROOM is allowed and documented as degrading
#: voice; raising it past this constant is not.
CAPACITY_CEILING = max(MAX_PEERS_PER_ROOM, int(os.environ.get("CAPACITY_CEILING", "16")))


def clamp_capacity(value: object, floor: int = MIN_CAPACITY) -> int:
    """Coerce anything a client sent into a capacity this server will honour."""
    try:
        requested = int(value)
    except (TypeError, ValueError):
        return MAX_PEERS_PER_ROOM
    return max(floor, min(CAPACITY_CEILING, requested))

#: A room id is SHA-derived client-side. Anything else is rejected outright,
#: which is what stops this relay being usable with plaintext room names.
ROOM_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")

#: Generous enough for a bundled SDP with many candidates, small enough that
#: the relay cannot be repurposed as a file transfer service. This is the
#: *graceful* tier: a frame over it earns an error and the socket stays open.
MAX_FRAME_BYTES = 96 * 1024

#: The hard tier, enforced by the websocket transport before a frame is even
#: assembled. It has to sit above MAX_FRAME_BYTES, otherwise the transport
#: would hang up first and the graceful path above would be unreachable.
TRANSPORT_MAX_BYTES = MAX_FRAME_BYTES * 2

#: Token bucket. A peer joining a full room legitimately bursts ~7 offers plus
#: their trickled ICE candidates, so the bucket is deep and refills quickly.
RATE_BUCKET_CAPACITY = 240
RATE_REFILL_PER_SECOND = 60.0

#: Peers get this long to send a valid `join` before we hang up, so half-open
#: sockets cannot accumulate.
JOIN_DEADLINE_SECONDS = 15.0

#: Dev-only. Exposes live room/peer counts at /api/debug/stats so the test
#: suite can assert that empty rooms are really deleted. Off by default: the
#: count alone is metadata an observer should not get for free.
DEBUG_STATS = os.environ.get("DEBUG_STATS") == "1"

CLIENT_DIR = Path(__file__).resolve().parent.parent / "client"


# ---------------------------------------------------------------------------
# Keep-alive
#
# Free hosting tiers idle a service out after a period with no inbound
# requests. This loop gives the platform some. Two honest limits:
#
#   * It cannot wake a sleeping instance. Once the platform has stopped the
#     process, nothing here is running to make a request. This prevents
#     idling out while alive; it is not a resurrection mechanism.
#   * Some providers consider self-pinging a way around the free tier they
#     designed. Check the terms for wherever this runs.
#
# The ping carries no session data, and neither does the Discord notice: the
# only facts either one transmits are "this process answered" and the time.
# ---------------------------------------------------------------------------

#: Ten minutes by default. Overridable so the test suite can watch the loop
#: complete several cycles instead of waiting out a real interval.
KEEPALIVE_INTERVAL_SECONDS = max(1, int(os.environ.get("KEEPALIVE_INTERVAL_SECONDS", "600")))
#: One early ping so a misconfiguration shows up in seconds, not ten minutes.
KEEPALIVE_WARMUP_SECONDS = 5.0
KEEPALIVE_TIMEOUT_SECONDS = 15.0

#: Render exports this. Anything else can set it explicitly.
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "").strip().rstrip("/")

#: Optional. Setting this means uptime notices leave this machine for Discord.
#: See README, "The keep-alive loop is the one thing that phones home".
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()

#: Mint green, matching the client's "live" accent.
DISCORD_EMBED_COLOR = 0x4ADE9B


# ---------------------------------------------------------------------------
# In-memory room registry
# ---------------------------------------------------------------------------

class Room:
    """One live room: its occupants, its capacity, and which peer hosts it.

    This is the complete set of what the relay knows about a room. It is
    coordination state, not content: `peers` maps a peer id this server
    invented to the socket it arrived on, `capacity` is a number, and `host_id`
    is one of those invented ids. There is still no room name, no passkey, no
    nickname, and no message anywhere in here.

    Host order follows insertion order, which dicts preserve, so "the next peer
    in line" is simply the oldest remaining one.
    """

    __slots__ = ("peers", "capacity", "host_id")

    def __init__(self, capacity: int) -> None:
        self.peers: dict[str, WebSocket] = {}
        self.capacity = capacity
        self.host_id: str | None = None


class Rooms:
    """room_id -> Room.

    Guarded by a lock so that the capacity check and the insert cannot
    interleave: without it, eight simultaneous joins could all observe seven
    occupants and push the room past its limit.
    """

    def __init__(self) -> None:
        self._rooms: dict[str, Room] = {}
        self._lock = asyncio.Lock()

    async def join(
        self, room_id: str, ws: WebSocket, requested_capacity: object
    ) -> tuple[str, list[str], str, int] | None:
        """Insert `ws`. Returns (peer_id, existing_ids, host_id, capacity), or None if full.

        The requested capacity is honoured only when this call creates the room.
        A later joiner cannot talk the room into a different size -- otherwise
        anyone with the passkey could overrule the host just by reconnecting.
        """
        async with self._lock:
            room = self._rooms.get(room_id)
            if room is None:
                room = Room(clamp_capacity(requested_capacity))
                self._rooms[room_id] = room

            if len(room.peers) >= room.capacity:
                if not room.peers:
                    # Refused into an empty room we just made; do not leave it behind.
                    del self._rooms[room_id]
                return None

            peer_id = secrets.token_hex(8)
            existing = list(room.peers.keys())
            room.peers[peer_id] = ws
            if room.host_id is None:
                # First peer through the door hosts the room.
                room.host_id = peer_id
            return peer_id, existing, room.host_id, room.capacity

    async def leave(self, room_id: str, peer_id: str) -> tuple[list[WebSocket], str | None, int]:
        """Remove a peer.

        Returns (remaining sockets, new host id if it changed, capacity).
        Drops the room entirely when the last peer goes.
        """
        async with self._lock:
            room = self._rooms.get(room_id)
            if room is None:
                return [], None, MAX_PEERS_PER_ROOM
            room.peers.pop(peer_id, None)

            if not room.peers:
                # Last peer out: the room and every trace of it go away now.
                del self._rooms[room_id]
                return [], None, room.capacity

            new_host = None
            if room.host_id == peer_id:
                # Hand the crown to the oldest remaining peer.
                room.host_id = next(iter(room.peers))
                new_host = room.host_id
            return list(room.peers.values()), new_host, room.capacity

    async def set_capacity(self, room_id: str, peer_id: str, value: object) -> tuple[int, list[WebSocket]] | None:
        """Host-only capacity change. Returns (applied capacity, sockets) or None if refused.

        Lowering below the current headcount is clamped rather than enforced by
        eviction: throwing people out of a conversation because the number moved
        would be a hostile way to resize a room. New joins are what the lower
        number governs.
        """
        async with self._lock:
            room = self._rooms.get(room_id)
            if room is None or room.host_id != peer_id:
                return None
            room.capacity = clamp_capacity(value, floor=max(MIN_CAPACITY, len(room.peers)))
            return room.capacity, list(room.peers.values())

    async def peers(self, room_id: str) -> dict[str, WebSocket]:
        async with self._lock:
            room = self._rooms.get(room_id)
            return dict(room.peers) if room else {}

    async def target(self, room_id: str, peer_id: str) -> WebSocket | None:
        """Look up one peer, scoped to its room -- the relay never crosses rooms."""
        async with self._lock:
            room = self._rooms.get(room_id)
            return room.peers.get(peer_id) if room else None

    async def snapshot(self) -> dict[str, int]:
        async with self._lock:
            return {rid: len(room.peers) for rid, room in self._rooms.items()}


rooms = Rooms()


class RateLimiter:
    """Per-connection token bucket."""

    __slots__ = ("_tokens", "_checked_at")

    def __init__(self) -> None:
        self._tokens = float(RATE_BUCKET_CAPACITY)
        self._checked_at = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        self._tokens = min(
            RATE_BUCKET_CAPACITY,
            self._tokens + (now - self._checked_at) * RATE_REFILL_PER_SECOND,
        )
        self._checked_at = now
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _keepalive_target() -> str:
    """Where to send the self-ping. External URL if the platform gave us one."""
    base = RENDER_EXTERNAL_URL or f"http://127.0.0.1:{os.environ.get('PORT', '8000')}"
    return f"{base}/health"


def _http_get_status(url: str) -> int:
    """Blocking GET, run off the event loop. Returns the status code."""
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "chatroom-p2p-keepalive"})
    with urllib.request.urlopen(request, timeout=KEEPALIVE_TIMEOUT_SECONDS) as response:
        response.read(0)
        return response.status


def _http_post_json(url: str, payload: dict) -> int:
    """Blocking POST, run off the event loop. Returns the status code."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "chatroom-p2p-keepalive"},
    )
    with urllib.request.urlopen(request, timeout=KEEPALIVE_TIMEOUT_SECONDS) as response:
        response.read(0)
        return response.status


async def _notify_discord(target: str, status: int) -> None:
    """Post an uptime notice. Carries no room, peer, or address information."""
    payload = {
        "username": "Chat Room P2P",
        "embeds": [
            {
                "title": "Keep-alive ping OK",
                "description": f"`GET {target}` returned **{status}**.",
                "color": DISCORD_EMBED_COLOR,
                "timestamp": _utc_now(),
                "footer": {"text": "Signaling relay is awake. No session data is reported."},
            }
        ],
    }
    await asyncio.to_thread(_http_post_json, DISCORD_WEBHOOK_URL, payload)


async def keepalive_loop() -> None:
    """Ping ourselves forever. This coroutine must never exit on its own.

    Every iteration is wrapped, so a DNS failure, a timeout, a 502 from the
    platform's router, or a Discord outage costs one cycle and nothing more.
    CancelledError is deliberately re-raised -- swallowing it would make the
    task un-stoppable and hang shutdown.
    """
    await asyncio.sleep(KEEPALIVE_WARMUP_SECONDS)
    while True:
        try:
            target = _keepalive_target()
            status = await asyncio.to_thread(_http_get_status, target)
            if DISCORD_WEBHOOK_URL and 200 <= status < 300:
                await _notify_discord(target, status)
        except asyncio.CancelledError:
            raise
        except BaseException:
            # Intentionally total. Nothing a ping can raise is worth ending
            # the loop over, and there is nowhere to report it: this process
            # does not log.
            pass

        try:
            await asyncio.sleep(KEEPALIVE_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(keepalive_loop())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(
    title="Chat Room P2P signaling relay",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# Requested: accept any origin. Two things worth knowing about this choice.
#
#   1. It does nothing for /ws. WebSocket handshakes are not subject to CORS,
#      so a permissive policy here neither helps nor hinders peers connecting.
#   2. It lets any website's JavaScript read this origin's HTTP responses.
#      Today that means /health and /api/health, which carry no session data,
#      so the practical exposure is small -- but it is a door held open for no
#      functional gain, and it contradicts the CSP two blocks down.
#
# To close it, replace ["*"] with your own origin, e.g.
# ["https://chat.example.com"]. allow_credentials stays False because "*" plus
# credentials is rejected by browsers anyway.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

#: Extra origins for connect-src, space-separated. Needed only when this server
#: serves the page but the client is configured (window.SIGNALING_URL) to reach a
#: relay somewhere else -- otherwise connect-src 'self' blocks the socket and the
#: browser reports it nowhere the user can see.
#: e.g. EXTRA_CONNECT_SRC="wss://relay.example.com"
EXTRA_CONNECT_SRC = os.environ.get("EXTRA_CONNECT_SRC", "").strip()

# Tailwind is loaded from its CDN, so script-src has to name that host and
# allow the inline config block it needs. Vendoring Tailwind (see README,
# "Removing the CDN") lets this collapse to `default-src 'self'`.
CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "media-src 'self' blob: mediastream:",
        f"connect-src 'self'{' ' + EXTRA_CONNECT_SRC if EXTRA_CONNECT_SRC else ''}",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    )
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": (
        "microphone=(self), camera=(), geolocation=(), payment=(), usb=(), "
        "display-capture=(), idle-detection=()"
    ),
}


@app.middleware("http")
async def security_headers(request, call_next):
    response: Response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


@app.get("/health")
async def health_status() -> JSONResponse:
    """Liveness for the platform's health check and the keep-alive loop.

    Status and clock only. No room count, no peer count, nothing derived from
    a session -- an uptime probe is not a reason to start emitting metadata.
    """
    return JSONResponse({"status": "ok", "timestamp": _utc_now()})


@app.get("/api/health")
async def health() -> JSONResponse:
    """Liveness only. Deliberately reveals no room or peer counts."""
    return JSONResponse({"ok": True})


if DEBUG_STATS:

    @app.get("/api/debug/stats")
    async def debug_stats() -> JSONResponse:
        snapshot = await rooms.snapshot()
        return JSONResponse({"rooms": len(snapshot), "peers": sum(snapshot.values())})


# ---------------------------------------------------------------------------
# Signaling
# ---------------------------------------------------------------------------

async def _send(ws: WebSocket, message: dict) -> None:
    """Best-effort send. A peer vanishing mid-broadcast must not abort the loop."""
    if ws.client_state is not WebSocketState.CONNECTED:
        return
    with suppress(Exception):
        await ws.send_text(json.dumps(message, separators=(",", ":")))


async def _broadcast(sockets: list[WebSocket], message: dict) -> None:
    if sockets:
        await asyncio.gather(*(_send(sock, message) for sock in sockets), return_exceptions=True)


async def _close(ws: WebSocket, code: int = 1000) -> None:
    with suppress(Exception):
        await ws.close(code=code)


@app.websocket("/ws")
async def signaling(ws: WebSocket) -> None:
    await ws.accept()

    limiter = RateLimiter()
    room_id: str | None = None
    peer_id: str | None = None
    joined_at = time.monotonic()

    try:
        while True:
            raw = await ws.receive_text()

            # Character count, not byte count: a UTF-8 character is never
            # fewer than one byte, so exceeding this in characters guarantees
            # the frame is oversized. TRANSPORT_MAX_BYTES is what enforces the
            # exact byte ceiling.
            if len(raw) > MAX_FRAME_BYTES:
                await _send(ws, {"type": "error", "code": "frame_too_large"})
                continue

            if not limiter.allow():
                await _send(ws, {"type": "error", "code": "rate_limited"})
                await _close(ws, code=1008)
                return

            try:
                message = json.loads(raw)
            except (ValueError, TypeError):
                await _send(ws, {"type": "error", "code": "bad_json"})
                continue
            if not isinstance(message, dict):
                await _send(ws, {"type": "error", "code": "bad_json"})
                continue

            kind = message.get("type")

            # -- join -------------------------------------------------------
            if kind == "join":
                if peer_id is not None:
                    await _send(ws, {"type": "error", "code": "already_joined"})
                    continue

                requested = message.get("room")
                if not isinstance(requested, str) or not ROOM_ID_PATTERN.match(requested):
                    # Rejecting anything that is not a derived digest is what
                    # keeps plaintext room names off this server.
                    await _send(ws, {"type": "error", "code": "bad_room_id"})
                    await _close(ws, code=1008)
                    return

                result = await rooms.join(requested, ws, message.get("capacity"))
                if result is None:
                    await _send(ws, {"type": "error", "code": "room_full"})
                    await _close(ws, code=1013)
                    return

                peer_id, existing, host_id, capacity = result
                room_id = requested
                await _send(
                    ws,
                    {
                        "type": "welcome",
                        "peerId": peer_id,
                        "peers": existing,
                        "hostId": host_id,
                        "capacity": capacity,
                        "ceiling": CAPACITY_CEILING,
                        "minCapacity": MIN_CAPACITY,
                    },
                )
                others = [
                    sock
                    for other_id, sock in (await rooms.peers(room_id)).items()
                    if other_id != peer_id
                ]
                await _broadcast(others, {"type": "peer-join", "peerId": peer_id})
                continue

            # Everything past this point requires a joined socket.
            if peer_id is None or room_id is None:
                if time.monotonic() - joined_at > JOIN_DEADLINE_SECONDS:
                    await _close(ws, code=1008)
                    return
                await _send(ws, {"type": "error", "code": "not_joined"})
                continue

            # -- signal -----------------------------------------------------
            if kind == "signal":
                target_id = message.get("to")
                payload = message.get("data")
                if not isinstance(target_id, str) or payload is None:
                    await _send(ws, {"type": "error", "code": "bad_request"})
                    continue
                if target_id == peer_id:
                    await _send(ws, {"type": "error", "code": "bad_request"})
                    continue

                target = await rooms.target(room_id, target_id)
                if target is None:
                    # Peer already left, or is in another room. Either way this
                    # relay will not deliver it.
                    await _send(ws, {"type": "error", "code": "no_such_peer", "peerId": target_id})
                    continue

                # The payload is copied through untouched and uninspected.
                await _send(target, {"type": "signal", "from": peer_id, "data": payload})
                continue

            # -- set-capacity -----------------------------------------------
            if kind == "set-capacity":
                applied = await rooms.set_capacity(room_id, peer_id, message.get("capacity"))
                if applied is None:
                    # Not the host. Refusing here is the whole point: otherwise
                    # any occupant could resize the room.
                    await _send(ws, {"type": "error", "code": "not_host"})
                    continue
                capacity, sockets = applied
                await _broadcast(
                    sockets,
                    {"type": "room-meta", "hostId": peer_id, "capacity": capacity},
                )
                continue

            # -- leave ------------------------------------------------------
            if kind == "leave":
                await _close(ws, code=1000)
                return

            # -- ping -------------------------------------------------------
            if kind == "ping":
                await _send(ws, {"type": "pong"})
                continue

            await _send(ws, {"type": "error", "code": "unknown_type"})

    except WebSocketDisconnect:
        pass
    except (RuntimeError, ValueError, OSError):
        # Socket torn down under us, or a malformed frame. Fall through to
        # teardown; there is nothing worth reporting and nowhere to report it.
        pass
    finally:
        if room_id is not None and peer_id is not None:
            remaining, new_host, capacity = await rooms.leave(room_id, peer_id)
            await _broadcast(remaining, {"type": "peer-leave", "peerId": peer_id})
            if new_host is not None:
                # The host left. Tell everyone who holds the crown now, before
                # any of them try to use a control they no longer have (or do
                # have, and do not know it yet).
                await _broadcast(
                    remaining,
                    {"type": "room-meta", "hostId": new_host, "capacity": capacity},
                )


# Mounted last so /ws, /health, and /api/* win over any same-named static path.
if CLIENT_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(CLIENT_DIR), html=True), name="client")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    import uvicorn

    # Locally, bind loopback so a dev server is not exposed to the LAN by
    # accident. On a platform that routes traffic to the container, loopback
    # would make the service unreachable, so default to all interfaces there.
    # RENDER_EXTERNAL_URL being set is the signal that we are behind a router.
    default_host = "0.0.0.0" if RENDER_EXTERNAL_URL else "127.0.0.1"
    host = os.environ.get("HOST", default_host)
    port = int(os.environ.get("PORT", "8000"))

    # This banner is the only thing this process writes on its own, and it
    # carries no session data. flush=True so it still appears when stdout is a
    # pipe -- otherwise it sits in the buffer and the operator sees nothing.
    print(f"Chat Room P2P signaling relay -> http://{host}:{port}", flush=True)
    print(
        f"  rooms: in-memory only  |  peer cap: {MAX_PEERS_PER_ROOM}  |  logging: disabled",
        flush=True,
    )
    print(
        f"  keep-alive: every {KEEPALIVE_INTERVAL_SECONDS}s -> {_keepalive_target()}",
        flush=True,
    )
    if DEBUG_STATS:
        print("  WARNING: DEBUG_STATS=1 -- /api/debug/stats is exposed (dev only)", flush=True)
    if DISCORD_WEBHOOK_URL:
        print("  NOTE: DISCORD_WEBHOOK_URL is set -- uptime notices leave this machine", flush=True)
    print("  NOTE: CORS is open to all origins", flush=True)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_config=None,
        log_level=None,
        access_log=False,
        server_header=False,
        date_header=True,
        ws_ping_interval=20.0,
        ws_ping_timeout=20.0,
        ws_max_size=TRANSPORT_MAX_BYTES,
    )


if __name__ == "__main__":
    main()
