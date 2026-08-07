"""
EnDa Chat -- ephemeral E2EE peer-to-peer chat room.

This module is the *entire* server: a minimal WebSocket signaling relay whose
only job is to help browsers find each other and exchange SDP/ICE. It is
deliberately ignorant.

What this server knows about a session
--------------------------------------
  * A 64-hex room identifier, which the client derives locally via
    PBKDF2 -> HKDF from the room name and passkey. Neither the room name nor
    the passkey is recoverable from it.
  * A random per-connection peer id that this server itself invents.
  * Opaque signaling blobs it copies from one socket to another.

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
from contextlib import suppress
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
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

#: Full-mesh audio degrades sharply past this: each peer uploads N-1 streams.
MAX_PEERS_PER_ROOM = 8

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
DEBUG_STATS = os.environ.get("ENDA_DEBUG_STATS") == "1"

CLIENT_DIR = Path(__file__).resolve().parent.parent / "client"


# ---------------------------------------------------------------------------
# In-memory room registry
# ---------------------------------------------------------------------------

class Rooms:
    """room_id -> {peer_id: WebSocket}, and nothing else, ever.

    Guarded by a lock so that the join-capacity check and the insert cannot
    interleave: without it, eight simultaneous joins could all observe seven
    occupants and push the room to fifteen.
    """

    def __init__(self) -> None:
        self._rooms: dict[str, dict[str, WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def join(self, room_id: str, ws: WebSocket) -> tuple[str, list[str]] | None:
        """Insert `ws` into a room. Returns (peer_id, existing_peer_ids) or None if full."""
        async with self._lock:
            room = self._rooms.setdefault(room_id, {})
            if len(room) >= MAX_PEERS_PER_ROOM:
                if not room:
                    del self._rooms[room_id]
                return None
            peer_id = secrets.token_hex(8)
            existing = list(room.keys())
            room[peer_id] = ws
            return peer_id, existing

    async def leave(self, room_id: str, peer_id: str) -> list[WebSocket]:
        """Remove a peer and return the sockets that remain. Drops the room when empty."""
        async with self._lock:
            room = self._rooms.get(room_id)
            if room is None:
                return []
            room.pop(peer_id, None)
            if not room:
                # Last peer out: the room and every trace of it go away now.
                del self._rooms[room_id]
                return []
            return list(room.values())

    async def peers(self, room_id: str) -> dict[str, WebSocket]:
        async with self._lock:
            return dict(self._rooms.get(room_id, {}))

    async def target(self, room_id: str, peer_id: str) -> WebSocket | None:
        """Look up one peer, scoped to its room -- the relay never crosses rooms."""
        async with self._lock:
            return self._rooms.get(room_id, {}).get(peer_id)

    async def snapshot(self) -> dict[str, int]:
        async with self._lock:
            return {rid: len(members) for rid, members in self._rooms.items()}


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

app = FastAPI(
    title="EnDa Chat signaling relay",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

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
        "connect-src 'self'",
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

                result = await rooms.join(requested, ws)
                if result is None:
                    await _send(
                        ws,
                        {
                            "type": "error",
                            "code": "room_full",
                            "limit": MAX_PEERS_PER_ROOM,
                        },
                    )
                    await _close(ws, code=1013)
                    return

                room_id, peer_id = requested, result[0]
                await _send(
                    ws,
                    {
                        "type": "welcome",
                        "peerId": peer_id,
                        "peers": result[1],
                        "limit": MAX_PEERS_PER_ROOM,
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
            remaining = await rooms.leave(room_id, peer_id)
            await _broadcast(remaining, {"type": "peer-leave", "peerId": peer_id})


# Mounted last so /ws and /api/* win over any same-named static path.
if CLIENT_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(CLIENT_DIR), html=True), name="client")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    import uvicorn

    host = os.environ.get("ENDA_HOST", "127.0.0.1")
    port = int(os.environ.get("ENDA_PORT", "8000"))

    # This banner is the only thing this process ever writes, and it carries no
    # session data. flush=True so it still appears when stdout is a pipe --
    # otherwise it sits in the buffer and the operator sees nothing at all.
    print(f"EnDa Chat signaling relay -> http://{host}:{port}", flush=True)
    print(
        f"  rooms: in-memory only  |  peer cap: {MAX_PEERS_PER_ROOM}  |  logging: disabled",
        flush=True,
    )
    if DEBUG_STATS:
        print("  WARNING: ENDA_DEBUG_STATS=1 -- /api/debug/stats is exposed (dev only)", flush=True)

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
