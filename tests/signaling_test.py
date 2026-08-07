"""
Black-box checks against a running relay.

Every assertion here is about a claim the README makes, so this file is the
evidence for those claims rather than a smoke test.

Run:
    # terminal 1
    set DEBUG_STATS=1
    .venv\\Scripts\\python.exe -m server.main

    # terminal 2
    .venv\\Scripts\\python.exe tests\\signaling_test.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime

import websockets

BASE_HTTP = os.environ.get("TEST_HTTP", "http://127.0.0.1:8000")
BASE_WS = os.environ.get("TEST_WS", "ws://127.0.0.1:8000/ws")

passed: list[str] = []
failed: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        passed.append(name)
        print(f"  PASS  {name}")
    else:
        failed.append(name)
        print(f"  FAIL  {name}" + (f"  -- {detail}" if detail else ""))


def room_id(label: str) -> str:
    """Any 64-hex string is a valid room id as far as the relay is concerned."""
    return hashlib.sha256(label.encode()).hexdigest()


async def recv_json(ws, timeout: float = 5.0) -> dict:
    return json.loads(await asyncio.wait_for(ws.recv(), timeout=timeout))


async def join(ws, rid: str) -> dict:
    await ws.send(json.dumps({"type": "join", "room": rid}))
    return await recv_json(ws)


def debug_stats() -> dict | None:
    try:
        with urllib.request.urlopen(f"{BASE_HTTP}/api/debug/stats", timeout=3) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None


# ---------------------------------------------------------------------------


async def test_static_and_headers() -> None:
    print("\n[ static assets + security headers ]")
    with urllib.request.urlopen(f"{BASE_HTTP}/", timeout=5) as response:
        body = response.read().decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in response.headers.items()}

    check("index.html is served", "Chat Room P2P" in body)
    check("app.js is referenced", 'src="app.js"' in body)
    check("Cache-Control is no-store", "no-store" in headers.get("cache-control", ""))
    check("Referrer-Policy is no-referrer", headers.get("referrer-policy") == "no-referrer")
    check("CSP is present", "default-src 'self'" in headers.get("content-security-policy", ""))
    check("CSP forbids framing", "frame-ancestors 'none'" in headers.get("content-security-policy", ""))
    check("Permissions-Policy limits microphone",
          "microphone=(self)" in headers.get("permissions-policy", ""))
    check("Server header is suppressed", "server" not in headers, headers.get("server", ""))

    with urllib.request.urlopen(f"{BASE_HTTP}/app.js", timeout=5) as response:
        js = response.read().decode("utf-8", "replace")
    check("app.js is served", "deriveSession" in js)

    # Look for *use* of a storage API -- the identifier followed by a property
    # access or a call -- rather than the bare word, which appears in the file's
    # own comment about not using them.
    storage_use = re.search(
        r"\b(localStorage|sessionStorage|indexedDB|openDatabase|caches)\s*(\.|\[|\()", js
    )
    check("client never uses a storage API", storage_use is None,
          storage_use.group(0) if storage_use else "")
    check("client never sets a cookie", not re.search(r"document\s*\.\s*cookie", js))
    check("client uses a non-extractable room key", "AES-GCM', length: 256 },\n    false," in js
          or re.search(r"\{ name: 'AES-GCM', length: 256 \},\s*\n\s*false,", js) is not None)


async def test_health_leaks_nothing() -> None:
    print("\n[ health endpoint reveals no session metadata ]")
    with urllib.request.urlopen(f"{BASE_HTTP}/api/health", timeout=5) as response:
        payload = json.loads(response.read())
    check("health returns ok", payload.get("ok") is True)
    check("health exposes no room count", "rooms" not in payload and "peers" not in payload, str(payload))


async def test_health_endpoint() -> None:
    print("\n[ /health for the platform probe and keep-alive loop ]")
    with urllib.request.urlopen(f"{BASE_HTTP}/health", timeout=5) as response:
        payload = json.loads(response.read())
        headers = {k.lower(): v for k, v in response.headers.items()}

    check("status is ok", payload.get("status") == "ok", str(payload))
    check("timestamp is present", isinstance(payload.get("timestamp"), str), str(payload))

    stamp = payload.get("timestamp", "")
    try:
        parsed = datetime.fromisoformat(stamp)
        valid = parsed.tzinfo is not None
    except ValueError:
        valid = False
    check("timestamp is tz-aware ISO 8601", valid, stamp)

    # An uptime probe is not a reason to start emitting session metadata.
    leaked = [k for k in payload if k not in {"status", "timestamp"}]
    check("/health exposes nothing but status and time", not leaked, str(leaked))

    # CORS headers only appear when the request carries an Origin, so a plain
    # urlopen sees none. Ask as a cross-origin caller would.
    cross_origin = urllib.request.Request(
        f"{BASE_HTTP}/health", headers={"Origin": "https://unrelated.example"}
    )
    with urllib.request.urlopen(cross_origin, timeout=5) as response:
        cors = {k.lower(): v for k, v in response.headers.items()}

    check("CORS is open to any origin",
          cors.get("access-control-allow-origin") == "*",
          cors.get("access-control-allow-origin", "(absent)"))
    check("CORS does not also allow credentials",
          cors.get("access-control-allow-credentials") != "true",
          cors.get("access-control-allow-credentials", ""))
    check("no CORS headers without an Origin (middleware is conditional)",
          "access-control-allow-origin" not in headers,
          headers.get("access-control-allow-origin", ""))


async def test_room_id_validation() -> None:
    print("\n[ relay rejects anything that is not a derived digest ]")
    for label, bad in (
        ("plaintext room name", "kitchen-table"),
        ("too short", "abc123"),
        ("uppercase hex", "A" * 64),
        ("non-hex", "z" * 64),
        ("wrong type", 12345),
    ):
        async with websockets.connect(BASE_WS) as ws:
            await ws.send(json.dumps({"type": "join", "room": bad}))
            message = await recv_json(ws)
            check(f"rejects {label}", message.get("code") == "bad_room_id", str(message))


async def test_join_and_relay() -> None:
    print("\n[ two peers exchange an opaque signal ]")
    rid = room_id("relay-test")

    async with websockets.connect(BASE_WS) as alice, websockets.connect(BASE_WS) as bob:
        welcome_a = await join(alice, rid)
        check("first peer gets welcome", welcome_a.get("type") == "welcome", str(welcome_a))
        check("first peer sees an empty room", welcome_a.get("peers") == [], str(welcome_a.get("peers")))
        check("relay assigns the peer id", isinstance(welcome_a.get("peerId"), str) and len(welcome_a["peerId"]) == 16)
        check("welcome advertises the peer cap", welcome_a.get("limit") == 8)

        welcome_b = await join(bob, rid)
        check("second peer sees the first", welcome_b.get("peers") == [welcome_a["peerId"]], str(welcome_b))

        notice = await recv_json(alice)
        check("first peer is told about the join",
              notice.get("type") == "peer-join" and notice.get("peerId") == welcome_b["peerId"], str(notice))

        # Relay must copy the payload through byte-for-byte without inspecting it.
        payload = {"kind": "desc", "description": {"type": "offer", "sdp": "v=0\r\nopaque-to-the-server\r\n"}}
        await bob.send(json.dumps({"type": "signal", "to": welcome_a["peerId"], "data": payload}))
        relayed = await recv_json(alice)
        check("signal is relayed", relayed.get("type") == "signal", str(relayed))
        check("relay stamps the true sender", relayed.get("from") == welcome_b["peerId"])
        check("payload arrives unmodified", relayed.get("data") == payload)

        await bob.send(json.dumps({"type": "signal", "to": "ffffffffffffffff", "data": {"x": 1}}))
        missing = await recv_json(bob)
        check("unknown peer is refused", missing.get("code") == "no_such_peer", str(missing))

        await bob.send(json.dumps({"type": "signal", "to": welcome_b["peerId"], "data": {"x": 1}}))
        self_signal = await recv_json(bob)
        check("self-addressed signal is refused", self_signal.get("code") == "bad_request", str(self_signal))


async def test_cross_room_isolation() -> None:
    print("\n[ the relay will not bridge two rooms ]")
    async with websockets.connect(BASE_WS) as one, websockets.connect(BASE_WS) as two:
        welcome_one = await join(one, room_id("room-alpha"))
        welcome_two = await join(two, room_id("room-beta"))

        await two.send(json.dumps({"type": "signal", "to": welcome_one["peerId"], "data": {"leak": True}}))
        response = await recv_json(two)
        check("cross-room signal is refused", response.get("code") == "no_such_peer", str(response))

        # And nothing should have reached the other room.
        try:
            stray = await recv_json(one, timeout=1.0)
            check("no stray delivery", False, str(stray))
        except asyncio.TimeoutError:
            check("no stray delivery", True)
        assert welcome_two["peerId"]


async def test_peer_cap() -> None:
    print("\n[ eight peers in, ninth refused ]")
    rid = room_id("cap-test")
    sockets = []
    try:
        for index in range(8):
            ws = await websockets.connect(BASE_WS)
            sockets.append(ws)
            welcome = await join(ws, rid)
            if welcome.get("type") != "welcome":
                check(f"peer {index + 1} admitted", False, str(welcome))
                return
        check("eight peers admitted", True)

        async with websockets.connect(BASE_WS) as ninth:
            refusal = await join(ninth, rid)
            check("ninth peer refused", refusal.get("code") == "room_full", str(refusal))
            check("refusal names the limit", refusal.get("limit") == 8)
    finally:
        for ws in sockets:
            await ws.close()


async def test_room_is_deleted_when_empty() -> None:
    print("\n[ the room is destroyed when the last peer leaves ]")
    stats_before = debug_stats()
    if stats_before is None:
        check("debug stats reachable", False,
              "start the server with DEBUG_STATS=1 to assert room deletion directly")
        return

    rid = room_id("ephemeral-test")
    async with websockets.connect(BASE_WS) as ws:
        await join(ws, rid)
        during = debug_stats()
        check("room exists while occupied", during["rooms"] == stats_before["rooms"] + 1, str(during))

    # Give the server a moment to run the disconnect handler.
    for _ in range(20):
        await asyncio.sleep(0.1)
        after = debug_stats()
        if after["rooms"] == stats_before["rooms"]:
            break
    check("room is gone once empty", after["rooms"] == stats_before["rooms"], str(after))
    check("no peers left behind", after["peers"] == stats_before["peers"], str(after))

    # Rejoining the same id must land in a fresh, empty room.
    async with websockets.connect(BASE_WS) as ws:
        welcome = await join(ws, rid)
        check("rejoin gets a fresh room", welcome.get("peers") == [], str(welcome))


async def test_peer_leave_notice() -> None:
    print("\n[ remaining peers are told when someone drops ]")
    rid = room_id("leave-test")
    async with websockets.connect(BASE_WS) as stayer:
        welcome_stayer = await join(stayer, rid)
        leaver = await websockets.connect(BASE_WS)
        welcome_leaver = await join(leaver, rid)
        await recv_json(stayer)  # peer-join

        await leaver.close()
        notice = await recv_json(stayer)
        check("peer-leave is broadcast",
              notice.get("type") == "peer-leave" and notice.get("peerId") == welcome_leaver["peerId"], str(notice))
        assert welcome_stayer["peerId"]


async def test_protocol_guards() -> None:
    print("\n[ protocol guards ]")
    async with websockets.connect(BASE_WS) as ws:
        await ws.send("this is not json")
        check("malformed json refused", (await recv_json(ws)).get("code") == "bad_json")

        await ws.send(json.dumps(["not", "an", "object"]))
        check("non-object refused", (await recv_json(ws)).get("code") == "bad_json")

        await ws.send(json.dumps({"type": "signal", "to": "x", "data": {}}))
        check("signal before join refused", (await recv_json(ws)).get("code") == "not_joined")

        rid = room_id("guard-test")
        await join(ws, rid)

        await ws.send(json.dumps({"type": "join", "room": rid}))
        check("double join refused", (await recv_json(ws)).get("code") == "already_joined")

        await ws.send(json.dumps({"type": "ping"}))
        check("ping answered", (await recv_json(ws)).get("type") == "pong")

        await ws.send(json.dumps({"type": "nonsense"}))
        check("unknown type refused", (await recv_json(ws)).get("code") == "unknown_type")


async def test_frame_size_tiers() -> None:
    print("\n[ oversized frames: graceful tier, then hard tier ]")

    # Just over the app limit (96 KiB): a polite refusal, socket stays usable.
    async with websockets.connect(BASE_WS, max_size=None) as ws:
        await join(ws, room_id("size-test"))
        await ws.send(json.dumps({"type": "signal", "to": "a" * 16, "data": "x" * (97 * 1024)}))
        refusal = await recv_json(ws)
        check("frame over the app limit is refused", refusal.get("code") == "frame_too_large", str(refusal))

        await ws.send(json.dumps({"type": "ping"}))
        check("socket survives the refusal", (await recv_json(ws)).get("type") == "pong")

    # Over the transport limit (192 KiB): the websocket layer hangs up first.
    async with websockets.connect(BASE_WS, max_size=None) as ws:
        await join(ws, room_id("size-test"))
        closed = False
        try:
            await ws.send(json.dumps({"type": "signal", "to": "a" * 16, "data": "x" * (200 * 1024)}))
            await recv_json(ws, timeout=3.0)
        except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
            closed = True
        check("frame over the transport limit closes the socket", closed)


async def test_rate_limit() -> None:
    print("\n[ the relay cannot be used as a firehose ]")
    async with websockets.connect(BASE_WS) as ws:
        await join(ws, room_id("flood-test"))
        limited = False
        for _ in range(600):
            await ws.send(json.dumps({"type": "ping"}))
        try:
            for _ in range(600):
                message = await recv_json(ws, timeout=3.0)
                if message.get("code") == "rate_limited":
                    limited = True
                    break
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass
        check("sustained flood is rate limited", limited)


async def main() -> int:
    print(f"Testing relay at {BASE_HTTP}")
    try:
        urllib.request.urlopen(f"{BASE_HTTP}/api/health", timeout=3).close()
    except Exception as exc:  # noqa: BLE001 - any failure here means "not running"
        print(f"\nCannot reach {BASE_HTTP}: {exc}")
        print("Start the server first:  .venv\\Scripts\\python.exe -m server.main")
        return 2

    for test in (
        test_static_and_headers,
        test_health_leaks_nothing,
        test_health_endpoint,
        test_room_id_validation,
        test_join_and_relay,
        test_cross_room_isolation,
        test_peer_cap,
        test_room_is_deleted_when_empty,
        test_peer_leave_notice,
        test_protocol_guards,
        test_frame_size_tiers,
        test_rate_limit,
    ):
        try:
            await test()
        except Exception as exc:  # noqa: BLE001 - report and keep going
            failed.append(test.__name__)
            print(f"  ERROR {test.__name__}: {type(exc).__name__}: {exc}")

    print(f"\n{'=' * 58}")
    print(f"{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("\nFailures:")
        for name in failed:
            print(f"  - {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
