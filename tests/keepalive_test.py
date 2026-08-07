"""
Checks on the keep-alive loop and its Discord notice.

Self-contained: starts its own relay and its own mock endpoint, so it needs no
Render account, no Discord server, and no already-running server.

Three things are verified, and the third is the one that matters most:

  1. The loop fires, and it targets RENDER_EXTERNAL_URL + "/health".
  2. The Discord payload is a well-formed embed.
  3. The Discord payload carries no session data. A webhook that leaked room
     ids or peer counts would quietly undo the whole point of this project,
     so that is asserted rather than assumed.

And the loop's central promise -- that it never dies -- is tested by pointing
it at a closed port and confirming it keeps going afterwards.

Run:
    .venv\\Scripts\\python.exe tests\\keepalive_test.py
"""

from __future__ import annotations

import http.server
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
if not PYTHON.is_file():  # non-Windows checkout
    PYTHON = REPO_ROOT / ".venv" / "bin" / "python"

passed: list[str] = []
failed: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        passed.append(name)
        print(f"  PASS  {name}")
    else:
        failed.append(name)
        print(f"  FAIL  {name}" + (f"  -- {detail}" if detail else ""))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---------------------------------------------------------------------------
# Mock endpoint standing in for both Render's router and Discord
# ---------------------------------------------------------------------------

class Capture:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, str]] = []
        self.lock = threading.Lock()

    def add(self, method: str, path: str, body: str) -> None:
        with self.lock:
            self.requests.append((method, path, body))

    def matching(self, method: str, path: str) -> list[tuple[str, str, str]]:
        with self.lock:
            return [r for r in self.requests if r[0] == method and r[1] == path]


def make_server(capture: Capture, port: int) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            capture.add("GET", self.path, "")
            body = b'{"status":"ok","timestamp":"mock"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            capture.add("POST", self.path, self.rfile.read(length).decode("utf-8", "replace"))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args) -> None:
            pass  # this test is about the relay's output, not the mock's

    return http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)


def start_relay(env_extra: dict[str, str], port: int) -> subprocess.Popen:
    env = dict(os.environ)
    env.update({
        "HOST": "127.0.0.1",  # never bind all interfaces during a test
        "PORT": str(port),
        "PYTHONUNBUFFERED": "1",
    })
    env.update(env_extra)
    env.pop("DEBUG_STATS", None)
    return subprocess.Popen(
        [str(PYTHON), "-m", "server.main"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def wait_until_up(port: int, timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(0.3)
    return False


def wait_for(predicate, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------


def test_ping_and_discord() -> None:
    print("\n[ the loop pings, and notifies Discord without leaking anything ]")
    mock_port, relay_port = free_port(), free_port()
    capture = Capture()
    mock = make_server(capture, mock_port)
    threading.Thread(target=mock.serve_forever, daemon=True).start()

    relay = start_relay(
        {
            "RENDER_EXTERNAL_URL": f"http://127.0.0.1:{mock_port}",
            "DISCORD_WEBHOOK_URL": f"http://127.0.0.1:{mock_port}/discord",
            "KEEPALIVE_INTERVAL_SECONDS": "3",
        },
        relay_port,
    )
    try:
        check("relay started", wait_until_up(relay_port))

        got_ping = wait_for(lambda: capture.matching("GET", "/health"), timeout=30)
        check("keep-alive GET reached RENDER_EXTERNAL_URL + /health", got_ping)

        got_hook = wait_for(lambda: capture.matching("POST", "/discord"), timeout=30)
        check("Discord webhook received a POST", got_hook)

        if not got_hook:
            return

        raw = capture.matching("POST", "/discord")[0][2]
        try:
            payload = json.loads(raw)
        except ValueError:
            check("Discord payload is JSON", False, raw[:200])
            return
        check("Discord payload is JSON", True)

        embeds = payload.get("embeds")
        check("payload carries exactly one embed", isinstance(embeds, list) and len(embeds) == 1, str(embeds)[:200])
        embed = embeds[0] if isinstance(embeds, list) and embeds else {}
        check("embed title reports a successful ping", "Keep-alive" in str(embed.get("title")), str(embed.get("title")))
        check("embed carries a timestamp", isinstance(embed.get("timestamp"), str), str(embed.get("timestamp")))
        check("embed reports the HTTP status", "200" in str(embed.get("description")), str(embed.get("description")))

        # The privacy assertion. A room id is 64 hex chars and a peer id is 16;
        # neither may appear, and no room or peer tallies either.
        check("no room id in the payload", re.search(r"\b[0-9a-f]{64}\b", raw) is None)
        check("no peer id in the payload", re.search(r"\b[0-9a-f]{16}\b", raw) is None)
        check('no "rooms" field', '"rooms"' not in raw)
        check('no "peers" field', '"peers"' not in raw)
        check("no IP address in the payload",
              re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw.replace(f"127.0.0.1:{mock_port}", "")) is None,
              raw[:200])

        # Several cycles must complete, which is what "never terminates" means
        # in practice: the loop keeps going rather than firing once.
        repeated = wait_for(lambda: len(capture.matching("GET", "/health")) >= 3, timeout=30)
        check("loop keeps cycling (3+ pings observed)", repeated,
              f"saw {len(capture.matching('GET', '/health'))}")
    finally:
        relay.terminate()
        relay.wait(timeout=15)
        mock.shutdown()


def test_loop_survives_a_dead_target() -> None:
    print("\n[ a failing ping costs one cycle, not the loop ]")
    relay_port = free_port()
    # Port 9 discards; nothing accepts, so every ping raises.
    relay = start_relay(
        {
            "RENDER_EXTERNAL_URL": "http://127.0.0.1:9",
            "DISCORD_WEBHOOK_URL": "http://127.0.0.1:9/discord",
            "KEEPALIVE_INTERVAL_SECONDS": "2",
        },
        relay_port,
    )
    try:
        check("relay started with an unreachable ping target", wait_until_up(relay_port))

        # Let several cycles fail.
        time.sleep(12)

        still_alive = relay.poll() is None
        check("process survived repeated ping failures", still_alive,
              f"exit code {relay.poll()}")
        check("relay still serves /health after failures", wait_until_up(relay_port, timeout=8))

        # And it is still serving websockets, i.e. the failures stayed contained
        # to the keep-alive task.
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{relay_port}/api/health", timeout=4) as response:
                ok = json.loads(response.read()).get("ok") is True
        except Exception:  # noqa: BLE001
            ok = False
        check("unrelated endpoints unaffected", ok)
    finally:
        relay.terminate()
        try:
            relay.wait(timeout=15)
        except subprocess.TimeoutExpired:
            relay.kill()


def test_zero_log_holds_with_keepalive() -> None:
    print("\n[ the keep-alive loop does not start writing logs ]")
    mock_port, relay_port = free_port(), free_port()
    capture = Capture()
    mock = make_server(capture, mock_port)
    threading.Thread(target=mock.serve_forever, daemon=True).start()

    relay = start_relay(
        {
            "RENDER_EXTERNAL_URL": f"http://127.0.0.1:{mock_port}",
            "DISCORD_WEBHOOK_URL": f"http://127.0.0.1:{mock_port}/discord",
            "KEEPALIVE_INTERVAL_SECONDS": "2",
        },
        relay_port,
    )
    try:
        wait_until_up(relay_port)
        wait_for(lambda: len(capture.matching("GET", "/health")) >= 3, timeout=25)
        relay.terminate()
        output = relay.communicate(timeout=15)[0] or ""
    finally:
        mock.shutdown()

    lines = [line for line in output.splitlines() if line.strip()]
    # Banner only: the relay line, the rooms line, the keep-alive line, plus the
    # two NOTE lines this configuration prints.
    check("no per-ping output", not any("Keep-alive ping OK" in line for line in lines), output[:300])
    check("stdout stays at banner size", len(lines) <= 6, f"{len(lines)} lines: {lines}")
    check("banner names the keep-alive target",
          any("keep-alive: every" in line for line in lines), str(lines))
    check("banner discloses the Discord webhook",
          any("DISCORD_WEBHOOK_URL is set" in line for line in lines), str(lines))
    check("banner discloses open CORS",
          any("CORS is open" in line for line in lines), str(lines))


def main() -> int:
    if not PYTHON.is_file():
        print(f"No interpreter at {PYTHON}. Create the venv first.")
        return 2

    for test in (test_ping_and_discord, test_loop_survives_a_dead_target, test_zero_log_holds_with_keepalive):
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report and continue
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
    sys.exit(main())
