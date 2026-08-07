"""
End-to-end test through two real browsers.

Launches headless Chrome, opens two pages against the running relay, joins both
to the same room, and checks the things the product actually promises: that the
mesh forms, that both sides derive the same session seal, that chat crosses the
encrypted DataChannel, that voice tracks flow, and that a peer with the wrong
passkey is refused.

Chrome is driven over the DevTools Protocol, so no extension or driver binary is
needed. A fake capture device stands in for a microphone, which is what lets
getUserMedia succeed without a permission prompt.

Run:
    # terminal 1
    .venv\\Scripts\\python.exe -m server.main

    # terminal 2
    .venv\\Scripts\\python.exe tests\\browser_e2e_test.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

import websockets

BASE_HTTP = os.environ.get("TEST_HTTP", "http://127.0.0.1:8000")
DEBUG_PORT = int(os.environ.get("TEST_CDP_PORT", "9333"))

ROOM = "kitchen-table"
PASSKEY = "correct-horse-battery-staple"
WRONG_PASSKEY = "not-the-passkey"

CHROME_CANDIDATES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)

#: Installed before the app's own scripts, so a throw during boot is recorded.
ERROR_COLLECTOR = """
window.__errors = [];
window.addEventListener('error', (e) => window.__errors.push(String(e.message)));
window.addEventListener('unhandledrejection',
  (e) => window.__errors.push('unhandled rejection: ' + String(e.reason)));
"""

passed: list[str] = []
failed: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        passed.append(name)
        print(f"  PASS  {name}")
    else:
        failed.append(name)
        print(f"  FAIL  {name}" + (f"  -- {detail}" if detail else ""))


def find_chrome() -> str | None:
    for path in CHROME_CANDIDATES:
        if path and os.path.isfile(path):
            return path
    return shutil.which("chrome") or shutil.which("chromium") or shutil.which("google-chrome")


# ---------------------------------------------------------------------------
# Minimal DevTools Protocol client
# ---------------------------------------------------------------------------

class Page:
    """One browser page, addressed over its own DevTools websocket."""

    def __init__(self, name: str, ws) -> None:
        self.name = name
        self.ws = ws
        self._next_id = 0

    async def call(self, method: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        self._next_id += 1
        message_id = self._next_id
        await self.ws.send(json.dumps({"id": message_id, "method": method, "params": params or {}}))
        while True:
            raw = await asyncio.wait_for(self.ws.recv(), timeout=timeout)
            message = json.loads(raw)
            if message.get("id") == message_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})
            # Anything else is an event we did not subscribe to; drop it.

    async def eval(self, expression: str, timeout: float = 30.0):
        """Evaluate an expression in the page and return its value."""
        result = await self.call(
            "Runtime.evaluate",
            {
                "expression": f"(async () => {{ {expression} }})()",
                "awaitPromise": True,
                "returnByValue": True,
            },
            timeout=timeout,
        )
        details = result.get("exceptionDetails")
        if details:
            raise RuntimeError(f"page exception: {details.get('text')} {details.get('exception', {}).get('description', '')}")
        return result.get("result", {}).get("value")

    async def wait_for(self, expression: str, seconds: float = 25.0, interval: float = 0.25):
        """Poll until truthy. Accepts a bare expression or a block with `return`."""
        body = expression if "return" in expression else f"return ({expression});"
        deadline = asyncio.get_event_loop().time() + seconds
        last = None
        while asyncio.get_event_loop().time() < deadline:
            last = await self.eval(body)
            if last:
                return last
            await asyncio.sleep(interval)
        return last


class Browser:
    def __init__(self, binary: str) -> None:
        self.binary = binary
        self.process: subprocess.Popen | None = None
        self.profile = tempfile.mkdtemp(prefix="chatroom-e2e-")
        self.browser_ws = None
        self.pages: list[Page] = []

    async def start(self) -> None:
        self.process = subprocess.Popen(
            [
                self.binary,
                "--headless=new",
                f"--remote-debugging-port={DEBUG_PORT}",
                f"--user-data-dir={self.profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-gpu",
                "--mute-audio",
                # A synthetic capture device: getUserMedia resolves with no prompt.
                "--use-fake-device-for-media-stream",
                "--use-fake-ui-for-media-stream",
                "--autoplay-policy=no-user-gesture-required",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        endpoint = None
        for _ in range(80):
            await asyncio.sleep(0.25)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{DEBUG_PORT}/json/version", timeout=2) as response:
                    endpoint = json.loads(response.read())["webSocketDebuggerUrl"]
                break
            except Exception:  # noqa: BLE001 - browser not up yet
                continue
        if not endpoint:
            raise RuntimeError("headless browser never exposed a DevTools endpoint")

        self.browser_ws = await websockets.connect(endpoint, max_size=None)
        self._browser_id = 0

    async def _browser_call(self, method: str, params: dict) -> dict:
        self._browser_id += 1
        await self.browser_ws.send(json.dumps({"id": self._browser_id, "method": method, "params": params}))
        while True:
            message = json.loads(await asyncio.wait_for(self.browser_ws.recv(), timeout=20))
            if message.get("id") == self._browser_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    async def open_page(self, name: str, url: str) -> Page:
        # Open blank first so the error collector is installed before any of the
        # app's own script runs -- otherwise a boot-time throw would go unseen.
        result = await self._browser_call("Target.createTarget", {"url": "about:blank"})
        target_id = result["targetId"]
        ws = await websockets.connect(
            f"ws://127.0.0.1:{DEBUG_PORT}/devtools/page/{target_id}", max_size=None
        )
        page = Page(name, ws)
        await page.call("Runtime.enable")
        await page.call("Page.enable")
        await page.call("Page.addScriptToEvaluateOnNewDocument", {"source": ERROR_COLLECTOR})
        await page.call("Page.navigate", {"url": url})

        ready = await page.wait_for("document.readyState === 'complete'", seconds=25)
        if not ready:
            raise RuntimeError(f"{name}: page never finished loading {url}")
        self.pages.append(page)
        return page

    async def stop(self) -> None:
        for page in self.pages:
            try:
                await page.ws.close()
            except Exception:  # noqa: BLE001
                pass
        if self.browser_ws:
            try:
                await self.browser_ws.close()
            except Exception:  # noqa: BLE001
                pass
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


# ---------------------------------------------------------------------------
# Page actions
# ---------------------------------------------------------------------------

JOIN_JS = """
const set = (id, value) => {{ document.getElementById(id).value = value; }};
set('f-room', {room!r});
set('f-passkey', {passkey!r});
set('f-nick', {nick!r});
document.getElementById('f-mic').checked = {mic};
document.getElementById('join-form').requestSubmit();
return true;
"""


async def join(page: Page, nick: str, passkey: str = PASSKEY, mic: bool = True) -> None:
    await page.eval(JOIN_JS.format(room=ROOM, passkey=passkey, nick=nick, mic="true" if mic else "false"))


async def in_room(page: Page) -> bool:
    return bool(await page.wait_for(
        "!document.getElementById('app').classList.contains('hidden')", seconds=45))


async def join_diagnostics(page: Page) -> str:
    """Why a join did not complete: the visible error, the work state, any throw."""
    return await page.eval("""
        const box = document.getElementById('join-error');
        const work = document.getElementById('join-work-text');
        return JSON.stringify({
            error: box.classList.contains('hidden') ? null : box.textContent,
            stuckAt: work.textContent || null,
            thrown: window.__errors || [],
        });
    """)


async def log_text(page: Page) -> list[str]:
    return await page.eval(
        "return [...document.querySelectorAll('#log .msg-body')].map(n => n.textContent);")


async def send_chat(page: Page, text: str) -> None:
    await page.eval(f"""
        const input = document.getElementById('composer-input');
        input.value = {text!r};
        document.getElementById('send-btn').click();
        return true;
    """)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def run(browser: Browser) -> None:
    print("\n[ two peers join the same room ]")
    alice = await browser.open_page("alice", f"{BASE_HTTP}/")
    bob = await browser.open_page("bob", f"{BASE_HTTP}/")

    for page in (alice, bob):
        ok = await page.wait_for(
            "document.getElementById('brand-seal')?.children.length === 16", seconds=20)
        check(f"{page.name}: page booted", bool(ok))
        fatal = await page.eval(
            "return !document.getElementById('fatal-screen').classList.contains('hidden');")
        check(f"{page.name}: no fatal error (secure context + WebCrypto)", not fatal)

    await join(alice, "alice")
    alice_in = await in_room(alice)
    check("alice reached the room", alice_in, "" if alice_in else await join_diagnostics(alice))

    await join(bob, "bob")
    bob_in = await in_room(bob)
    check("bob reached the room", bob_in, "" if bob_in else await join_diagnostics(bob))

    print("\n[ both sides derive the same session seal ]")
    seal_alice = await alice.eval("return document.getElementById('seal-code').textContent;")
    seal_bob = await bob.eval("return document.getElementById('seal-code').textContent;")
    check("seal is rendered", bool(seal_alice) and "·" not in seal_alice, str(seal_alice))
    check("seals match across peers", seal_alice == seal_bob, f"{seal_alice!r} vs {seal_bob!r}")
    check("seal is 4 groups of 4 hex", len((seal_alice or "").split()) == 4, str(seal_alice))

    print("\n[ the mesh connects ]")
    # Session state is deliberately not exposed on window, so this reads the
    # rendered transport panel -- the same thing a user would look at.
    connected = await alice.wait_for(
        "document.getElementById('transport').textContent.includes('1/1 connected')", seconds=40)
    check("alice sees a connected link", bool(connected))

    verified = await alice.wait_for(
        "[...document.querySelectorAll('#peer-list li')].some(li => li.textContent.includes('bob'))",
        seconds=30)
    check("alice's roster shows bob (proves HELLO decrypted)", bool(verified))
    verified_b = await bob.wait_for(
        "[...document.querySelectorAll('#peer-list li')].some(li => li.textContent.includes('alice'))",
        seconds=30)
    check("bob's roster shows alice", bool(verified_b))

    roster_count = await alice.eval("return document.getElementById('peer-count').textContent;")
    check("roster counts 2 of 8", roster_count == "2/8", str(roster_count))

    print("\n[ chat crosses the encrypted DataChannel ]")
    await send_chat(alice, "seal check: does yours match?")
    got = await bob.wait_for(
        "[...document.querySelectorAll('#log .msg-body')]"
        ".some(n => n.textContent.includes('seal check'))", seconds=20)
    check("bob received alice's message", bool(got))

    await send_chat(bob, "matches exactly")
    got_back = await alice.wait_for(
        "[...document.querySelectorAll('#log .msg-body')]"
        ".some(n => n.textContent.includes('matches exactly'))", seconds=20)
    check("alice received bob's reply", bool(got_back))

    author = await bob.eval("""
        const rows = [...document.querySelectorAll('#log .msg-body')];
        const hit = rows.find(n => n.textContent.includes('seal check'));
        return hit ? hit.closest('.msg-enter').querySelector('span').textContent : null;
    """)
    check("message is attributed to alice", author == "alice", str(author))

    print("\n[ voice ]")
    mic_state = await alice.eval("return document.getElementById('self-state').textContent;")
    check("alice has a live mic", "Mic live" in (mic_state or ""), str(mic_state))

    audio_flowing = await bob.wait_for("""
        const el = document.querySelector('#sinks audio');
        return !!(el && el.srcObject && el.srcObject.getAudioTracks().length > 0);
    """, seconds=25)
    check("bob has an inbound audio track", bool(audio_flowing))

    inbound = await bob.wait_for("""
        const peers = [...document.querySelectorAll('#peer-list li')];
        return peers.length >= 2;
    """, seconds=10)
    check("bob's roster is populated", bool(inbound))

    print("\n[ mute and deafen ]")
    await alice.eval("document.getElementById('mic-btn').click(); return true;")
    muted_locally = await alice.wait_for(
        "document.getElementById('self-state').textContent.includes('Muted')", seconds=10)
    check("alice shows muted", bool(muted_locally))
    muted_remotely = await bob.wait_for("""
        const row = [...document.querySelectorAll('#peer-list li')]
            .find(li => li.textContent.includes('alice'));
        return !!(row && row.querySelector('svg'));
    """, seconds=15)
    check("bob sees alice's mute (encrypted STATE frame)", bool(muted_remotely))
    await alice.eval("document.getElementById('mic-btn').click(); return true;")

    await bob.eval("document.getElementById('deaf-btn').click(); return true;")
    deafened = await bob.wait_for("""
        const el = document.querySelector('#sinks audio');
        return document.getElementById('self-state').textContent.includes('Deafened')
            && !!el && el.muted === true;
    """, seconds=10)
    check("deafen mutes the remote sink", bool(deafened))
    await bob.eval("document.getElementById('deaf-btn').click(); return true;")

    print("\n[ file transfer over the DataChannel ]")
    # 140 KiB forces multiple 16 KiB chunks, so this exercises the chunking and
    # backpressure path rather than a single-frame shortcut.
    await alice.eval("""
        const size = 140 * 1024;
        const bytes = new Uint8Array(size);
        for (let i = 0; i < size; i += 1) bytes[i] = i & 0xff;
        const transfer = new DataTransfer();
        transfer.items.add(new File([bytes], 'notes.bin', { type: 'application/octet-stream' }));
        const input = document.getElementById('file-input');
        input.files = transfer.files;
        input.dispatchEvent(new Event('change'));
        return true;
    """)

    received = await bob.wait_for("""
        const links = [...document.querySelectorAll('#log a[download]')];
        return links.some(a => a.download === 'notes.bin') ? 'yes' : false;
    """, seconds=40)
    check("bob received the file and can save it", received == "yes")

    # Verify by actually pressing Save, which is the path a user takes. Reading
    # the blob with fetch() would be blocked by this app's own CSP, and asking
    # the CSP to allow it just to make a test convenient is the wrong trade.
    download_dir = tempfile.mkdtemp(prefix="chatroom-dl-")
    await browser._browser_call("Browser.setDownloadBehavior", {
        "behavior": "allow", "downloadPath": download_dir,
    })
    await bob.eval("""
        const link = [...document.querySelectorAll('#log a[download]')]
            .find(a => a.download === 'notes.bin');
        link.click();
        return true;
    """)

    saved = os.path.join(download_dir, "notes.bin")
    for _ in range(60):
        if os.path.isfile(saved) and os.path.getsize(saved) == 140 * 1024:
            break
        await asyncio.sleep(0.25)
    check("Save writes the file to disk", os.path.isfile(saved),
          f"nothing in {download_dir}: {os.listdir(download_dir)}")

    if os.path.isfile(saved):
        with open(saved, "rb") as handle:
            data = handle.read()
        expected = bytes((i & 0xFF) for i in range(140 * 1024))
        check("every byte survived the round trip", data == expected,
              f"got {len(data)} bytes, expected {len(expected)}")
    shutil.rmtree(download_dir, ignore_errors=True)

    held_in_memory = await bob.eval("""
        const link = [...document.querySelectorAll('#log a[download]')]
            .find(a => a.download === 'notes.bin');
        return link ? link.href.startsWith('blob:') : false;
    """)
    check("the file is a blob in memory, never a server URL", bool(held_in_memory))

    sent_state = await alice.wait_for("""
        return [...document.querySelectorAll('#log')].some(
            n => n.textContent.includes('sent')) ? 'yes' : false;
    """, seconds=15)
    check("alice's card reports the file sent", sent_state == "yes")

    print("\n[ a peer with the wrong passkey is refused ]")
    mallory = await browser.open_page("mallory", f"{BASE_HTTP}/")
    await mallory.wait_for("document.getElementById('brand-seal').children.length === 16", seconds=20)
    await join(mallory, "mallory", passkey=WRONG_PASSKEY)
    reached = await in_room(mallory)
    check("wrong passkey still reaches the relay (it derives a different room id)", bool(reached))

    # A different passkey derives a different room id, so mallory lands in a
    # room of her own and never sees the real peers at all.
    alone = await mallory.eval("return document.getElementById('peer-count').textContent;")
    check("wrong passkey lands in a different room entirely", alone == "1/8", str(alone))

    mallory_seal = await mallory.eval("return document.getElementById('seal-code').textContent;")
    check("wrong passkey yields a different seal", mallory_seal != seal_alice,
          f"{mallory_seal!r} vs {seal_alice!r}")

    unaffected = await alice.eval("return document.getElementById('peer-count').textContent;")
    check("the real room is untouched", unaffected == "2/8", str(unaffected))

    print("\n[ leaving destroys the room view ]")
    await bob.eval("document.getElementById('leave-btn').click(); return true;")
    destroyed = await bob.wait_for(
        "document.getElementById('status-text').textContent === 'Destroyed'", seconds=10)
    check("bob's session reports destroyed", bool(destroyed))
    # The log keeps exactly one line -- the destruction notice. What must be gone
    # is every trace of the conversation itself.
    remaining = json.loads(await bob.eval("""
        const bodies = [...document.querySelectorAll('#log .msg-body')].map(n => n.textContent);
        return JSON.stringify({
            count: bodies.length,
            keptConversation: bodies.some(t => t.includes('seal check') || t.includes('matches exactly')),
            text: bodies.join(' | '),
        });
    """))
    check("bob's conversation is wiped", not remaining["keptConversation"], remaining["text"])
    check("only the destruction notice remains", remaining["count"] == 1, str(remaining))
    check("the notice says the room was destroyed",
          "destroyed" in remaining["text"].lower(), remaining["text"])
    zeroed = await bob.eval("return document.getElementById('seal-code').textContent;")
    check("bob's seal code is zeroed", zeroed.replace(" ", "") == "0" * 16, str(zeroed))
    key_dropped = await bob.eval(
        "return document.getElementById('composer-input').disabled === true;")
    check("bob's composer is disabled after leaving", bool(key_dropped))

    gone = await alice.wait_for("""
        return document.getElementById('peer-count').textContent === '1/8';
    """, seconds=20)
    check("alice sees bob leave", bool(gone))

    print("\n[ no page errors anywhere ]")
    for page in (alice, bob, mallory):
        errors = await page.eval("return window.__errors || [];")
        check(f"{page.name}: no uncaught errors", not errors, "; ".join(errors or []))


async def main() -> int:
    try:
        urllib.request.urlopen(f"{BASE_HTTP}/api/health", timeout=3).close()
    except Exception as exc:  # noqa: BLE001
        print(f"Cannot reach {BASE_HTTP}: {exc}")
        print("Start the server first:  .venv\\Scripts\\python.exe -m server.main")
        return 2

    binary = find_chrome()
    if not binary:
        print("No Chrome or Edge binary found; skipping the browser end-to-end test.")
        return 0
    print(f"Driving {binary}")

    browser = Browser(binary)
    try:
        await browser.start()
        await run(browser)
    except Exception as exc:  # noqa: BLE001
        failed.append("harness")
        print(f"\n  ERROR {type(exc).__name__}: {exc}")
    finally:
        await browser.stop()

    print(f"\n{'=' * 58}")
    print(f"{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("\nFailures:")
        for name in failed:
            print(f"  - {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
