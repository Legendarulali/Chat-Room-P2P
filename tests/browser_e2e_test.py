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
    def __init__(self, binary: str, port: int = DEBUG_PORT, extra_args: tuple[str, ...] = ()) -> None:
        self.binary = binary
        self.port = port
        self.extra_args = extra_args
        self.process: subprocess.Popen | None = None
        self.profile = tempfile.mkdtemp(prefix="chatroom-e2e-")
        self.browser_ws = None
        self.pages: list[Page] = []

    async def start(self) -> None:
        self.process = subprocess.Popen(
            [
                self.binary,
                "--headless=new",
                f"--remote-debugging-port={self.port}",
                f"--user-data-dir={self.profile}",
                *self.extra_args,
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
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=2) as response:
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

    async def open_page(self, name: str, url: str, preload: str = "") -> Page:
        # Open blank first so the error collector is installed before any of the
        # app's own script runs -- otherwise a boot-time throw would go unseen.
        result = await self._browser_call("Target.createTarget", {"url": "about:blank"})
        target_id = result["targetId"]
        ws = await websockets.connect(
            f"ws://127.0.0.1:{self.port}/devtools/page/{target_id}", max_size=None
        )
        page = Page(name, ws)
        await page.call("Runtime.enable")
        await page.call("Page.enable")
        await page.call("Page.addScriptToEvaluateOnNewDocument", {"source": ERROR_COLLECTOR})
        if preload:
            # Runs before app.js, which is the only point at which setting
            # window.SIGNALING_URL has any effect.
            await page.call("Page.addScriptToEvaluateOnNewDocument", {"source": preload})
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
set('f-capacity', {capacity});
document.getElementById('f-mic').checked = {mic};
document.getElementById('join-form').requestSubmit();
return true;
"""


async def join(
    page: Page, nick: str, passkey: str = PASSKEY, mic: bool = True,
    capacity: int = 8, room: str = ROOM,
) -> None:
    await page.eval(JOIN_JS.format(
        room=room, passkey=passkey, nick=nick, capacity=capacity,
        mic="true" if mic else "false",
    ))


async def roster(page: Page) -> list[str]:
    """Just the display names in the sidebar, in order.

    peerRow puts the name in its own span.truncate, separate from the crown glyph
    and the "you" tag, so this reads the name and nothing else.
    """
    names = await page.eval("""
        return JSON.stringify([...document.querySelectorAll('#peer-list li')]
            .map(li => li.querySelector('p span.truncate')?.textContent.trim() ?? null));
    """)
    return json.loads(names)


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

    print("\n[ host ownership in the UI ]")
    # alice opened the room, so she wears the crown and gets the stepper.
    crown_on_alice = await alice.eval("""
        const rows = [...document.querySelectorAll('#peer-list li')];
        const mine = rows.find(li => li.textContent.includes('you'));
        return mine ? mine.textContent.includes('\\u{1F451}') : false;
    """)
    check("alice's own row shows the crown", bool(crown_on_alice))

    crown_seen_by_bob = await bob.wait_for("""
        const rows = [...document.querySelectorAll('#peer-list li')];
        const other = rows.find(li => li.textContent.includes('alice'));
        return other && other.textContent.includes('\\u{1F451}') ? 'yes' : false;
    """, seconds=20)
    check("bob sees the crown on alice", crown_seen_by_bob == "yes")

    bob_crown_count = await bob.eval("""
        return [...document.querySelectorAll('#peer-list li')]
            .filter(li => li.textContent.includes('\\u{1F451}')).length;
    """)
    check("exactly one crown in the room", bob_crown_count == 1, str(bob_crown_count))

    host_colour = await bob.eval("""
        const row = [...document.querySelectorAll('#peer-list li')]
            .find(li => li.textContent.includes('alice'));
        const name = row ? row.querySelector('p') : null;
        return name ? getComputedStyle(name).color : null;
    """)
    # --amber is #f2b544 -> rgb(242, 181, 68)
    check("host name is rendered amber", host_colour == "rgb(242, 181, 68)", str(host_colour))

    print("\n[ host-only capacity controls ]")
    alice_panel = await alice.eval(
        "return !document.getElementById('capacity-control').classList.contains('hidden');")
    check("host sees the capacity stepper", bool(alice_panel))
    bob_panel = await bob.eval(
        "return !document.getElementById('capacity-control').classList.contains('hidden');")
    check("non-host does not see the stepper", not bob_panel)

    shown = await alice.eval("return document.getElementById('capacity-value').textContent;")
    check("stepper shows headcount over capacity", shown.strip() == "2 / 8", repr(shown))

    await alice.eval("document.getElementById('capacity-up').click(); return true;")
    raised = await alice.wait_for(
        "document.getElementById('capacity-value').textContent.trim() === '2 / 9'", seconds=15)
    check("host raised the limit to 9", bool(raised),
          await alice.eval("return document.getElementById('capacity-value').textContent;"))

    bob_saw = await bob.wait_for(
        "document.getElementById('peer-count').textContent === '2/9'", seconds=15)
    check("bob's roster reflects the new limit", bool(bob_saw),
          await bob.eval("return document.getElementById('peer-count').textContent;"))

    warned = await alice.eval("return document.getElementById('capacity-note').textContent;")
    check("host is warned that voice degrades past 8", "mesh" in warned.lower(), warned)

    await alice.eval("document.getElementById('capacity-down').click(); return true;")
    lowered = await alice.wait_for(
        "document.getElementById('capacity-value').textContent.trim() === '2 / 8'", seconds=15)
    check("host lowered it back to 8", bool(lowered))

    # Two people are in the room, so the floor is 2: the button must bottom out
    # rather than let a number change evict anyone.
    for _ in range(10):
        await alice.eval("document.getElementById('capacity-down').click(); return true;")
        await asyncio.sleep(0.15)
    floored = await alice.eval("return document.getElementById('capacity-value').textContent;")
    check("lowering stops at the headcount", floored.strip() == "2 / 2", repr(floored))
    disabled = await alice.eval("return document.getElementById('capacity-down').disabled;")
    check("the minus button disables at the floor", bool(disabled))

    print("\n[ a third peer is refused once the room is full ]")
    gatecrasher = await browser.open_page("gatecrasher", f"{BASE_HTTP}/")
    await gatecrasher.wait_for("document.getElementById('brand-seal')?.children.length === 16", seconds=20)
    await join(gatecrasher, "carol")
    refused = await gatecrasher.wait_for("""
        const box = document.getElementById('join-error');
        return !box.classList.contains('hidden') && /full/i.test(box.textContent) ? 'yes' : false;
    """, seconds=25)
    check("third peer told the room is full", refused == "yes",
          await gatecrasher.eval("return document.getElementById('join-error').textContent;"))
    check("gatecrasher never entered the room",
          await gatecrasher.eval(
              "return document.getElementById('app').classList.contains('hidden');"))

    # Clicks accumulate against a local intent now, so a burst reaches its
    # target -- which is exactly the regression this next line guards.
    await alice.eval("""
        const up = document.getElementById('capacity-up');
        for (let i = 0; i < 6; i += 1) up.click();
        return true;
    """)
    restored = await alice.wait_for(
        "document.getElementById('capacity-value').textContent.trim() === '2 / 8'", seconds=20)
    check("a burst of 6 clicks moves the limit by 6", bool(restored),
          await alice.eval("return document.getElementById('capacity-value').textContent;"))

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

    # The bar must actually reach the end. A card that says "sent" over a
    # part-filled bar is the kind of detail that reads as a stuck transfer.
    bar = await alice.wait_for("""
        const fill = [...document.querySelectorAll('#log [data-role="file-progress"]')].pop();
        if (!fill) return false;
        const track = fill.parentElement.getBoundingClientRect().width;
        const done = fill.getBoundingClientRect().width;
        return track > 0 ? JSON.stringify({ pct: Math.round((done / track) * 100),
                                            css: fill.style.width }) : false;
    """, seconds=20)
    measured = json.loads(bar) if bar else {}
    check("sender's progress bar is full", measured.get("pct") == 100, str(measured))

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

    print("\n[ the crown moves when the host leaves ]")
    # alice is the host; when she goes, mallory is alone in her own room, so use
    # a fresh pair to watch the handover in a shared room.
    host = await browser.open_page("host", f"{BASE_HTTP}/")
    heir = await browser.open_page("heir", f"{BASE_HTTP}/")
    for page in (host, heir):
        await page.wait_for("document.getElementById('brand-seal')?.children.length === 16", seconds=20)

    await alice.eval("document.getElementById('leave-btn').click(); return true;")
    await asyncio.sleep(1.0)  # let the room empty so the pair opens it fresh

    await join(host, "dana")
    await in_room(host)
    await join(heir, "erik")
    await in_room(heir)
    await heir.wait_for("[...document.querySelectorAll('#peer-list li')].length >= 2", seconds=40)

    check("dana holds the crown first",
          bool(await host.eval(
              "return !document.getElementById('capacity-control').classList.contains('hidden');")))
    check("erik has no controls yet",
          not await heir.eval(
              "return !document.getElementById('capacity-control').classList.contains('hidden');"))

    await host.eval("document.getElementById('leave-btn').click(); return true;")

    promoted = await heir.wait_for("""
        const rows = [...document.querySelectorAll('#peer-list li')];
        const mine = rows.find(li => li.textContent.includes('you'));
        return mine && mine.textContent.includes('\\u{1F451}') ? 'yes' : false;
    """, seconds=25)
    check("erik inherits the crown", promoted == "yes")

    inherited_panel = await heir.wait_for(
        "!document.getElementById('capacity-control').classList.contains('hidden')", seconds=15)
    check("erik gains the capacity stepper", bool(inherited_panel))

    told = await heir.eval("""
        return [...document.querySelectorAll('#log .msg-body')]
            .some(n => /host now/i.test(n.textContent));
    """)
    check("erik is told he is the host now", bool(told))

    # And the inherited control actually works.
    await heir.eval("document.getElementById('capacity-up').click(); return true;")
    works = await heir.wait_for(
        "document.getElementById('capacity-value').textContent.trim() === '1 / 9'", seconds=15)
    check("the inherited stepper works", bool(works),
          await heir.eval("return document.getElementById('capacity-value').textContent;"))

    print("\n[ signaling address resolution ]")
    relay_row = await alice.eval("""
        const rows = [...document.querySelectorAll('#transport > div')];
        const row = rows.find(r => r.querySelector('dt')?.textContent === 'relay');
        return row ? row.querySelector('dd').textContent : null;
    """)
    check("transport panel reports the relay host", relay_row is not None, str(relay_row))
    check("same-origin relay is not flagged as external",
          relay_row is not None and not relay_row.endswith("*"), str(relay_row))

    # An explicitly configured address must be used verbatim, and must work.
    configured = await browser.open_page(
        "configured", f"{BASE_HTTP}/",
        preload=f"window.SIGNALING_URL = 'ws://127.0.0.1:{BASE_HTTP.rsplit(':', 1)[1]}/ws';",
    )
    await configured.wait_for("document.getElementById('brand-seal')?.children.length === 16", seconds=20)
    check("configured address does not block boot",
          await configured.eval(
              "return document.getElementById('join-error').classList.contains('hidden');"))
    await join(configured, "frank")
    check("a configured SIGNALING_URL connects", await in_room(configured))
    configured_row = await configured.eval("""
        const rows = [...document.querySelectorAll('#transport > div')];
        const row = rows.find(r => r.querySelector('dt')?.textContent === 'relay');
        return row ? row.querySelector('dd').textContent : null;
    """)
    check("configured relay is flagged as external",
          configured_row is not None and configured_row.endswith("*"), str(configured_row))
    await configured.eval("document.getElementById('leave-btn').click(); return true;")

    # A bad address must name itself in the error rather than failing silently.
    broken = await browser.open_page(
        "broken", f"{BASE_HTTP}/",
        preload="window.SIGNALING_URL = 'ws://127.0.0.1:9/ws';",
    )
    await broken.wait_for("document.getElementById('brand-seal')?.children.length === 16", seconds=20)
    await join(broken, "grace")
    told = await broken.wait_for("""
        const box = document.getElementById('join-error');
        return !box.classList.contains('hidden') ? box.textContent : false;
    """, seconds=40)
    check("unreachable relay is reported", bool(told), str(told))
    check("the error names the address", "127.0.0.1:9" in str(told), str(told))
    check("the error names the config knob", "SIGNALING_URL" in str(told), str(told))

    # Bare host and https:// forms must normalise to a wss:// /ws endpoint.
    forms = await alice.eval("""
        const cases = ['example.com', 'example.com/ws', 'https://example.com',
                       'wss://example.com/custom', 'ws://example.com'];
        return JSON.stringify(cases.map(c => {
            const u = normalizeSignalingUrl(c);
            return u ? u.href : null;
        }));
    """)
    normalised = json.loads(forms)
    check("bare host normalises to /ws", normalised[0].endswith("://example.com/ws"), str(normalised[0]))
    check("host with path is kept", normalised[1].endswith("/ws"), str(normalised[1]))
    check("https:// becomes wss://", normalised[2].startswith("wss://"), str(normalised[2]))
    check("an explicit path is preserved", normalised[3] == "wss://example.com/custom", str(normalised[3]))
    check("ws:// is left as ws://", normalised[4].startswith("ws://"), str(normalised[4]))

    print("\n[ no page errors anywhere ]")
    for page in (alice, bob, mallory, gatecrasher, host, heir, configured, broken):
        errors = await page.eval("return window.__errors || [];")
        check(f"{page.name}: no uncaught errors", not errors, "; ".join(errors or []))


async def run_static_host_check(binary: str) -> None:
    """The reported Vercel bug, reproduced.

    Chrome's host resolver is pointed at the local relay for a hostname ending
    in .vercel.app, so the page really is served from a static-looking origin.
    resolveSignalingUrl is then asked what it would do. No network is involved
    beyond localhost, so this does not depend on any deployment existing.
    """
    print("\n[ a page on a static host must not signal to its own host ]")
    port = BASE_HTTP.rsplit(":", 1)[1]
    # Deliberately not *.vercel.app: .app is an HSTS-preloaded TLD, so Chrome
    # force-upgrades it to https and a plain-http test page is impossible.
    # .surge.sh is in the same STATIC_ONLY_HOSTS list and reachable over http,
    # so it exercises the identical branch. That vercel.app is recognised is
    # asserted separately below.
    fake = "chat-room-p2p.surge.sh"
    browser = Browser(
        binary,
        port=DEBUG_PORT + 1,
        # MAP takes a host pattern and a replacement host; the URL's port is
        # preserved, so it must not appear in the pattern.
        extra_args=(f"--host-resolver-rules=MAP {fake} 127.0.0.1",),
    )
    try:
        await browser.start()
        page = await browser.open_page("static", f"http://{fake}:{port}/")
        await page.wait_for("typeof resolveSignalingUrl === 'function'", seconds=25)

        check("page really is on a static-host name",
              await page.eval("return location.hostname;") == fake,
              await page.eval("return location.hostname;"))

        # The hostname from the bug report must be recognised by the same list.
        recognised = json.loads(await page.eval("""
            const hosts = ['chat-room-p2p.vercel.app', 'anything.netlify.app',
                           'user.github.io', 'proj.pages.dev', 'x.surge.sh',
                           '127.0.0.1', 'chat.example.com'];
            return JSON.stringify(hosts.map(
                h => [h, STATIC_ONLY_HOSTS.some(s => h.endsWith(s))]));
        """))
        by_host = dict(recognised)
        check("chat-room-p2p.vercel.app is treated as a static host",
              by_host["chat-room-p2p.vercel.app"] is True, str(by_host))
        check("netlify, pages.dev and github.io too",
              all(by_host[h] for h in ("anything.netlify.app", "user.github.io", "proj.pages.dev")),
              str(by_host))
        check("a real relay host is not misclassified",
              by_host["127.0.0.1"] is False and by_host["chat.example.com"] is False, str(by_host))

        resolved = json.loads(await page.eval("return JSON.stringify(resolveSignalingUrl());"))
        check("static host is detected", resolved.get("source") == "fallback", str(resolved))
        check("does NOT signal to its own host",
              "vercel.app" not in str(resolved.get("url")), str(resolved))
        check("falls back to the configured relay",
              "chat-room-p2p.onrender.com" in str(resolved.get("url")), str(resolved))
        check("fallback resolves to the /ws endpoint",
              str(resolved.get("url")).endswith("/ws"), str(resolved))
        check("no error on the fallback path", resolved.get("error") is None, str(resolved))

        # An explicit override must still beat the fallback on a static host.
        overridden = json.loads(await page.eval("""
            window.SIGNALING_URL = 'wss://relay.example.org/ws';
            const r = resolveSignalingUrl();
            delete window.SIGNALING_URL;
            return JSON.stringify(r);
        """))
        check("SIGNALING_URL overrides the fallback",
              overridden.get("source") == "configured"
              and overridden.get("url") == "wss://relay.example.org/ws", str(overridden))

        # And a same-origin override on a static host must be called out.
        self_pointed = json.loads(await page.eval(f"""
            window.SIGNALING_URL = 'ws://{fake}:{port}/ws';
            const r = resolveSignalingUrl();
            delete window.SIGNALING_URL;
            return JSON.stringify(r);
        """))
        check("pointing a static host at itself is refused with an explanation",
              bool(self_pointed.get("error")) and "only serves files" in str(self_pointed.get("error")),
              str(self_pointed))
    finally:
        await browser.stop()


async def run_identity_checks(browser: Browser) -> None:
    """Three people, all claiming the same name, in their own room.

    The property that matters is agreement: it is no use if each client picks its
    own answer, because then one person's "dan (2)" is another's "dan" and the
    confusion is worse than the duplicate was. Nothing coordinates this -- the
    relay never sees a display name -- so each client has to derive the same
    answer from what it independently knows.
    """
    probe = await browser.open_page("probe", f"{BASE_HTTP}/")
    await probe.wait_for("document.getElementById('brand-seal')?.children.length === 16", seconds=25)

    # A stray --> once closed the config comment early, and the paragraph after it
    # rendered as body text at the top of the page. Nothing in the markup is
    # supposed to reach the screen except through an element the app controls, so
    # assert that directly rather than trusting the delimiters to stay matched.
    print("\n[ no documentation leaks into the page ]")
    leaked = await probe.eval("""
        const text = document.body.innerText;
        const terms = ['ICE_SERVERS', 'SIGNALING_URL', 'FALLBACK_', 'coturn',
                       'OpenRelay', 'connect-src', 'wss://', '-->'];
        return JSON.stringify(terms.filter(t => text.includes(t)));
    """)
    check("no config prose is rendered", json.loads(leaked) == [], str(leaked))

    stray = await probe.eval("""
        // Any text node directly under <body> or <head> that is not whitespace.
        const loose = [];
        for (const root of [document.head, document.body]) {
            for (const node of root.childNodes) {
                if (node.nodeType === 3 && node.textContent.trim()) {
                    loose.push(node.textContent.trim().slice(0, 60));
                }
            }
        }
        return JSON.stringify(loose);
    """)
    check("no loose text nodes outside an element", json.loads(stray) == [], str(stray))

    print("\n[ display names: the pure function ]")

    # cleanNick is what stops a name from being made to *look* like another one.
    cleaned = await probe.eval(r"""
        return JSON.stringify({
            zeroWidth: cleanNick('dan\u200b'),
            rtlOverride: cleanNick('dan\u202e'),
            bom: cleanNick('\ufeffdan'),
            controls: cleanNick('da\u0007n'),
            spaces: cleanNick('  dan   smith  '),
            newline: cleanNick('dan\nsmith'),
            empty: cleanNick('\u200b\u200b'),
            blank: cleanNick('   '),
            missing: cleanNick(null),
            tooLong: cleanNick('x'.repeat(80)).length,
            foldsCase: foldNick('DAN') === foldNick('dan'),
            foldsInvisible: foldNick('dan\u200b') === foldNick('dan'),
        });
    """)
    got = json.loads(cleaned)
    check("a zero-width space is stripped", got["zeroWidth"] == "dan", str(got["zeroWidth"]))
    check("a bidi override is stripped", got["rtlOverride"] == "dan", str(got["rtlOverride"]))
    check("a byte order mark is stripped", got["bom"] == "dan", str(got["bom"]))
    check("control characters are stripped", got["controls"] == "dan", str(got["controls"]))
    check("runs of whitespace collapse", got["spaces"] == "dan smith", str(got["spaces"]))
    check("a newline cannot split a name", got["newline"] == "dan smith", str(got["newline"]))
    check("an all-invisible name falls back", got["empty"] == "peer", str(got["empty"]))
    check("a blank name falls back", got["blank"] == "peer", str(got["blank"]))
    check("a missing name falls back", got["missing"] == "peer", str(got["missing"]))
    check("a long name is truncated", got["tooLong"] == 24, str(got["tooLong"]))
    check("case does not make a new person", got["foldsCase"] is True)
    check("an invisible does not make a new person", got["foldsInvisible"] is True)

    # resolveLabels reads the live room, so drive it against a fabricated one. The
    # interesting inputs are the ones that would be tedious to arrange with real
    # peers -- above all somebody claiming the literal string another peer has
    # already been *given*.
    print("\n[ display names: collisions resolve to distinct labels ]")
    resolved = await probe.eval("""
        const label = (nicks) => {
            // A throwaway room: resolveLabels only needs order, id, and nick.
            state.peerId = 'self';
            state.nick = cleanNick(nicks[0]);
            state.selfOrder = 0;
            state.peers = new Map(nicks.slice(1).map((nick, i) => [
                'p' + i,
                { id: 'p' + i, order: i + 1, nick: cleanNick(nick), label: null },
            ]));
            resolveLabels();
            return [state.label, ...[...state.peers.values()].map(p => p.label)];
        };
        const out = {
            plain: label(['ana', 'ben']),
            twoSame: label(['dan', 'dan']),
            threeSame: label(['dan', 'dan', 'dan']),
            caseOnly: label(['Dan', 'dan']),
            invisible: label(['dan', 'dan\\u200b']),
            claimsTheSuffix: label(['dan', 'dan', 'dan (2)']),
            suffixFirst: label(['dan (2)', 'dan', 'dan']),
        };
        state.peers = new Map();
        return JSON.stringify(out);
    """)
    got = json.loads(resolved)
    check("distinct names are left alone", got["plain"] == ["ana", "ben"], str(got["plain"]))
    check("two of the same name get a counter",
          got["twoSame"] == ["dan", "dan (2)"], str(got["twoSame"]))
    check("three of the same name keep counting",
          got["threeSame"] == ["dan", "dan (2)", "dan (3)"], str(got["threeSame"]))
    check("a case-only difference still counts as a collision",
          got["caseOnly"] == ["Dan", "dan (2)"], str(got["caseOnly"]))
    check("an invisible character does not dodge the collision",
          got["invisible"] == ["dan", "dan (2)"], str(got["invisible"]))
    # The bypass: claiming the label the second "dan" was handed.
    check("claiming another peer's assigned label does not duplicate it",
          got["claimsTheSuffix"] == ["dan", "dan (2)", "dan (2) (2)"],
          str(got["claimsTheSuffix"]))
    check("a name that already looks like a counter is not special",
          len(set(got["suffixFirst"])) == 3, str(got["suffixFirst"]))
    for key, labels in got.items():
        check(f"every label in the {key} case is unique",
              len({name.lower() for name in labels}) == len(labels), str(labels))

    print("\n[ three peers all called dan ]")
    room = "identity-room"
    first = await browser.open_page("dan-1", f"{BASE_HTTP}/")
    second = await browser.open_page("dan-2", f"{BASE_HTTP}/")
    third = await browser.open_page("dan-3", f"{BASE_HTTP}/")
    for page in (first, second, third):
        await page.wait_for("document.getElementById('brand-seal')?.children.length === 16", seconds=25)

    # Sequential, so arrival order is unambiguous. The third uses a zero-width
    # space, which is the impersonation attempt: without cleanNick it would render
    # as a third bare "dan" rather than colliding.
    await join(first, "dan", room=room, mic=False)
    check("the first dan joined", await in_room(first))
    await join(second, "dan", room=room, mic=False)
    check("the second dan joined", await in_room(second))
    await join(third, "dan\u200b", room=room, mic=False)
    check("the third dan joined", await in_room(third))

    settled = await first.wait_for(
        "document.getElementById('peer-count').textContent === '3/8'", seconds=90)
    check("all three are in the room", bool(settled),
          await first.eval("return document.getElementById('peer-count').textContent;"))

    for page in (first, second, third):
        await page.wait_for("""
            return [...document.querySelectorAll('#peer-list li')]
                .every(li => li.querySelector('p span.truncate')
                    ?.textContent.trim().startsWith('dan')) ? 'yes' : false;
        """, seconds=90)

    views = {page.name: sorted(await roster(page)) for page in (first, second, third)}
    expected = sorted(["dan", "dan (2)", "dan (3)"])
    for name, view in views.items():
        check(f"{name} sees three distinguishable names", view == expected, str(view))
    check("every client agrees on the same three names",
          len({tuple(v) for v in views.values()}) == 1, str(views))

    # Agreement has to go further than the set of names: each client must attach
    # the same name to the same person.
    labels = {}
    for page in (first, second, third):
        labels[page.name] = json.loads(await page.eval("""
            const out = { self: [state.peerId, state.label] };
            for (const p of state.peers.values()) out[p.id] = p.label;
            return JSON.stringify(out);
        """))
    mapping = {}
    agree = True
    for view in labels.values():
        own_id, own_label = view.pop("self")
        for peer_id, label in list(view.items()) + [(own_id, own_label)]:
            if mapping.setdefault(peer_id, label) != label:
                agree = False
    check("no peer id is labelled two different ways", agree, str(labels))
    check("three distinct people, three distinct labels",
          len(set(mapping.values())) == 3, str(mapping))

    # The incumbent keeps the bare name: arrival order decides, so nobody already
    # in the room is renamed by a newcomer.
    own = {}
    for page in (first, second, third):
        own[page.name] = await page.eval("return state.label;")
    check("the first to arrive keeps the plain name", own["dan-1"] == "dan", str(own))
    check("the second gets a counter", own["dan-2"] == "dan (2)", str(own))
    check("the third gets the next counter", own["dan-3"] == "dan (3)", str(own))

    # And a message is attributed to the label, not the claim.
    await send_chat(third, "which dan is this")
    attributed = await first.wait_for("""
        const rows = [...document.querySelectorAll('#log .msg-enter')];
        const row = rows.find(r => r.textContent.includes('which dan is this'));
        if (!row) return false;
        return row.querySelector('[data-field="name"]')?.textContent || false;
    """, seconds=60)
    check("a message from the third dan is labelled dan (3)", attributed == "dan (3)", str(attributed))

    # A rename onto a name already present must be announced, not absorbed: a
    # silent one is exactly how impersonation would work.
    await third.eval("""
        const peers = [...state.peers.values()];
        for (const p of peers) p.send(F.HELLO, { nick: 'renamed-dan', muted: false, deafened: false });
        return true;
    """)
    announced = await first.wait_for("""
        return [...document.querySelectorAll('#log .msg-body')]
            .some(n => /is now calling themselves/i.test(n.textContent)) ? 'yes' : false;
    """, seconds=60)
    check("a mid-session rename is announced", announced == "yes",
          str(await log_text(first)))
    relabelled = await first.wait_for("""
        const rows = [...document.querySelectorAll('#log .msg-enter')];
        const row = rows.find(r => r.textContent.includes('which dan is this'));
        return row?.querySelector('[data-field="name"]')?.textContent === 'renamed-dan'
            ? 'yes' : false;
    """, seconds=30)
    check("their earlier message is relabelled to match", relabelled == "yes",
          await first.eval("""
            const rows = [...document.querySelectorAll('#log .msg-enter')];
            const row = rows.find(r => r.textContent.includes('which dan is this'));
            return row?.querySelector('[data-field="name"]')?.textContent || 'gone';
          """))

    for page in (probe, first, second, third):
        errors = await page.eval("return window.__errors || [];")
        check(f"{page.name}: no uncaught errors", not errors, "; ".join(errors or []))


async def run_reconnect_check(binary: str) -> None:
    """Kill the relay under two live clients and watch them come back.

    Two phases, because the two outages are not the same failure:

      1. The socket drops while the relay stays up. The relay still holds the
         room, so it recognises the session and hands the same peer id back --
         the peers keep their connections and only ICE is restarted.
      2. The relay process restarts. Its rooms were in memory, so they are gone;
         there is nothing to resume and the mesh has to be rebuilt. What matters
         here is that it rebuilds *once* per peer instead of accumulating ghosts.

    A relay of its own, because restarting the shared one would break every other
    check. CDP's offline emulation is not an alternative: it leaves loopback
    connections alone, so it drops nothing at all.
    """
    print("\n[ two clients on a private relay ]")

    import socket as _socket

    def free_port() -> int:
        with _socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python = os.path.join(repo, ".venv", "Scripts", "python.exe")
    if not os.path.isfile(python):
        python = os.path.join(repo, ".venv", "bin", "python")

    port = free_port()
    base = f"http://127.0.0.1:{port}"

    def start_relay() -> subprocess.Popen:
        env = dict(os.environ)
        env.update({"HOST": "127.0.0.1", "PORT": str(port), "PYTHONUNBUFFERED": "1"})
        env.pop("DEBUG_STATS", None)
        return subprocess.Popen(
            [python, "-m", "server.main"], cwd=repo, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    async def wait_up(timeout: float = 30.0) -> bool:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                with urllib.request.urlopen(f"{base}/health", timeout=2) as r:
                    if r.status == 200:
                        return True
            except Exception:  # noqa: BLE001 - not up yet
                await asyncio.sleep(0.3)
        return False

    relay = start_relay()
    browser = Browser(binary, port=DEBUG_PORT + 2)
    try:
        check("test relay started", await wait_up())
        await browser.start()

        one = await browser.open_page("one", f"{base}/")
        two = await browser.open_page("two", f"{base}/")
        for page in (one, two):
            await page.wait_for("document.getElementById('brand-seal')?.children.length === 16", seconds=25)

        await join(one, "ivy")
        check("ivy joined", await in_room(one))
        await join(two, "jonas")
        check("jonas joined", await in_room(two))

        formed = await one.wait_for(
            "document.getElementById('transport').textContent.includes('1/1 connected')", seconds=60)
        check("mesh formed before the restart", bool(formed))

        # -- Phase one: the signaling path moves, the relay stays up -----------
        #
        # A network change leaves the relay holding a socket it does not yet know
        # is dead: the phone's route is gone, so no close frame ever arrives and
        # the peer stays in the room until the relay's own ping times out. The new
        # socket therefore turns up *while the old one is still registered*, which
        # is the only ordering under which a resume is possible.
        #
        # That ordering is what is reproduced here. It is not simulated by closing
        # the socket: a close frame reaches the relay immediately, the peer is torn
        # down before the reconnect lands, and a rebuild is then the correct
        # outcome -- which is what phase two covers. So this drives rejoin()
        # directly, with the relay in exactly the state a network change leaves it.
        print("\n[ a moved signaling path resumes rather than rebuilding ]")

        before = await one.eval("""
            const peer = [...state.peers.values()][0];
            // Tag the live objects. If either is replaced, this peer was rebuilt,
            // which is exactly what must not happen.
            peer.__probe = 'kept';
            peer.channel.__probe = 'kept';
            return JSON.stringify({ peerId: state.peerId, otherId: peer.id, verified: peer.verified });
        """)
        marks = json.loads(before)
        check("ivy is verified before the drop", marks["verified"] is True, str(marks))

        resumed = await one.eval("""
            state.reconnecting = true;
            await rejoin();
            return [...document.querySelectorAll('#log .msg-body')]
                .some(n => /reconnected/i.test(n.textContent)) ? 'yes' : false;
        """, timeout=90)
        check("ivy rejoins and is told so", resumed == "yes",
              await one.eval("return document.getElementById('status-text').textContent;"))
        kept_note = await one.eval("""
            const body = [...document.querySelectorAll('#log .msg-body')]
                .reverse().find(n => /reconnected/i.test(n.textContent));
            return body ? body.textContent : null;
        """)
        check("the notice says the connection was kept, not rebuilt",
              "kept" in (kept_note or "") and "rebuilding" not in (kept_note or ""),
              str(kept_note))

        after = await one.eval("""
            const peer = state.peers.get(%s);
            return JSON.stringify({
                peerId: state.peerId,
                found: Boolean(peer),
                peerKept: peer?.__probe === 'kept',
                channelKept: peer?.channel?.__probe === 'kept',
                verified: peer?.verified === true,
                open: peer?.channel?.readyState === 'open',
                count: document.getElementById('peer-count').textContent,
                roster: [...document.querySelectorAll('#peer-list li')].length,
            });
        """ % json.dumps(marks["otherId"]))
        state_after = json.loads(after)
        check("ivy keeps the same peer id across the resume",
              state_after["peerId"] == marks["peerId"], str(state_after))
        check("the peer object was not replaced", state_after["peerKept"] is True, str(state_after))
        check("the DataChannel survived the resume", state_after["channelKept"] is True, str(state_after))
        check("the channel is still open", state_after["open"] is True, str(state_after))
        check("no re-verification was needed", state_after["verified"] is True, str(state_after))
        check("the room did not double", state_after["count"] == "2/8", str(state_after))
        check("the roster still holds exactly two", state_after["roster"] == 2, str(state_after))

        # jonas saw a resume, not a departure and an arrival.
        churn = await two.eval("""
            const bodies = [...document.querySelectorAll('#log .msg-body')].map(n => n.textContent);
            return JSON.stringify({
                left: bodies.filter(t => / left\\.$/.test(t)).length,
                joined: bodies.filter(t => / joined\\.$/.test(t)).length,
                count: document.getElementById('peer-count').textContent,
            });
        """)
        seen = json.loads(churn)
        check("jonas was never told ivy left", seen["left"] == 0, str(seen))
        check("jonas saw ivy join exactly once", seen["joined"] == 1, str(seen))
        check("jonas still counts two people", seen["count"] == "2/8", str(seen))

        still_talking = "resumed without a rebuild"
        await send_chat(two, still_talking)
        carried = await one.wait_for("""
            return [...document.querySelectorAll('#log .msg-body')]
                .some(n => n.textContent.includes('without a rebuild')) ? 'yes' : false;
        """, seconds=60)
        check("the surviving channel still carries chat", carried == "yes")

        # The ICE restart branch itself. On loopback the connection never actually
        # breaks, so resume() correctly declines to restart a working path -- the
        # branch has to be reached by making the connection report failure.
        print("\n[ resume() decides correctly per connection state ]")
        decisions = await one.eval("""
            const peer = [...state.peers.values()][0];
            const result = {};

            result.connectedNoRestart = (() => {
                let restarts = 0;
                const real = peer.pc.restartIce;
                peer.pc.restartIce = () => { restarts += 1; };
                const kept = peer.resume();
                peer.pc.restartIce = real;
                return kept === true && restarts === 0;
            })();

            const pretend = (value) => Object.defineProperty(peer.pc, 'connectionState', {
                configurable: true, get: () => value,
            });

            result.failedRestarts = (() => {
                let restarts = 0;
                const real = peer.pc.restartIce;
                peer.pc.restartIce = () => { restarts += 1; };
                pretend('failed');
                const kept = peer.resume();
                delete peer.pc.connectionState;
                peer.pc.restartIce = real;
                clearTimeout(peer.connectTimer);
                return kept === true && restarts === 1;
            })();

            result.disconnectedRestarts = (() => {
                let restarts = 0;
                const real = peer.pc.restartIce;
                peer.pc.restartIce = () => { restarts += 1; };
                pretend('disconnected');
                const kept = peer.resume();
                delete peer.pc.connectionState;
                peer.pc.restartIce = real;
                clearTimeout(peer.connectTimer);
                return kept === true && restarts === 1;
            })();

            result.connectingRebuilds = (() => {
                pretend('connecting');
                const kept = peer.resume();
                delete peer.pc.connectionState;
                return kept === false;
            })();

            result.staleRebuilds = (() => {
                peer.stale = true;
                const kept = peer.resume();
                peer.stale = false;
                return kept === false;
            })();

            // The legacy path must produce a real ICE-restart offer, since that is
            // the only option on an engine without restartIce().
            result.legacyOffer = await (async () => {
                const pc = new RTCPeerConnection();
                pc.createDataChannel('probe');
                await pc.setLocalDescription();
                const first = pc.localDescription.sdp.match(/a=ice-ufrag:(\\S+)/)[1];
                const offer = await pc.createOffer({ iceRestart: true });
                const second = offer.sdp.match(/a=ice-ufrag:(\\S+)/)[1];
                pc.close();
                return first !== second;
            })();

            return JSON.stringify(result);
        """)
        decided = json.loads(decisions)
        check("a connection that never broke is kept without a restart",
              decided["connectedNoRestart"] is True, str(decided))
        check("a failed connection is kept and gets an ICE restart",
              decided["failedRestarts"] is True, str(decided))
        check("a disconnected connection is kept and gets an ICE restart",
              decided["disconnectedRestarts"] is True, str(decided))
        check("one that never connected is rebuilt instead",
              decided["connectingRebuilds"] is True, str(decided))
        check("one whose channel died is rebuilt instead",
              decided["staleRebuilds"] is True, str(decided))
        check("iceRestart: true produces fresh ICE credentials",
              decided["legacyOffer"] is True, str(decided))

        # -- Phase two: the relay itself restarts -----------------------------
        print("\n[ the relay restarts under two live clients ]")

        # Phase one already put "lost the connection" and "Reconnected" in the log,
        # so waiting for the text alone would match instantly and test nothing.
        # Count first, then wait for the count to go up.
        async def log_hits(page: Page, pattern: str) -> int:
            return await page.eval(f"""
                return [...document.querySelectorAll('#log .msg-body')]
                    .filter(n => {pattern}.test(n.textContent)).length;
            """)

        lost_before = await log_hits(one, "/lost the connection/i")
        back_before = await log_hits(one, "/reconnected/i")

        # A restarted relay has lost every room, so both peers must come back with
        # new ids. That makes the ids, not the headcount, the signal that a rebuild
        # really happened -- the headcount reads 2/8 both before and after.
        ids_before = json.loads(await one.eval("""
            return JSON.stringify({ self: state.peerId, other: [...state.peers.keys()][0] });
        """))

        relay.terminate()
        try:
            relay.wait(timeout=10)
        except subprocess.TimeoutExpired:
            relay.kill()

        dropped = await one.wait_for(f"""
            return [...document.querySelectorAll('#log .msg-body')]
                .filter(n => /lost the connection/i.test(n.textContent)).length > {lost_before}
                ? 'yes' : false;
        """, seconds=45)
        check("ivy notices the relay went away", dropped == "yes",
              await one.eval("return document.getElementById('status-text').textContent;"))

        # The mesh is deliberately *not* torn down. A relay outage says nothing
        # about whether the peers can still reach each other, and dropping them
        # here would throw away connections an ICE restart could repair.
        held = await one.eval("return document.getElementById('peer-count').textContent;")
        check("ivy keeps the room while the relay is away", held == "2/8", str(held))

        kept_roster = await roster(one)
        check("jonas stays in her roster through the outage",
              len(kept_roster) == 2 and any("jonas" in (n or "") for n in kept_roster),
              str(kept_roster))
        no_exit = await one.eval("""
            return [...document.querySelectorAll('#log .msg-body')]
                .filter(n => / left\\.$/.test(n.textContent)).length;
        """)
        check("nobody is reported as having left", no_exit == 0, str(no_exit))

        # And back up.
        relay = start_relay()
        check("test relay restarted", await wait_up())

        recovered = await one.wait_for(f"""
            return [...document.querySelectorAll('#log .msg-body')]
                .filter(n => /reconnected/i.test(n.textContent)).length > {back_before}
                ? 'yes' : false;
        """, seconds=120)
        check("ivy reconnects unattended", recovered == "yes",
              await one.eval("return document.getElementById('status-text').textContent;"))

        # Rebuilt, not resumed: both ids are new, and jonas's old entry is gone
        # rather than sitting alongside the new one.
        settled = await one.wait_for(f"""
            const ids = [...state.peers.keys()];
            return (state.peerId !== {json.dumps(ids_before['self'])}
                && ids.length === 1
                && ids[0] !== {json.dumps(ids_before['other'])}
                && document.getElementById('peer-count').textContent === '2/8') ? 'yes' : false;
        """, seconds=120)
        check("the room settles back to two people, both with new ids", settled == "yes",
              await one.eval("""
                return JSON.stringify({
                    self: state.peerId,
                    peers: [...state.peers.keys()],
                    count: document.getElementById('peer-count').textContent,
                });
              """))

        # The ghost check: exactly one of each person, not two.
        names = await roster(one)
        jonas_rows = [n for n in names if n and "jonas" in n]
        check("no duplicate jonas after the reconnect", len(jonas_rows) == 1, str(names))
        check("and jonas is not renamed to jonas (2)", jonas_rows == ["jonas"], str(names))

        remade = await one.wait_for(
            "document.getElementById('transport').textContent.includes('1/1 connected')", seconds=120)
        check("the mesh re-forms", bool(remade))

        await send_chat(two, "back after the restart")
        delivered = await one.wait_for("""
            return [...document.querySelectorAll('#log .msg-body')]
                .some(n => n.textContent.includes('after the restart')) ? 'yes' : false;
        """, seconds=60)
        check("encrypted chat works again", delivered == "yes")

        for page in (one, two):
            errors = await page.eval("return window.__errors || [];")
            check(f"{page.name}: no uncaught errors through the outage", not errors,
                  "; ".join(errors or []))
    finally:
        await browser.stop()
        if relay.poll() is None:
            relay.terminate()
            try:
                relay.wait(timeout=10)
            except subprocess.TimeoutExpired:
                relay.kill()


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
        # Shares the browser and the relay, but uses a room of its own so it
        # cannot disturb anything above.
        await run_identity_checks(browser)
    except Exception as exc:  # noqa: BLE001 - report and keep going
        failed.append("harness")
        print(f"\n  ERROR {type(exc).__name__}: {exc}")
    finally:
        await browser.stop()

    # Runs in its own browser: it needs host-resolver rules the main instance
    # must not have, since they would rewrite every other page's origin.
    try:
        await run_static_host_check(binary)
    except Exception as exc:  # noqa: BLE001 - report and keep going
        failed.append("static-host-harness")
        print(f"\n  ERROR {type(exc).__name__}: {exc}")

    # Its own relay as well as its own browser, because it restarts the relay --
    # which nothing else running against the shared one could survive.
    try:
        await run_reconnect_check(binary)
    except Exception as exc:  # noqa: BLE001 - report and keep going
        failed.append("reconnect-harness")
        print(f"\n  ERROR {type(exc).__name__}: {exc}")

    print(f"\n{'=' * 58}")
    print(f"{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("\nFailures:")
        for name in failed:
            print(f"  - {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
