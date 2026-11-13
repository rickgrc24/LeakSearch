#!/usr/bin/env python3
# check_passwords.py — test whether the username+password pairs found by LeakSearch
# still work on a site you specify.
#
# Purpose: defensive audit of your own accounts. It reads a LeakSearch export (CSV
# with "email,password,breach_sites" or TXT with one "email:password" per line),
# takes the username+password pairs it contains, and tries each pair against the
# site's real login form, so you know which leaked credentials are still live.
#
# Usage:
#   python3 check_passwords.py --url https://example.com/login --leaks leaks.csv
#
#   --leaks accepts a LeakSearch CSV export (email,password,breach_sites) or a TXT
#   export (one "email:password" per line). Every pair in the file is tested.
#   --basic tests HTTP Basic Auth instead of a login form.
#
# Detection is heuristic (baseline failed-login comparison + form disappearance):
# results are "WORKS", "failed", or "unclear (verify manually)". JavaScript-driven
# login pages (no HTML <form>) can't be tested with this script. Attempts are
# rate-limited (default 10s apart, max 20) to stay polite to the target site.

import argparse
import csv
import secrets
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

MAX_ATTEMPTS = 20
DEFAULT_DELAY = 10.0


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "fields": []}
        elif tag == "input" and self._form is not None:
            self._form["fields"].append({"name": a.get("name", ""), "type": (a.get("type") or "text").lower(),
                                         "value": a.get("value", "")})
        elif tag == "button" and self._form is not None and a.get("type") == "submit" and a.get("name"):
            self._form["fields"].append({"name": a["name"], "type": "submit", "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def fetch_login_form(session, url):
    """GET the page and return (response, form, method, absolute_action) for the form with a password field."""
    resp = session.get(url, timeout=30, allow_redirects=True)
    parser = FormParser()
    parser.feed(resp.text)
    for form in parser.forms:
        if any(f["type"] == "password" for f in form["fields"]):
            action = form["action"] or url
            return resp, form, form["method"], urljoin(resp.url, action)
    return resp, None, None, None


def build_payload(form, username, password):
    payload = {}
    user_fields = []
    for f in form["fields"]:
        name, ftype = f["name"], f["type"]
        if not name or ftype in ("submit", "button", "image"):
            continue
        if ftype == "hidden":
            payload[name] = f["value"]  # keep CSRF and friends
        elif ftype == "password":
            payload[name] = password
        elif ftype == "email" or any(hint in name.lower() for hint in ("user", "email", "login", "mail", "account", "nick")):
            user_fields.append(name)
        elif ftype == "checkbox":
            payload[name] = f["value"]
        else:
            payload[name] = f["value"]
    for i, name in enumerate(user_fields):
        payload[name] = username if i == 0 else ""
    return payload


def attempt(session, url, username, password, basic=False):
    """Submit one credential pair. Returns a dict describing the outcome page."""
    if basic:
        resp = session.get(url, timeout=30, allow_redirects=True, auth=(username, password))
        return {"status": resp.status_code, "url": resp.url, "auth_ok": resp.status_code == 200,
                "len": len(resp.content)}
    resp, form, method, action = fetch_login_form(session, url)
    if form is None:
        return {"status": resp.status_code, "url": resp.url, "no_form": True, "len": len(resp.content)}
    if method == "get":
        resp = session.get(action, params=build_payload(form, username, password), timeout=30, allow_redirects=True)
    else:
        resp = session.post(action, data=build_payload(form, username, password), timeout=30, allow_redirects=True)
    parser = FormParser()
    parser.feed(resp.text)
    still_has_form = any(any(f["type"] == "password" for f in fm["fields"]) for fm in parser.forms)
    return {"status": resp.status_code, "url": resp.url, "no_form": not still_has_form, "len": len(resp.content)}


def signature(resp):
    return (resp["status"], urlparse(resp["url"]).path)


def extract_pairs(path):
    """Pull username+password pairs from a LeakSearch CSV or TXT export."""
    pairs = []
    text = open(path, encoding="utf-8", errors="ignore").read()
    if path.lower().endswith(".csv"):
        for row in csv.reader(text.splitlines()):
            if len(row) >= 2 and row[0].strip() and row[1].strip():
                pairs.append((row[0].strip(), row[1]))
    else:
        for line in text.splitlines():
            if ":" in line:
                ident, pw = line.split(":", 1)
                if ident.strip() and pw.strip():
                    pairs.append((ident.strip(), pw))
    seen, unique = set(), []
    for user, pw in pairs:
        if (user.lower(), pw) not in seen:
            seen.add((user.lower(), pw))
            unique.append((user, pw))
    return unique


def main():
    ap = argparse.ArgumentParser(description="Test LeakSearch username+password pairs against a site's login.")
    ap.add_argument("--url", required=True, help="Login page URL (or resource URL for --basic)")
    ap.add_argument("--leaks", required=True, help="LeakSearch CSV or TXT export with the pairs to test")
    ap.add_argument("--basic", action="store_true", help="Site uses HTTP Basic Auth instead of a login form")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Seconds between attempts (default 10)")
    ap.add_argument("--max", type=int, default=MAX_ATTEMPTS, help="Maximum pairs to test (default 20)")
    args = ap.parse_args()

    pairs = extract_pairs(args.leaks)
    if not pairs:
        print(f"[!] No username/password pairs found in {args.leaks}")
        sys.exit(1)
    pairs = pairs[:args.max]
    print(f"[*] {len(pairs)} unique pair(s) to test against {args.url}")

    session = requests.session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) LeakSearch-self-audit"})

    baseline_user, baseline_pw = pairs[0][0], "definitely-wrong-" + secrets.token_hex(8)
    if args.basic:
        baseline = attempt(session, args.url, baseline_user, baseline_pw, basic=True)
        print(f"[*] Baseline (wrong password, Basic Auth): status {baseline['status']}")
    else:
        print("[*] Establishing a failed-login baseline with a random wrong password..")
        baseline = attempt(session, args.url, baseline_user, baseline_pw)
        if baseline.get("no_form"):
            print("[!] No HTML login form with a password field found at that URL.")
            print("    JavaScript-driven login pages can't be tested by this script.")
            sys.exit(1)
        print(f"[*] Baseline: status {baseline['status']}, path {urlparse(baseline['url']).path}, {baseline['len']} bytes")

    results = []
    for index, (user, password) in enumerate(pairs, 1):
        time.sleep(args.delay if index > 1 else 0)
        resp = attempt(session, args.url, user, password, args.basic)
        same_sig = signature(resp) == signature(baseline)
        similar_len = abs(resp["len"] - baseline["len"]) <= max(256, baseline["len"] // 20)
        if args.basic:
            verdict = "WORKS" if resp["auth_ok"] else "failed"
        elif resp.get("no_form"):
            verdict = "WORKS (login form gone after submit)" if not same_sig else "unclear (verify manually)"
        elif not same_sig and not similar_len:
            verdict = "probably WORKS (different response than a failed login - verify manually)"
        else:
            verdict = "failed"
        results.append((user, password, verdict, resp["status"], urlparse(resp["url"]).path))
        print(f"  [{index}/{len(pairs)}] {user:40} {'WORKS' if verdict.startswith(('WORKS', 'probably')) else verdict:52} pw={'<len %d>' % len(password)} status={resp['status']} -> {urlparse(resp['url']).path}")

    print("\n===== RESULTS =====")
    for user, password, verdict, status, path in results:
        shown = password if verdict.startswith(("WORKS", "probably")) else "*failed* " + password[:3] + ".."
        print(f"  {user:40} {verdict:52} password={shown}")

    working = [r for r in results if r[2].startswith(("WORKS", "probably"))]
    if working:
        print(f"\n[!] {len(working)} pair(s) still work on {urlparse(args.url).netloc}:")
        for user, password, verdict, status, path in working:
            print(f"      {user}  /  {password}")
    else:
        print("\n[+] None of the leaked pairs appear to be live on this site.")


if __name__ == "__main__":
    main()
