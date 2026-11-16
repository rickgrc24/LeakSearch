#!/usr/bin/env python3
# leakscan.py — comprehensive leak search for every username/email found in a
# LeakSearch export.
#
# Input:  one or more leaks CSV/TXT exports (a single file, several files, or a
#         glob like 'leaks_*.csv'). The username/email column is extracted.
# Action: every identity is searched across all selected LeakSearch sources
#         (default: proxynova + checkleaked; breachdirectory is quota-limited
#         and opt-in via --sources all).
# Output: a SEPARATE CSV per identity — <outdir>/<identity>.csv with
#         "email,password,breach_sites" rows — plus a combined
#         _all_found.csv. Locked records (paid-unlock on CheckLeaked) are kept
#         with an empty password and the site marked "(locked)".
#
# Usage:
#   python3 leakscan.py 'leaks_*.csv'
#   python3 leakscan.py leaks_@stake.csv leaks_johndoe99.csv --outdir found/
#   python3 leakscan.py 'leaks_*.csv' --proxy socks5h://127.0.0.1:9050

import argparse
import csv
import glob as _glob
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import LeakSearch as ls  # reuse the verified source functions + keychain access


def extract_identities(path: Path) -> list[str]:
    """Unique usernames/emails from a LeakSearch CSV export (first column)."""
    identities: list[str] = []
    seen: set[str] = set()
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() == ".csv":
        for row in csv.reader(text.splitlines()):
            if row and row[0].strip():
                ident = row[0].strip()
                if ident.lower() == "email":
                    continue  # header
                if ident.lower() not in seen:
                    seen.add(ident.lower())
                    identities.append(ident)
    else:
        for line in text.splitlines():
            if ":" in line:
                ident = line.split(":", 1)[0].strip()
                if ident and ident.lower() not in seen:
                    seen.add(ident.lower())
                    identities.append(ident)
    return identities


def parse_record(record: str) -> tuple[str, str, str]:
    """'user [site]:password' or 'user:password' -> (user, password, site).

    Locked CheckLeaked records ('user [site] (locked):password requires ...')
    become (user, '', 'site (locked)')."""
    ident, _, rest = record.partition(":")
    m = re.match(r"^(.*?)\s*\[([^\]]+)\](\s*\(locked\))?$", ident.strip())
    if m:
        user, site, locked = m.group(1).strip(), m.group(2).strip(), bool(m.group(3))
    else:
        user, site, locked = ident.strip(), "", False
    if locked or "password requires" in rest:
        return user, "", f"{site} (locked)".strip()
    return user, rest, site


def safe_name(ident: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._@+-]", "_", ident)
    return name[:100] or "unnamed"


SOURCES = {
    "proxynova": ls.find_leaks_proxynova,
    "checkleaked": ls.find_leaks_checkleaked,
    "breachdirectory": ls.find_leaks_breachdirectory,
}


def main() -> None:
    ap = argparse.ArgumentParser(description="Comprehensive leak search for every identity in LeakSearch exports.")
    ap.add_argument("inputs", nargs="+", help="LeakSearch CSV/TXT export(s), or a glob like 'leaks_*.csv'")
    ap.add_argument("--outdir", default="found", help="Directory for the per-identity CSVs (default: found/)")
    ap.add_argument("--sources", default="proxynova,checkleaked",
                    help="Comma-separated: proxynova,checkleaked,breachdirectory "
                         "or 'all' (breachdirectory free quota is usually exhausted)")
    ap.add_argument("--proxy", default=None, help="Optional proxy, e.g. socks5h://127.0.0.1:9050 (Tor)")
    ap.add_argument("--number", type=int, default=100, help="Max records per source per identity (default 100)")
    ap.add_argument("--delay", type=float, default=2.0, help="Seconds between identities (default 2)")
    args = ap.parse_args()

    files: list[Path] = []
    for pattern in args.inputs:
        if any(c in pattern for c in "*?["):
            matches = sorted(_glob.glob(pattern, recursive=True))  # glob module handles absolute paths
        else:
            matches = [pattern]
        files.extend(Path(m) for m in matches)
    files = sorted(set(f for f in files if f.is_file()))
    if not files:
        print("[!] No input files found.")
        sys.exit(1)

    wanted = [s.strip().lower() for s in args.sources.split(",")]
    if "all" in wanted:
        wanted = list(SOURCES)
    unknown = [s for s in wanted if s not in SOURCES]
    if unknown:
        print(f"[!] Unknown source(s): {', '.join(unknown)} (available: {', '.join(SOURCES)}, or 'all')")
        sys.exit(1)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    all_path = outdir / "_all_found.csv"

    identities: list[str] = []
    seen: set[str] = set()
    for f in files:
        for ident in extract_identities(f):
            if ident not in seen:
                seen.add(ident)
                identities.append(ident)

    print(f"[*] {len(files)} input file(s), {len(identities)} unique identit(ies) to scan "
          f"across {', '.join(wanted)} -> {outdir}/\n", flush=True)

    combined_header_written = all_path.exists()
    totals = {"identities": 0, "records": 0, "locked": 0}

    for index, ident in enumerate(identities, 1):
        rows: dict[tuple[str, str, str], str] = {}   # (user,password,site) -> source
        per_source: dict[str, int] = {}
        for source in wanted:
            try:
                records = SOURCES[source](ident, args.proxy, args.number)
            except Exception as exc:            # a dead source must not stop the scan
                print(f"    [!] {source} error: {exc}")
                records = []
            per_source[source] = len(records)
            for record in records:
                user, password, site = parse_record(record)
                if not password:
                    totals["locked"] += 1
                key = (user.lower(), password, site.lower())
                rows.setdefault(key, source)
            time.sleep(0.4)   # be polite between sources

        out_file = outdir / f"{safe_name(ident)}.csv"
        with open(out_file, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["email", "password", "breach_sites"])
            for (user, password, site) in rows:
                writer.writerow([user, password, site])
        with open(all_path, "a", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            if not combined_header_written:
                writer.writerow(["email", "password", "breach_sites", "source", "searched_as"])
                combined_header_written = True
            for (user, password, site), source in rows.items():
                writer.writerow([user, password, site, source, ident])

        locked_n = sum(1 for (_, pw, _) in rows if not pw)
        totals["identities"] += 1
        totals["records"] += len(rows)
        detail = ", ".join(f"{s}: {n}" for s, n in per_source.items())
        print(f"  [{index}/{len(identities)}] {ident:42} {len(rows):>3} record(s) "
              f"({locked_n} locked) [{detail}] -> {out_file.name}", flush=True)
        if index < len(identities):
            time.sleep(args.delay)

    print(f"\n[+] Done: {totals['identities']} identit(ies), {totals['records']} unique record(s) "
          f"({totals['locked']} locked, no plaintext available). Per-identity CSVs in {outdir}/, "
          f"combined list in {all_path}")


if __name__ == "__main__":
    main()
