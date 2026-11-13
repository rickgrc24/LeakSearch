#!/usr/bin/python3
#============================#
#  LeakSearch by @JoelGMSec  #
#    https://darkbyte.net    #
#============================#

import os
import time
import csv
import json
import hashlib
import urllib3
import requests
import argparse
import subprocess
from urllib.parse import quote
from concurrent.futures import ProcessPoolExecutor
from tabulate import tabulate
from neotermcolor import colored
from requests import ConnectionError
urllib3.disable_warnings()

banner = r"""
  _               _     ____                      _     
 | |    ___  __ _| | __/ ___|  ___  __ _ _ __ ___| |__  
 | |   / _ \/ _` | |/ /\___ \ / _ \/ _` | '__/ __| '_ \ 
 | |__|  __/ (_| |   <  ___) |  __/ (_| | | | (__| | | |
 |_____\___|\__,_|_|\_\|____/ \___|\__,_|_|  \___|_| |_|"""

banner2 = r"""                                               
  ------------------- by @JoelGMSec -------------------
  """

def find_leaks_proxynova(email, proxy, number):
    # Endpoint verified from proxynova.com's own frontend:
    # GET https://api.proxynova.com/comb?query=<term>&start=<offset>&limit=<n>
    # Server-side rule (verified live): a request only succeeds while
    # start + limit <= 100 - the API serves at most the first 100 records
    # of any query ("You are limited to 100 results"), and windows differ
    # between query variants. To drain more, the email, its local part and
    # local@domain for every domain seen so far are queried in turn and the
    # results are merged and de-duplicated.
    # Endpoint verified from proxynova.com's own frontend:
    # GET https://api.proxynova.com/comb?query=<term>&start=<offset>&limit=<n>
    # Server-side rules (verified live): a request only succeeds while
    # start + limit <= 100, so at most the first 100 records of any query
    # are served ("You are limited to 100 results"); querying variants of
    # the same term (full email, local part, local@domain) always returns
    # the same underlying records, so nothing beyond that window exists on
    # their side. The email and its local part are queried and merged to
    # be safe, records are de-duplicated, and only lines containing the
    # searched local part are kept (the API also returns unrelated fuzzy
    # matches for a query).
    session = requests.session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    headers = {'User-Agent': 'curl'}
    queries = [email]
    local = None
    if '@' in email:
        local = email.split('@', 1)[0]
        if local and local != email:
            queries.append(local)
    needle = (local or email).lower()

    seen, lines = set(), []
    for index, query in enumerate(queries):
        url = f"https://api.proxynova.com/comb?query={quote(query)}&start=0&limit=100"
        response = session.get(url, headers=headers, verify=False)
        if response.status_code != 200:
            if index == 0:
                print(colored(f"[!] Failed to fetch results from ProxyNova. Status code: {response.status_code}\n", "red"))
            continue
        data = response.json()
        if index == 0:
            total = data.get("count", 0)
            print(colored(f"[*] Found {total} different records in database (the API serves at most 100 per query)", "magenta"), end='')
        for line in data.get("lines", []) or []:
            if needle in line.lower() and line not in seen:
                seen.add(line)
                lines.append(line)
        if len(lines) >= number:
            break
        time.sleep(0.3)
    return lines[:number]

# Common passwords tried first when cracking a hash, before any wordlist.
_COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567890", "1234567", "111111", "123123", "abc123", "1234",
    "password1", "iloveyou", "000000", "qwerty123", "1q2w3e", "aa123456789",
    "monkey", "dragon", "letmein", "welcome", "admin", "login", "princess",
    "solo", "qwertyuiop", "starwars", "passw0rd", "football", "baseball",
    "sunshine", "master", "shadow", "superman", "batman", "michael",
    "football1", "trustno1", "hello", "freedom", "whatever", "qazwsx",
    "guest", "charlie", "thomas", "robert", "access", "love", "sex",
    "secret", "summer", "winter", "spring", "autumn", "killer", "george",
    "hunter", "soccer", "hockey", "anime", "internet", "service",
    "canada", "hello123", "ranger", "daniel", "hannah", "jennifer",
    "joshua", "bailey", "dylan", "jordan", "tigger", "purple", "cookie",
    "naruto", "samsung", "google", "facebook", "pokemon", "chocolate",
    "flower", "hottie", "loveme", "zaq12wsx", "1qaz2wsx", "asdfghjkl",
    "qwerty12", "pass123", "pass1234", "root", "toor", "test", "abcd1234",
]

def _find_wordlist():
    # Optional wordlist for cracking: LEAKSEARCH_WORDLIST env var first,
    # then common rockyou locations. Returns None if none is available.
    for path in (os.environ.get("LEAKSEARCH_WORDLIST"),
                 "/usr/share/wordlists/rockyou.txt",
                 "/opt/homebrew/share/wordlists/rockyou.txt",
                 os.path.expanduser("~/wordlists/rockyou.txt")):
        if path and os.path.exists(path):
            return path
    return None

def _crack_hash(digest, hashtype, salt, wordlist):
    # BreachDirectory returns hashes when the plaintext is not in their own
    # database: MD5 / SHA-1 / SHA-256, optionally salted. Cracking is a
    # dictionary attack: candidates are tried with and without the salt
    # prepended/appended since the exact salt convention is not documented.
    digest = digest.strip().lower()
    hashtype = (hashtype or "").upper()

    def matches(password):
        candidates = (salt + password, password + salt) if salt else (password,)
        for cand in candidates:
            encoded = cand.encode("utf-8", "ignore")
            if "MD5" in hashtype and hashlib.md5(encoded).hexdigest() == digest:
                return password
            if "SHA1" in hashtype and hashlib.sha1(encoded).hexdigest() == digest:
                return password
            if "SHA256" in hashtype and hashlib.sha256(encoded).hexdigest() == digest:
                return password
        return None

    for password in _COMMON_PASSWORDS:
        found = matches(password)
        if found:
            return found

    if not wordlist:
        return None

    try:
        with open(wordlist, "rb") as f:
            for raw in f:
                password = raw.decode("utf-8", "ignore").strip("\r\n")
                if password:
                    found = matches(password)
                    if found:
                        return found
    except OSError:
        pass
    return None

def find_leaks_breachdirectory(keyword, proxy, number):
    # BreachDirectory over RapidAPI (endpoint and headers verified live from
    # their RapidAPI listing): GET https://breachdirectory.p.rapidapi.com/
    # with func=auto&term=<keyword>. The free BASIC plan allows 10 requests
    # per month. Entries carry the plaintext password when their database
    # knows it, otherwise a hash (MD5/SHA-1/SHA-256, optionally salted)
    # which we attempt to crack with the embedded list + an optional
    # wordlist, plus 'sources' naming the breaches each record came from.
    api_key = get_key("breachdirectory_user")
    if not api_key:
        key_missing("breachdirectory_user")
        return []

    url = f"https://breachdirectory.p.rapidapi.com/?func=auto&term={quote(keyword)}"
    session = requests.session()
    session.headers.update({"x-rapidapi-key": api_key,
                            "x-rapidapi-host": "breachdirectory.p.rapidapi.com"})
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    response = session.get(url, timeout=60)
    if response.status_code != 200:
        print(colored(f"[!] Failed to fetch results from BreachDirectory. Status code: {response.status_code}\n"
                      "    (the free plan allows 10 requests/month; a 429 means the quota is spent until it resets)\n", "red"))
        return []

    data = response.json()
    if not data.get("success") or not data.get("results"):
        return []

    wordlist = _find_wordlist()
    if not wordlist:
        print(colored("[*] No wordlist found for hash cracking (set LEAKSEARCH_WORDLIST or place rockyou.txt at ~/wordlists/) - only the built-in common-password list will be tried\n", "magenta"))

    results = []
    for entry in data.get("results", [])[:number]:
        ident = keyword
        sources = entry.get("sources") or []
        tag = f" [{', '.join(sources)}]" if sources else ""
        password = entry.get("password")
        if password and password.strip():
            results.append(f"{ident}{tag}:{password}")
        elif entry.get("hash"):
            print(colored("[*] No plaintext in BreachDirectory's database for this record - attempting to crack the hash..", "yellow"))
            cracked = _crack_hash(entry["hash"], entry.get("hash_type", ""),
                                  entry.get("hash_salt") or "", wordlist)
            if cracked:
                results.append(f"{ident}{tag}:{cracked}")
            else:
                results.append(f"{ident}{tag} (hash):not cracked")
        else:
            results.append(f"{ident}{tag}:no password data returned")
    return results

def _scan_chunk(task):
    """Scan one byte range of a text database for keyword matches (worker)."""
    path, start, end, keyword, file_size = task
    keyword = keyword.lower().encode("utf-8", "ignore")

    with open(path, 'rb') as f:
        f.seek(start)
        data = f.read(end - start)

        # Read through the newline so a line straddling the chunk boundary
        # is completed here and owned exclusively by this chunk
        if end != file_size:
            data += f.readline()

    # Align chunk start to a line boundary (chunk 0 already starts on one)
    if start != 0:
        first_line = data.find(b"\n")
        if first_line == -1:
            return [] # chunk holds only the tail of a huge line, owned by the previous chunk
        data = data[first_line + 1:]

    matches = []
    for line in data.split(b"\n"):
        if keyword in line.lower():
            matches.append(line.decode("utf-8", "ignore").strip())
    return matches

_KEYCHAIN_CACHE = {}

def get_key(name):
    # Reads an API key from the macOS Keychain at call time (items stored
    # under the 'leaksearch' service name). The value is never printed,
    # logged, or written to disk.
    if name not in _KEYCHAIN_CACHE:
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-a", name, "-s", "leaksearch", "-w"],
                capture_output=True, text=True, timeout=10)
            _KEYCHAIN_CACHE[name] = result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            _KEYCHAIN_CACHE[name] = None
    return _KEYCHAIN_CACHE[name]

def key_missing(name):
    print(colored(f"[!] Keychain item '{name}' not found. Add it with:\n"
                  f"    security add-generic-password -a {name} -s leaksearch -w\n", "red"))


def find_leaks_local_db(database, keyword, number):
    if not os.path.exists(database):
        print(colored(f"[!] Local database file not found: {database}\n", "red"))
        exit(-1)

    if database.endswith('.json'):
        with open(database, 'r') as json_file:
            try:
                data = json.load(json_file)
                lines = data.get("lines", [])
            except json.JSONDecodeError:
                print(colored("[!] Error: Failed to parse local database as JSON\n", "red"))
                exit(-1)
        return lines[:number] if number is not None else lines

    file_size = os.path.getsize(database)
    if file_size == 0:
        return []
    results = []

    # Tune chunking and worker count to this machine's hardware
    cpu_count = os.cpu_count() or 1
    chunk_size = 64 * 1024 * 1024 # 64 MiB per task keeps overhead low
    tasks = [(database, offset, min(offset + chunk_size, file_size), keyword, file_size)
             for offset in range(0, file_size, chunk_size)]
    workers = min(cpu_count, len(tasks))

    executor = None
    try:
        if workers <= 1:
            # Small file: scan it in-process, no pool startup cost
            results = _scan_chunk(tasks[0])
        else:
            done_bytes = 0
            executor = ProcessPoolExecutor(max_workers=workers)
            for chunk_results in executor.map(_scan_chunk, tasks):
                done_bytes += chunk_size
                percent = min(done_bytes, file_size) * 100 // file_size
                print(colored(f"\r[*] Reading {file_size // 1048576} MiB in database.. {percent}%", "magenta"), end='', flush=True)
                results.extend(chunk_results)

                if number is not None and len(results) >= number:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
            else:
                executor.shutdown()

    except KeyboardInterrupt:
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        print(colored("\n[!] Exiting..\n", "red"))
        exit(-1)

    return results[:number] if number is not None else results

ONLINE_SOURCES = {
    'proxynova': find_leaks_proxynova,
    'breachdirectory': find_leaks_breachdirectory,
}

def main(database, keyword, output=None, proxy=None, number=20):
    keyword = keyword.strip()

    if database.lower() in ONLINE_SOURCES or database.lower() == 'all' or ',' in database:
        if database.lower() == 'all':
            sources = list(ONLINE_SOURCES)
        else:
            sources = [name.strip().lower() for name in database.split(',')]

        unknown = [name for name in sources if name not in ONLINE_SOURCES]
        if unknown:
            print(colored(f"[!] Unknown online source(s): {', '.join(unknown)}\n    Available: {', '.join(ONLINE_SOURCES)}\n", "red"))
            exit(-1)

        results = []
        for name in sources:
            print(colored(f"[>] Searching for {keyword} leaks in {name}..", "yellow"))
            try:
                results.extend(ONLINE_SOURCES[name](keyword, proxy, number))
            except Exception as e:
                print(colored(f"[!] Error searching {name}: {e}\n", "red"))

        if not results:
            print(colored(f"\n[!] No leaks found!\n", "red"))
        else:
            print_results(results, output, number)

    else:
        print(colored(f"[>] Searching for {keyword} leaks in {database}..", "yellow"))
        results = find_leaks_local_db(database.strip(), keyword, number)

        if not results:
            print(colored(f"\n[!] No leaks found in {database}!\n", "red"))
        else:
            print_results(results, output, number)

def print_results(results, output, number):
    print(colored(f"\n[-] Selecting the first {len(results)} results..", "blue"))
    # Split on the FIRST colon only: passwords may themselves contain ':'
    rows = []
    for line in results:
        ident, sep, password = line.partition(":")
        if not sep:
            continue
        email, bracket, sites = ident.partition(" [")
        rows.append([email.strip(), password, sites.rstrip("]") if bracket else ""])

    has_sites = any(row[2] for row in rows)
    if has_sites:
        headers = ["Username@Domain", "Password", "Breach Site(s)"]
        table_data = rows
    else:
        headers = ["Username@Domain", "Password"]
        table_data = [row[:2] for row in rows]

    if output is not None:
        extension = os.path.splitext(output)[1].lower()
        if extension == '.json':
            with open(output, 'w') as json_file:
                json.dump({"lines": results}, json_file, indent=2)
                print(colored(f"[+] Data saved successfully in {output}!\n", "green"))
        elif extension == '.csv':
            with open(output, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["email", "password", "breach_sites"])
                writer.writerows(rows)
                print(colored(f"[+] Data saved successfully in {output}!\n", "green"))
        else:
            with open(output, 'w') as txt_file:
                txt_file.write(tabulate(table_data, headers, showindex="never"))
                print(colored(f"[+] Data saved successfully in {output}!\n", "green"))
    else:
        print(colored("[+] Done!\n", "green"))
        print(tabulate(table_data, headers, showindex="never"))
        print()

if __name__ == '__main__':
    print(colored(banner, "blue"))
    print(colored(banner2, "green"))
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--database", default="proxynova", help="Online source (proxynova, breachdirectory) or local file")
    parser.add_argument("-k", "--keyword", help="Keyword (user/domain/pass) to search for leaks in the DB")
    parser.add_argument("-n", "--number", type=int, default=20, help="Number of results to show (default is 20)")
    parser.add_argument("-o", "--output", help="Save the results as csv, json or txt into a file")
    parser.add_argument("-p", "--proxy", help="Set HTTP/S proxy (like http://localhost:8080)")
    args = parser.parse_args()

    if not args.keyword:
        parser.print_help()
        exit(-1)

    try:
        main(args.database, args.keyword, args.output, args.proxy, args.number)

    except ConnectionError:
        print(colored("[!] Can't connect to service! Check your internet connection!\n", "red"))
    
    except KeyboardInterrupt:
        print (colored("\n[!] Exiting..\n", "red"))
        exit(-1)

    except Exception as e:
        print(colored(f"\n[!] Error: {e}\n", "red"))
      
