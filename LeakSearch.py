#!/usr/bin/python3
#============================#
#  LeakSearch by @JoelGMSec  #
#    https://darkbyte.net    #
#============================#

import os
import json
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
    # (limit maxes at 100 per request; results are paged via start).
    session = requests.session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    headers = {'User-Agent': 'curl'}
    lines, start = [], 0
    total_results = None
    while len(lines) < number:
        limit = min(number - len(lines), 100)
        url = f"https://api.proxynova.com/comb?query={email}&start={start}&limit={limit}"
        response = session.get(url, headers=headers, verify=False)
        if response.status_code != 200:
            if start == 0:
                print(colored(f"[!] Failed to fetch results from ProxyNova. Status code: {response.status_code}\n", "red"))
            break
        data = response.json()
        if total_results is None:
            total_results = data.get("count", 0)
            print(colored(f"[*] Found {total_results} different records in database", "magenta"), end='')
        page_lines = data.get("lines", [])
        if not page_lines:
            break
        lines.extend(page_lines)
        start += len(page_lines)
    return lines[:number]

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
    headers = ["Username@Domain", "Password"]
    table_data = []

    for line in results:
        parts = line.split(":")
        if len(parts) == 2:
            username_domain, password = parts
            table_data.append([username_domain, password])

    if output is not None:
        if output.endswith('.json'):
            with open(output, 'w') as json_file:
                json.dump({"lines": results}, json_file, indent=2)
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
    parser.add_argument("-d", "--database", default="proxynova", help="Online source (proxynova) or local file")
    parser.add_argument("-k", "--keyword", help="Keyword (user/domain/pass) to search for leaks in the DB")
    parser.add_argument("-n", "--number", type=int, default=20, help="Number of results to show (default is 20)")
    parser.add_argument("-o", "--output", help="Save the results as json or txt into a file")
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
      
