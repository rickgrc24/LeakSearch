<p align="center"><img width=550 alt="LeakSearch" src="https://github.com/JoelGMSec/LeakSearch/blob/main/LeakSearch.png"></p>

# LeakSearch
**LeakSearch** is a simple tool to search and parse plain text passwords using ProxyNova COMB (Combination Of Many Breaches) over the Internet. You can define a custom proxy and you can also use your own password file, to search using different keywords: such as user, domain or password. 

In addition, you can define how many results you want to display on the terminal and export them as JSON or TXT files. Due to the simplicity of the code, it is very easy to add new sources, so more providers will be added in the future.


# Requirements
- Python 3 
- Install requirements


# Download
It is recommended to clone the complete repository or download the zip file.
You can do this by running the following command:
```
git clone https://github.com/JoelGMSec/LeakSearch
```


# Usage
```
  _               _     ____                      _     
 | |    ___  __ _| | __/ ___|  ___  __ _ _ __ ___| |__  
 | |   / _ \/ _` | |/ /\___ \ / _ \/ _` | '__/ __| '_ \ 
 | |__|  __/ (_| |   <  ___) |  __/ (_| | | | (__| | | |
 |_____\___|\__,_|_|\_\|____/ \___|\__,_|_|  \___|_| |_|
                                               
  ------------------- by @JoelGMSec -------------------
  
usage: LeakSearch.py [-h] [-d DATABASE] [-k KEYWORD] [-n NUMBER] [-o OUTPUT] [-p PROXY]

options:
  -h, --help            show this help message and exit
  -d DATABASE, --database DATABASE
                        Online source (proxynova, breachdirectory) or a local
                        file (text or JSON) to scan
  -k KEYWORD, --keyword KEYWORD
                        Keyword (user/domain/pass) to search for leaks in the DB
  -n NUMBER, --number NUMBER
                        Number of results to show (default is 20)
  -o OUTPUT, --output OUTPUT
                        Save the results as json or txt into a file
  -p PROXY, --proxy PROXY
                        Set HTTP/S or SOCKS5 proxy (like http://localhost:8080)

```

### Results

Every result contains an email (or username) and an **uncensored password in
plaintext**. ProxyNova COMB records hold only the credential pair, so no
breach site name or leak date is available for them; local database files
return whatever columns the file itself contains. BreachDirectory results
include the breach site names in brackets (`user [Site1, Site2]:password`).

### BreachDirectory

BreachDirectory (via RapidAPI) is limited by its free plan to **10 requests
per month**; a 429 response means the quota is spent until it resets. When
their database knows the plaintext it is returned directly; otherwise the
API returns an MD5/SHA-1/SHA-256 hash (optionally salted) which LeakSearch
attempts to crack with a built-in common-password list plus an optional
wordlist (set `LEAKSEARCH_WORDLIST` or place rockyou.txt at
`~/wordlists/rockyou.txt`). Cracking is a dictionary attack, so hashes
outside the wordlist are reported as `not cracked`.

### Notes on removed sources

Other leak-search services were evaluated and removed because none of their
routes (web or API) return uncensored credentials without a paid
subscription: DeHashed, Leak-Lookup, IntelX, Snusbase, HIBP (counts only,
no credentials) and pwndb (its onion service is offline and its v2 address
is unsupported by current Tor). Optional API keys can be
stored in the macOS Keychain under the `leaksearch` service name and are
read at call time, never written to disk:

```
security add-generic-password -a <keyname> -s leaksearch -w '<value>'
```

### The detailed guide of use can be found at the following link:

https://darkbyte.net/buscando-y-filtrando-contrasenas-con-leaksearch


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
This tool has been created and designed from scratch by Joel Gámez Molina (@JoelGMSec).


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can find me on Twitter as [@JoelGMSec](https://twitter.com/JoelGMSec) and on my blog [darkbyte.net](https://darkbyte.net).


# Support
You can support my work buying me a coffee:

[<img width=250 alt="buymeacoffe" src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png">](https://www.buymeacoffee.com/joelgmsec)
