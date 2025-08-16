import os
import time
import json
import requests
from itertools import cycle

# -------------------
# CONFIGURATION
# -------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_LIST_DIR = os.path.join(BASE_DIR, "VirusShare_Hashes")
CACHE_FILE = os.path.join(BASE_DIR, "vt_cache.json")
WORM_HASHES_FILE = os.path.join(BASE_DIR, "worm_hashes.txt")

# Add all your VT API keys here
API_KEYS = [
    "",
    "",
    ""
]
API_KEY_CYCLE = cycle(API_KEYS)  # Round robin iterator

API_URL = "https://www.virustotal.com/api/v3/files/"
API_DELAY = 6  # Free API limit: 4 requests/minute per key

worm_aliases = {
    "bagle": ["bagle", "beagle", "bagel"],
    "conficker": ["conficker", "kido", "downadup"],
    "blaster": ["blaster", "msblast", "lovsan", "poza"],
    "sasser": ["sasser"],
    "code red": ["codered", "iisworm", "code red"]
}

# -------------------
# LOAD CACHE
# -------------------
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        cache = json.load(f)
    print(f"[CACHE] Loaded {len(cache)} entries from cache.")
else:
    print(f"[!] No cache file found at: {CACHE_FILE}. Starting fresh.")
    cache = {}

worm_hashes = set()
if os.path.exists(WORM_HASHES_FILE):
    with open(WORM_HASHES_FILE, "r") as f:
        worm_hashes.update(line.strip() for line in f if line.strip())

family_hashes = {family: set() for family in worm_aliases}
for family in worm_aliases:
    family_file = os.path.join(BASE_DIR, f"{family.replace(' ', '_')}_hashes.txt")
    if os.path.exists(family_file):
        with open(family_file, "r") as f:
            family_hashes[family].update(line.strip() for line in f if line.strip())

# -------------------
# SAVE IMMEDIATELY
# -------------------
def save_cache():
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def save_worm_hash(hash_value):
    with open(WORM_HASHES_FILE, "a") as f:
        f.write(hash_value + "\n")

def save_family_hash(family, hash_value):
    family_file = os.path.join(BASE_DIR, f"{family.replace(' ', '_')}_hashes.txt")
    with open(family_file, "a") as f:
        f.write(hash_value + "\n")

# -------------------
# VIRUSTOTAL LOOKUP
# -------------------
def is_worm(md5_hash):
    if md5_hash in cache:
        result = cache[md5_hash]
        print(f"[CACHE] {md5_hash} → {result['is_worm']} ({len(result['detections'])} detections)")
        return result["is_worm"], result.get("family")

    current_api_key = next(API_KEY_CYCLE)
    print(f"[VT QUERY] Using API key ending with ...{current_api_key[-4:]}")
    print(f"[VT QUERY] Waiting {API_DELAY}s before querying VirusTotal...")
    time.sleep(API_DELAY)

    headers = {"x-apikey": current_api_key}

    while True:  # Keep retrying if we hit rate limit
        response = requests.get(API_URL + md5_hash, headers=headers)

        if response.status_code == 429:
            print("[!] Rate limit hit (429). Waiting 1 hour before retrying...")
            time.sleep(3600)  # 1 hour wait
            continue  # retry same request
        break  # Exit loop if no 429

    detections = []
    is_worm_flag = False
    family_detected = None

    generic_worm_keywords = ["worm"]

    if response.status_code == 200:
        data = response.json()
        try:
            analysis_results = data["data"]["attributes"]["last_analysis_results"]
            for vendor, result in analysis_results.items():
                if result["category"] == "malicious" and result["result"]:
                    detections.append(result["result"])
        except KeyError:
            pass

        for family, aliases in worm_aliases.items():
            if any(any(alias in d.lower() for alias in aliases) for d in detections):
                is_worm_flag = True
                family_detected = family
                break

        if not is_worm_flag:
            worm_vendors = sum(
                1 for d in detections if any(keyword in d.lower() for keyword in generic_worm_keywords)
            )
            is_worm_flag = worm_vendors >= 3

    elif response.status_code == 404:
        print(f"[!] Hash {md5_hash} not found in VirusTotal.")
    else:
        print(f"[!] Error {response.status_code} for hash {md5_hash}")

    cache[md5_hash] = {
        "is_worm": is_worm_flag,
        "detections": detections,
        "family": family_detected
    }
    save_cache()

    return is_worm_flag, family_detected

# -------------------
# PROCESS HASH LISTS
# -------------------
def process_hash_lists():
    if not os.path.exists(HASH_LIST_DIR):
        os.makedirs(HASH_LIST_DIR)
        print(f"[!] No 'VirusShare_Hashes' folder found. Created it at: {HASH_LIST_DIR}")
        print("[!] Please put your VirusShare hash list text files inside this folder.")
        return

    checked_count = 0
    max_checks = 1500

    for file in os.listdir(HASH_LIST_DIR):
        path = os.path.join(HASH_LIST_DIR, file)
        if os.path.isfile(path) and file.lower().endswith(".txt"):
            print(f"[+] Processing file: {path}")
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    if checked_count >= max_checks:
                        print(f"[!] Reached {max_checks} hash limit for this run.")
                        return

                    md5_hash = line.strip().lower()
                    if len(md5_hash) == 32 and md5_hash.isalnum():
                        
                        if md5_hash in worm_hashes:
                            print(f"[SKIP] Already saved worm hash: {md5_hash}")
                            continue
                        
                        if md5_hash in cache:
                            cached_data = cache[md5_hash]
                            print(f"[CACHE] Skipped cached hash: {md5_hash}")
                            if cached_data["is_worm"]:
                                worm_hashes.add(md5_hash)
                                save_worm_hash(md5_hash)
                                if cached_data.get("family"):
                                    family_hashes[cached_data["family"]].add(md5_hash)
                                    save_family_hash(cached_data["family"], md5_hash)
                            continue
                        
                        print(f"[+] Checking hash: {md5_hash}")
                        is_worm_flag, family_detected = is_worm(md5_hash)
                        checked_count += 1
                        print(checked_count, "hashes checked so far...")
                        if is_worm_flag:
                            worm_hashes.add(md5_hash)
                            save_worm_hash(md5_hash)
                            print(f"[+] Worm found: {md5_hash}")
                            if family_detected:
                                family_hashes[family_detected].add(md5_hash)
                                save_family_hash(family_detected, md5_hash)
                                print(f"    → Family: {family_detected}")
                        else:
                            print(f"[-] Not a worm: {md5_hash}")

if __name__ == "__main__":
    process_hash_lists()
