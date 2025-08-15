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
    "API_KEY_1",
    "API_KEY_2",
    "API_KEY_3"
]
API_KEY_CYCLE = cycle(API_KEYS)  # Round robin iterator

API_URL = "https://www.virustotal.com/api/v3/files/"
API_DELAY = 16  # Free API limit: 4 requests/minute per key

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

# Load already saved worm hashes so we can append instead of overwrite
worm_hashes = set()
if os.path.exists(WORM_HASHES_FILE):
    with open(WORM_HASHES_FILE, "r") as f:
        worm_hashes.update(line.strip() for line in f if line.strip())

# Load per-family hash files
family_hashes = {family: set() for family in worm_aliases}
for family in worm_aliases:
    family_file = os.path.join(BASE_DIR, f"{family.replace(' ', '_')}_hashes.txt")
    if os.path.exists(family_file):
        with open(family_file, "r") as f:
            family_hashes[family].update(line.strip() for line in f if line.strip())

# -------------------
# VIRUSTOTAL LOOKUP
# -------------------
def is_worm(md5_hash):
    if md5_hash in cache:
        result = cache[md5_hash]
        print(f"[CACHE] {md5_hash} → {result['is_worm']} ({len(result['detections'])} detections)")
        return result["is_worm"], result.get("family")

    # Get the next API key in the round robin
    current_api_key = next(API_KEY_CYCLE)

    print(f"[VT QUERY] Using API key ending with ...{current_api_key[-4:]}")
    print(f"[VT QUERY] Waiting {API_DELAY}s before querying VirusTotal...")
    time.sleep(API_DELAY)

    headers = {"x-apikey": current_api_key}
    response = requests.get(API_URL + md5_hash, headers=headers)

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

        # Match worm family aliases
        for family, aliases in worm_aliases.items():
            if any(any(alias in d.lower() for alias in aliases) for d in detections):
                is_worm_flag = True
                family_detected = family
                break

        # Generic worm detection
        if not is_worm_flag:
            worm_vendors = sum(
                1 for d in detections if any(keyword in d.lower() for keyword in generic_worm_keywords)
            )
            is_worm_flag = worm_vendors >= 3

    elif response.status_code == 404:
        print(f"[!] Hash {md5_hash} not found in VirusTotal.")
    else:
        print(f"[!] Error {response.status_code} for hash {md5_hash}")

    # Cache result
    cache[md5_hash] = {
        "is_worm": is_worm_flag,
        "detections": detections,
        "family": family_detected
    }

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

    for file in os.listdir(HASH_LIST_DIR):
        path = os.path.join(HASH_LIST_DIR, file)
        if os.path.isfile(path) and file.lower().endswith(".txt"):
            print(f"[+] Processing file: {path}")
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    md5_hash = line.strip().lower()
                    if len(md5_hash) == 32 and md5_hash.isalnum():
                        if md5_hash in worm_hashes:
                            print(f"[SKIP] Already saved worm hash: {md5_hash}")
                            continue
                        print(f"[+] Checking hash: {md5_hash}")
                        is_worm_flag, family_detected = is_worm(md5_hash)
                        if is_worm_flag:
                            worm_hashes.add(md5_hash)
                            print(f"[+] Worm found: {md5_hash}")
                            if family_detected:
                                family_hashes[family_detected].add(md5_hash)
                                print(f"    → Family: {family_detected}")
                        else:
                            print(f"[-] Not a worm: {md5_hash}")

    # Save cache
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

    # Append new worm hashes
    with open(WORM_HASHES_FILE, "w") as f:
        for h in sorted(worm_hashes):
            f.write(h + "\n")

    # Append per-family hashes
    for family, hashes in family_hashes.items():
        if hashes:
            family_file = os.path.join(BASE_DIR, f"{family.replace(' ', '_')}_hashes.txt")
            with open(family_file, "w") as f:
                for h in sorted(hashes):
                    f.write(h + "\n")
            print(f"[✓] {family.title()} hashes saved to: {family_file}")

    print(f"\n[✓] Finished! Found {len(worm_hashes)} total worm hashes.")
    for family, hashes in family_hashes.items():
        print(f"    {family.title()}: {len(hashes)}")

if __name__ == "__main__":
    process_hash_lists()
