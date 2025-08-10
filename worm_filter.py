import os
import time
import json
import requests

# -------------------
# CONFIGURATION
# -------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_LIST_DIR = os.path.join(BASE_DIR, "VirusShare_Hashes")
CACHE_FILE = os.path.join(BASE_DIR, "vt_cache.json")
WORM_HASHES_FILE = os.path.join(BASE_DIR, "worm_hashes.txt")
API_KEY = ""
API_URL = "https://www.virustotal.com/api/v3/files/"

API_DELAY = 0  # seconds (free API key limit: 4 requests/minute)

# -------------------
# LOAD CACHE
# -------------------
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        cache = json.load(f)
else:
    print(f"[!] No cache file found at: {CACHE_FILE}. Starting fresh.")
    cache = {}

worm_hashes = set()

# -------------------
# VIRUSTOTAL LOOKUP
# -------------------
def is_worm(md5_hash):
    if md5_hash in cache:
        return cache[md5_hash]["is_worm"]

    headers = {"x-apikey": API_KEY}
    response = requests.get(API_URL + md5_hash, headers=headers)

    detections = []
    is_worm_flag = False

    if response.status_code == 200:
        data = response.json()

        try:
            analysis_results = data["data"]["attributes"]["last_analysis_results"]
            for vendor, result in analysis_results.items():
                if result["category"] == "malicious" and result["result"]:
                    detections.append(result["result"])
        except KeyError:
            pass

        # Count vendors whose detection name contains "worm"
        worm_vendors = sum(1 for d in detections if "worm" in d.lower())
        is_worm_flag = worm_vendors >= 3

    elif response.status_code == 404:
        print(f"[!] Hash {md5_hash} not found in VirusTotal.")
    else:
        print(f"[!] Error {response.status_code} for hash {md5_hash}")

    cache[md5_hash] = {
        "is_worm": is_worm_flag,
        "detections": detections
    }
    return is_worm_flag

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
                        print(f"[+] Checking hash: {md5_hash}")
                        if is_worm(md5_hash):
                            worm_hashes.add(md5_hash)
                            print(f"[+] Worm found: {md5_hash}")
                        else:
                            print(f"[-] Not a worm: {md5_hash}")
                        time.sleep(API_DELAY)

    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

    with open(WORM_HASHES_FILE, "w") as f:
        for h in sorted(worm_hashes):
            f.write(h + "\n")

    print(f"\n[✓] Finished! Found {len(worm_hashes)} worm hashes.")
    print(f"[✓] Worm hashes saved to: {WORM_HASHES_FILE}")
    print(f"[✓] Cache saved to: {CACHE_FILE}")

if __name__ == "__main__":
    process_hash_lists()
