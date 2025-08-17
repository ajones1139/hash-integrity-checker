import os
import platform
import hashlib
import requests
import argparse
import json
import pandas as pd

# ---Configuration---
VT_API_KEY = os.getenv('VT_API_KEY')
VT_URL = 'https://www.virustotal.com/api/v3/files/'
# ---End Configuration---

# ---OS Detection---
def detect_os():
    return platform.system().lower()

# ---File Hashing---
def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
# ---End File Hashing---

def query_virustotal(file_hash):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(VT_URL + file_hash, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
        harmless_count = data['data']['attributes']['last_analysis_stats']['harmless']
        return {
            "hash": file_hash,
            "malicious": malicious_count,
            "harmless": harmless_count,
            "permalink": data['data']['links']['self']
        }
    elif response.status_code == 404:
        return {"hash": file_hash, "error": "Hash not found in VirusTotal database"}
    else:
        return {"hash": file_hash, "error": f"Unexpected error {response.status_code}"}

# ---Main---
def main():
    parser = argparse.ArgumentParser(description="Check file hashes against VirusTotal.")
    parser.add_argument("file", help="Path to the file to check")
    parser.add_argument("--output", "-o", help="Save results to file (no extension)", default=None)
    parser.add_argument("--format", "-f", choices=["json", "csv", "xlsx"], help="Output format", default=None)
    args = parser.parse_args()

    file_path = args.file
    file_hash = hash_file(file_path)
    result = query_virustotal(file_hash)

    # Always print to console
    print(result)

    # Optionally save
    if args.output and args.format:
        if args.format == "json":
            with open(f"{args.output}.json", "w") as f:
                json.dump(result, f, indent=4)
        elif args.format == "csv":
            pd.DataFrame([result]).to_csv(f"{args.output}.csv", index=False)
        elif args.format == "xlsx":
            pd.DataFrame([result]).to_excel(f"{args.output}.xlsx", index=False)

if __name__ == "__main__":
    main()
