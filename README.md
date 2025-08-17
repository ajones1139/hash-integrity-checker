# hash-integrity-checker

**Email and File Security Made Simple**

Email security is a critical vector in cybersecurity, with millions of users encountering phishing attempts and scams every day.  
`hash-integrity-checker` is a minimal, free tool that leverages VirusTotal’s free API to quickly validate whether files, directories, URLs, attachments, or `.eml` files are potentially malicious or tampered with.

---

## Features

- Generate **SHA256 hashes** for files.  
- Query **VirusTotal** to check if files or hashes are malicious.  
- Scan **single files**, **entire directories**, or **direct hashes**.  
- Output results in **JSON, CSV, or XLSX** formats.  
- Cross-platform support (**macOS, Linux, Windows**).  

---

## Installation

You will need a **VirusTotal API key**. VirusTotal offers a free API key with a rate limit of **4 lookups per minute** and **500 queries per day**.  

Save your API key as an **environment variable** on your platform:

```bash
export VT_API_KEY="your_api_key_here"  # macOS/Linux
setx VT_API_KEY "your_api_key_here"    # Windows PowerShell
```

## Usage
Check a single file:\
`python hash_integrity.py --file suspicious.exe`

Check a file and save as JSON file:\
`python hash_integrity.py --file suspicious.exe --output results --format json`

Scan a directory:\
`python hash_integrity.py --file ./downloads --output scan_results --format xlsx`

Detect your OS:\
`python hash_integrity.py --os`

Help Menu:\
`python hash_integrity.py -h`

# Example Output
```{
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "malicious": 0,
    "harmless": 70,
    "permalink": "https://www.virustotal.com/gui/file/d41d8cd98f00b204e9800998ecf8427e"
}
```
