## hash-integrity-checker

**Email and File Security Made Simple**

During my experience as a Helpdesk Analyst with email admin roles and tasks in **MIMECAST email security**, I realized that email security is an essential safeguard for all industries.  
`hash-integrity-checker` is a minimal, free tool that leverages VirusTotal’s API to quickly validate whether files, directories, URLs, attachments, or `.eml` files are potentially malicious or tampered with.

---

## Features

- Generate **SHA256 hashes** for files.  
- Query **VirusTotal** to check if files or hashes are malicious.  
- Scan **single files**, **entire directories**, or **direct hashes**.  
- Output results in **JSON, CSV, or XLSX** formats.  
- Cross-platform support (**macOS, Linux, Windows**).  

---

## Installation

Step 1: You will need a **VirusTotal API key**. VirusTotal offers a free API key with a rate limit of **4 lookups per minute** and **500 queries per day**.  

Save your API key as an **environment variable** on your platform:

```bash
export VT_API_KEY="your_api_key_here"  # macOS/Linux
setx VT_API_KEY "your_api_key_here"    # Windows PowerShell
```
Step 2: Clone the Repository

```bash
git clone https://github.com/yourusername/hash-integrity-checker.git
cd hash-integrity-checker
```
Step 3: Set your VirusTotal API key (temporary or permanent):
- Temporary (Current Session Only)
  ```bash
  export VT_API_KEY="your_api_key_here"   # Linux/macOS
  setx VT_API_KEY "your_api_key_here"    # Windows PowerShell
    ```
- Permanent (add to ~/.bashrc or ~/.zshrc file using nano/vim #Linux/MacOS
  ```bash
  export VT_API_KEY="your_api_key_here"
  ```
Step 4: Reload
```bash
source ~/.bashrc
# or
source ~/.zshrc
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
