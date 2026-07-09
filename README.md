# Host-Based Malware Signature Scanner (`MalDetect.py`)

A high-efficiency, lightweight endpoint detection utility written in Python. This security tool walks local file systems recursively, computes deterministic SHA-256 cryptographic fingerprints, and contrasts data integrity maps against a hash-backed database of known malicious threat vectors.

## Architectural & Technical Highlights
* **Memory-Safe Buffered Streaming:** Streams files in standardized `4096-byte` chunks via binary-read allocations (`rb`). This keeps a strict O(1) memory bound, neutralizing memory-exhaustion panics when confronting large file payloads.
* **Algorithmic Search Complexity:** Maps target malware definition matrices inside a key-value hash dictionary to guarantee O(1) constant-time signature evaluation lookup speed.
* **Fault-Tolerant Traversal:** Leverages Python's low-level `os.walk` file system engine with localized exception traps to cleanly pass restricted or locked administrative directories.
* **Native Shell Visualization:** Generates color-coded shell warning outputs using standard ANSI escape configurations supported natively by the Fedora terminal subsystem.

## File Structure
* `MalDetect.py` — Core cryptographic parsing engine, file tracker, and alert dispatcher.
* `LICENSE` — Open-source project governance via the permissive MIT License.

## Getting Started

### Prerequisites
Tested and optimized for **Fedora 44**. Ensure your environment contains a running deployment of Python 3:

```bash
# Verify Python runtime installation and status via DNF5
sudo dnf5 check-update
sudo dnf5 install python3
```

### Installation
Clone this repository to your local endpoint manager directory:

```bash
git clone https://github.com/JaquanteStacks/MalDetect
cd MalDetect
```

### Execution
Run the signature auditor via the command line interface, passing a destination directory target parameter:

```bash
# Audit the current directory path
python3 MalDetect.py .

# Audit a customized system directory tree
python3 MalDetect.py /path/to/target_directory
```

## Example System Output

```text
[+] Starting signature scan in target directory: /home/user/downloads
-----------------------------------------------------------------
[ALERT] MATCH FOUND: /home/user/downloads/test_payload.exe
        SHA-256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
        Classification: Ransomware.Mock.Test

-----------------------------------------------------------------
[✓] Scan Complete at 2026-07-09 14:15:00
    Files Audited: 142
    Threats Blocked: 1
```

## AI Assistance & Methodology
This tool was built using an AI-assisted development workflow. I designed the signature checking workflow parameters, directed the filesystem traversal criteria, and confirmed execution boundaries within Fedora 44. I then collaborated with AI models to design the chunked file-streaming framework and clean up CLI runtime arguments.

## License
This project is open-source software licensed under the MIT License.

## Contact
Datavis Battles — hadirshuja@gmail.com
Project Repository: https://github.com/JaquanteStacks/MalDetect

