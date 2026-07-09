# System-Wide Malware Signature Scanner (`MalDetect.py`)

A high-performance endpoint scanning engine built natively in Python for Linux infrastructure auditing. The utility maps underlying directory branches recursively, processes data layers in memory-isolated binary chunks, and dynamically cross-references SHA-256 integrity maps against a standalone, modular threat-intelligence database file while defending against virtual kernel memory locks.

## Architectural & Technical Highlights
* **Virtual Kernel Filesystem Avoidance:** Implements explicit inline array pruning (`dirs[:]`) to cut off infinite directory looping inside kernel runtime memory architectures (`/proc`, `/sys`, `/dev`).
* **Symlink & Node Isolation:** Validates files explicitly via `os.path.islink` checks before generation, neutralizing system traps, named pipes, and circular socket pathways.
* **Buffered Chunk-Streaming:** Reads system files in 4KB allocations to shield systems from low-memory crashes when confronting immense archival payloads.
* **Constant-Time Dictionary Lookups:** Parses external database entries into local memory hashes to achieve pure O(1) matching efficiency bounds.

## File Structure
* `MalDetect.py` — Core endpoint scanner engine, data streaming pipeline, and database manager.
* `malware_signatures.db` — Flat-file storage array hosting malicious data integrity fingerprints.
* `LICENSE` — Open-source project governance via the permissive MIT License.

## Getting Started

### Prerequisites
Tested and optimized for **Fedora 44**. Update your Python 3 dependencies natively through DNF5:

```bash
# Verify system repositories and prepare application dependencies
sudo dnf5 check-update
sudo dnf5 install python3
```

### Installation
Clone this repository to your local workspace engineering directory:

```bash
git clone https://github.com
cd MalDetect
```

### Execution
Run the system scanner by pointing the engine argument to any desired system tree destination path using root privileges:

```bash
# Execute signature scan on the local path directory
python3 MalDetect.py .

# Execute global signature scan across the entire operating system root
sudo python3 MalDetect.py /
```

## Example System Output

```text
[+] Launching Global System Security Audit on target branch: /
[+] Active Threat Definitions Operational: 1
[-] Scanning infrastructure branches (This process takes time depending on disk size)...
-----------------------------------------------------------------
[ALERT] SYSTEM THREAT EXPOSED: /var/tmp/eicar_test.txt
        Calculated Fingerprint: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
        Threat Vector Classification: EICAR_Standard_Test_File

-----------------------------------------------------------------
[✓] System Audit Concluded at 2026-07-09 15:15:00
    Total Operational Objects Scanned: 225000
    Active Vectors Isolated: 1
```

## AI Assistance & Methodology
This tool was built using an AI-assisted development workflow. I outlined the external database lookup architecture, structured the file parsing targets, and verified runtime validation tests on Fedora 44. I then collaborated with AI models to write the chunked `hashlib` parsing blocks and format file-exception loops.

## License
This project is open-source software licensed under the MIT License.

## Contact
Datavis Battles — hadirshuja@gmail.com
Project Repository: https://github.com/JaquanteStacks/MalDetect
