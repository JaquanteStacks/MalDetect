#!/usr/bin/env python3
"""
System-Wide Host-Based Malware Signature Scanner
Recursively audits entire Linux filesystems while defending against virtual memory locks.
"""

import os
import hashlib
import sys
from datetime import datetime

# Looks for the database file in the exact same folder as the script
SIGNATURE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "malware_signatures.db")

# Exclude virtual filesystems, device streams, and dynamic kernel maps
SYSTEM_EXCLUDE_DIRS = {
    "/proc",     # Dynamic kernel process tracking metrics
    "/sys",      # Live hardware and driver interface configurations
    "/dev",      # Device nodes (Prevents infinite reading on character streams)
    "/run",      # Transient runtime data maps
    "/mnt",      # Avoids scanning accidentally mounted external network storage loops
    "/media",    # Excludes removable physical media loops during system root scans
    ".snapshots" # Skips Btrfs snapshot loops to prevent processing identical twins
}

def check_privileges():
    """System-wide scans require root administrative privileges to bypass file permissions."""
    if os.geteuid() != 0:
        print("[!] CRITICAL: System-wide analysis requires root administrative authority.")
        print("    Execute via: sudo python3 MalDetect.py /\n")
        sys.exit(1)

def load_signatures(db_path):
    """Loads signature dataset securely; creates baseline tracking path if missing."""
    signatures = {}
    if not os.path.exists(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        # Seed default verification database using the global EICAR standard fingerprint
        with open(db_path, "w") as f:
            f.write("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:EICAR_Standard_Test_File\n")
        signatures["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"] = "EICAR_Standard_Test_File"
        return signatures

    try:
        with open(db_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and ":" in line:
                    hash_val, threat_name = line.split(":", 1)
                    signatures[hash_val.lower().strip()] = threat_name.strip()
    except Exception as e:
        print(f"[X] Database read failure: {e}")
    return signatures

def calculate_sha256(file_path):
    """Streams data blocks in isolated 4KB binary pools to maintain strict O(1) memory boundaries."""
    sha256_hash = hashlib.sha256()
    try:
        # Check if it is a standard file; explicitly avoid symlinks, named pipes, and socket files
        if not os.path.islink(file_path) and os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        # Gracefully drop system locks, locked sockets, or disappearing temporary records
        return None
    return None

def scan_system(root_target, signatures):
    """Orchestrates recursive filesystem tree walks over entire operating system branches."""
    abs_target = os.path.abspath(root_target)
    print(f"[+] Launching Global System Security Audit on target branch: {abs_target}")
    print(f"[+] Active Threat Definitions Operational: {len(signatures)}")
    print("[-] Scanning infrastructure branches (This process takes time depending on disk size)...")
    print("-----------------------------------------------------------------")
    
    files_scanned = 0
    threats_detected = 0

    for root, dirs, files in os.walk(abs_target, topdown=True):
        # Defensive Filtering: Modifies 'dirs' in-place to prevent os.walk from entering excluded spaces
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in SYSTEM_EXCLUDE_DIRS]
        
        # Double check if current base directory itself resides in an excluded path
        if root in SYSTEM_EXCLUDE_DIRS:
            continue

        for file in files:
            files_scanned += 1
            full_path = os.path.join(root, file)
            
            # Diagnostic telemetry notification interval to show system activity
            if files_scanned % 25000 == 0:
                print(f"[*] Audit Progress: Verified {files_scanned} system assets...")

            file_hash = calculate_sha256(full_path)
            
            if file_hash and file_hash in signatures:
                threat_name = signatures[file_hash]
                threats_detected += 1
                print(f"\n\033[91m[ALERT] SYSTEM THREAT EXPOSED: {full_path}\033[0m")
                print(f"        Calculated Fingerprint: {file_hash}")
                print(f"        Threat Vector Classification: {threat_name}\n")

    print("-----------------------------------------------------------------")
    print(f"[✓] System Audit Concluded at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"    Total Operational Objects Scanned: {files_scanned}")
    print(f"    Active Vectors Isolated: {threats_detected}")

def main():
    check_privileges()
    target = sys.argv[1] if len(sys.argv) > 1 else "/"
    
    if not os.path.isdir(target):
        print(f"[X] Operational Error: Targeted root element '{target}' is invalid.")
        sys.exit(1)
        
    signatures = load_signatures(SIGNATURE_DB_PATH)
    scan_system(target, signatures)

if __name__ == "__main__":
    main()