#!/usr/bin/env python3
import os
import re

LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))
AIRODUMP_CSV = os.path.join(LOCAL_DIR, "airodump.csv")
OUTPUT_CSV = os.path.join(LOCAL_DIR, "macextracted.csv")
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

def mac_type(mac):
    first_byte = int(mac.split(":")[0], 16)
    return "RANDOM-MAC" if (first_byte & 0b10) else "CONST-MAC"

def load_existing_macs():
    if not os.path.exists(OUTPUT_CSV):
        return set()
    existing = set()
    with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                mac = line[:17].upper()
                existing.add(mac)
    return existing

def extract_macs():
    if not os.path.exists(AIRODUMP_CSV):
        return []

    clients = []
    reading_clients = False

    with open(AIRODUMP_CSV, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = [p.strip() for p in line.split(",")]

            if parts[0].startswith("Station MAC"):
                reading_clients = True
                continue
            if parts[0].startswith("BSSID") and reading_clients:
                break

            if reading_clients and len(parts) >= 1 and MAC_REGEX.match(parts[0]):
                clients.append(parts[0].upper())

    return clients

def main():
    existing_macs = load_existing_macs()
    new_macs = []

    for mac in extract_macs():
        if mac not in existing_macs:
            new_macs.append(f"{mac} : {mac_type(mac)}")
            existing_macs.add(mac)

    if new_macs:
        with open(OUTPUT_CSV, "a", encoding="utf-8") as f:
            for line in new_macs:
                f.write(line + "\n")

if __name__ == "__main__":
    main()
