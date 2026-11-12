#!/usr/bin/env python3
"""Downloads the blocklists and writes assets/blocklist.bin: sorted, unique, big-endian signed
64-bit FNV-1a hashes of every blocked domain. The app blocks a name if it or any parent matches."""
import os, struct, sys, urllib.request

LISTS = {
    "ads+trackers (HaGeZi Pro)": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "porn (HaGeZi NSFW)": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
    "porn (OISD NSFW)": "https://nsfw.oisd.nl/domainswild2",
    "DNS bypass servers (HaGeZi DoH)": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt",
}

def fnv1a64(s):
    h = 0xcbf29ce484222325
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h - (1 << 64) if h >= (1 << 63) else h  # signed, to match Java's long ordering

def main(out_path):
    hashes = set()
    for name, url in LISTS.items():
        req = urllib.request.Request(url, headers={"User-Agent": "cleanshield-build"})
        text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
        n = 0
        for line in text.splitlines():
            d = line.strip().lower()
            if not d or d.startswith("#") or d.startswith("!"):
                continue
            d = d.lstrip("*.").rstrip(".")
            if "." not in d or " " in d:
                continue
            hashes.add(fnv1a64(d))
            n += 1
        print(f"  {name}: {n} domains")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        for h in sorted(hashes):
            f.write(struct.pack(">q", h))
    print(f"  total unique: {len(hashes)} -> {out_path}")

if __name__ == "__main__":
    main(sys.argv[1])
