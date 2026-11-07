#!/usr/bin/env python3
"""Verify each Homebrew archive against the published release checksums."""
import argparse
import hashlib
from pathlib import Path
import re

PLATFORMS = ('darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+', args.version):
        parser.error('Version must be a stable numeric release')
    entries = {}
    for line in (args.artifacts / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64})\s+[* ]?(.+)', line)
        if not match:
            raise ValueError('Malformed SHA256SUMS entry')
        digest, filename = match.groups()
        if filename in entries:
            raise ValueError(f'Duplicate checksum for {filename}')
        entries[filename] = digest.lower()
    for platform in PLATFORMS:
        filename = f'voidb-{args.version}-{platform}.tar.gz'
        if filename not in entries:
            raise ValueError(f'Missing checksum for {filename}')
        digest = hashlib.sha256((args.artifacts / filename).read_bytes()).hexdigest()
        if digest != entries[filename]:
            raise ValueError(f'Checksum mismatch for {filename}')
        print(f'Verified {filename}')


if __name__ == '__main__':
    main()
