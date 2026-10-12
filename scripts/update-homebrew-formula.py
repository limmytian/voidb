#!/usr/bin/env python3
"""Render formula URLs/checksums only after all four core-only Unix archives exist."""
import argparse
import hashlib
from pathlib import Path
import re
import tarfile

PLATFORMS = ('darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--formula', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+', args.version):
        parser.error('Version must be a stable numeric release')
    checksums = {}
    for platform in PLATFORMS:
        archive = args.artifacts / f'voidb-{args.version}-{platform}.tar.gz'
        with tarfile.open(archive) as package:
            members = package.getmembers()
            if len(members) != 2 or {member.name for member in members} != {'voidb', 'voidb-cli'} or not all(member.isfile() for member in members):
                raise ValueError(f'{archive.name} must contain only the two regular core binaries')
        checksums[platform] = hashlib.sha256(archive.read_bytes()).hexdigest()
    formula = args.formula.read_text()
    formula, count = re.subn(r'  version "[^"]+"', f'  version "{args.version}"', formula)
    if count != 1:
        raise ValueError('Formula must have exactly one version')
    for platform, digest in checksums.items():
        pattern = rf'url "[^"]+/voidb-[^/]+-{platform}\.tar\.gz"\n(\s+)sha256 "[^"]+"'
        replacement = rf'url "https://github.com/limmytian/voidb/releases/download/v{args.version}/voidb-{args.version}-{platform}.tar.gz"\n\1sha256 "{digest}"'
        formula, count = re.subn(pattern, replacement, formula)
        if count != 1:
            raise ValueError(f'Formula must have exactly one archive for {platform}')
    if 'pkgshare' in formula or 'bin.install "voidb-cli"' not in formula:
        raise ValueError('Formula must install only the core binaries')
    args.output.write_text(formula)
    print(f'Rendered verified v{args.version} formula: {args.output}')


if __name__ == '__main__':
    main()
