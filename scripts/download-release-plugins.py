#!/usr/bin/env python3
"""Stage verified official plugin release archives for packaging and indexing."""
import argparse
import hashlib
import importlib.util
import pathlib
import subprocess
import tarfile
import tempfile
import shutil

DEFAULT = ('mysql', 'postgres', 'sqlite', 'redis', 'ssh', 'duckdb')
ALL = DEFAULT + ('docker', 'kubernetes', 's3', 'elasticsearch', 'mongodb', 'jenkins', 'webdav', 'email')
TARGETS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-apple-darwin')


def stage(version, target, plugin, output, allow_legacy_unsigned=False, openssl="openssl"):
    filename = f'{plugin}-{version}-{target}.tar.gz'
    download = output / '.downloads' / plugin / target
    download.mkdir(parents=True, exist_ok=True)
    subprocess.run(['gh', 'release', 'download', f'v{version}', '--repo', f'limmytian/voidb-plugin-{plugin}',
                    '--pattern', filename, '--pattern', 'SHA256SUMS', '--dir', str(download), '--clobber'], check=True)
    checksums = [line.split()[0] for line in (download / 'SHA256SUMS').read_text().splitlines()
                 if len(line.split()) == 2 and line.split()[1].lstrip('*') == filename]
    if len(checksums) != 1:
        raise ValueError(f'Missing or ambiguous checksum: {filename}')
    archive = download / filename
    digest = hashlib.sha256()
    with archive.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != checksums[0]:
        raise ValueError(f'Checksum mismatch: {filename}')
    destination = output / target / 'plugins' / plugin
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='voidb-stage-', dir=destination.parent) as temporary:
        staged = pathlib.Path(temporary) / plugin
        staged.mkdir()
        with tarfile.open(archive) as package:
            for member in package.getmembers():
                path = pathlib.PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or '\\' in member.name or ':' in member.name or not (member.isfile() or member.isdir()):
                    raise ValueError(f'Unsafe archive member: {member.name}')
            package.extractall(staged)
        if not (staged / 'plugin.toml').is_file() or not (staged / 'bin' / f'voidb-plugin-{plugin}').is_file():
            raise ValueError(f'Incomplete archive: {filename}')
        if (staged / 'provenance.json').exists():
            spec = importlib.util.spec_from_file_location('verify_release', pathlib.Path(__file__).with_name('verify-plugin-provenance.py'))
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            verifier.verify(staged, target, plugin, version, openssl)
        elif not allow_legacy_unsigned or tuple(map(int, version.split('.'))) >= (0, 3, 4):
            raise ValueError('Missing authenticated release provenance; unsigned legacy staging requires explicit opt-in')
        if destination.exists():
            shutil.rmtree(destination)
        staged.rename(destination)
    print(f'Checksum and source policy verified {filename}: {digest.hexdigest()}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--target', choices=TARGETS)
    parser.add_argument('--all', action='store_true', help='Download all 14 plugins on all four targets.')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--allow-legacy-unsigned-staging', action='store_true', help='Inspect old immutable unsigned archives; this does not authorize execution.')
    parser.add_argument('--openssl', default='openssl')
    args = parser.parse_args()
    if not args.all and not args.target:
        parser.error('--target is required unless --all is supplied')
    for target in TARGETS if args.all else (args.target,):
        for plugin in ALL if args.all else DEFAULT:
            stage(args.version.removeprefix('v'), target, plugin, args.output, args.allow_legacy_unsigned_staging, args.openssl)


if __name__ == '__main__':
    main()
