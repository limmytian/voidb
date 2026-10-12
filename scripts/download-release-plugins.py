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
import time

DEFAULT = ('mysql', 'postgres', 'sqlite', 'redis', 'ssh', 'duckdb')
ALL = DEFAULT + ('docker', 'kubernetes', 's3', 'elasticsearch', 'mongodb', 'jenkins', 'webdav', 'email')
TARGETS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-apple-darwin')


def verify_archive_signature(archive, signature, public_key, openssl):
    raw_signature = bytes.fromhex(signature.read_text().strip())
    if len(raw_signature) != 64:
        raise ValueError('Invalid detached signature length')
    with tempfile.TemporaryDirectory(prefix='voidb-archive-signature-') as temporary:
        root = pathlib.Path(temporary)
        key = root / 'public.der'
        key.write_bytes(bytes.fromhex('302a300506032b6570032100' + public_key))
        raw = root / 'signature'
        raw.write_bytes(raw_signature)
        subprocess.run([openssl, 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER',
                        '-inkey', str(key), '-in', str(archive), '-sigfile', str(raw)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stage(version, target, plugin, output, allow_legacy_unsigned=False, openssl="openssl"):
    filename = f'{plugin}-{version}-{target}.tar.gz'
    download = output / '.downloads' / plugin / target
    download.mkdir(parents=True, exist_ok=True)
    signed_release = tuple(map(int, version.split('.'))) >= (0, 3, 4)
    command = ['gh', 'release', 'download', f'v{version}', '--repo', f'limmytian/voidb-plugin-{plugin}',
               '--pattern', filename, '--pattern', 'SHA256SUMS', '--dir', str(download), '--clobber']
    if signed_release:
        command.extend(['--pattern', filename + '.sig'])
    for attempt in range(3):
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=180)
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise RuntimeError(f'Published asset download failed: {filename}') from None
            time.sleep(2)
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
            if signed_release:
                signature = pathlib.Path(str(archive) + '.sig')
                signature_checksums = [line.split()[0] for line in (download / 'SHA256SUMS').read_text().splitlines()
                                       if len(line.split()) == 2 and line.split()[1].lstrip('*') == signature.name]
                if len(signature_checksums) != 1 or hashlib.sha256(signature.read_bytes()).hexdigest() != signature_checksums[0]:
                    raise ValueError(f'Missing or invalid signature checksum: {signature.name}')
                verify_archive_signature(archive, signature, verifier.PUBLIC_KEY, openssl)
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
