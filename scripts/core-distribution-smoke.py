#!/usr/bin/env python3
"""Test the unchanged shell installer with actual CI archives over routed real HTTP."""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--legacy-cli', type=Path, required=True)
    parser.add_argument('--legacy-tui', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--version', default='0.3.7', help='Release version under test')
    parser.add_argument('--legacy-version', default='0.3.6', help='Previously installed version for the upgrade mode')
    parser.add_argument('--public-release', action='store_true', help='Fetch actual public GitHub core assets without transport routing')
    args = parser.parse_args()
    artifacts = args.artifacts.resolve()
    legacy_cli, legacy_tui = args.legacy_cli.resolve(), args.legacy_tui.resolve()
    assert subprocess.check_output([str(legacy_cli), '--version'], text=True).strip() == f'voidb {args.legacy_version}'
    installer = Path(__file__).with_name('install.sh').resolve()
    report = {'transport': 'actual public GitHub Release and checksum HTTPS download' if args.public_release else 'actual curl and HTTP; only candidate GitHub download URLs routed to loopback',
              'installer': str(installer), 'checks': []}
    with tempfile.TemporaryDirectory(prefix='voidb-core-distribution-') as temporary:
        root = Path(temporary)
        served = root / 'served'
        served.mkdir()
        archives = sorted(artifacts.glob(f'voidb-{args.version}-*.tar.gz'))
        assert len(archives) == 4
        sums = ''
        for archive in archives:
            shutil.copyfile(archive, served / archive.name)
            sums += f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n'
        (served / 'SHA256SUMS').write_text(sums)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(served)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            shim = root / 'shim'
            shim.mkdir()
            prefix = f'https://github.com/limmytian/voidb/releases/download/v{args.version}/'
            base = f'http://127.0.0.1:{server.server_address[1]}/'
            # Route transport only; the production installer and fetched payloads remain unchanged.
            (shim / 'curl').write_text(
                '#!/usr/bin/env python3\nimport os,sys\n'
                f'prefix={prefix!r}\nbase={base!r}\n'
                'args=sys.argv[1:]\n'
                'urls=[a for a in args if a.startswith("https://") or a.startswith("http://")]\n'
                'assert len(urls)==1 and urls[0].startswith(prefix), "Unexpected installer request"\n'
                'name=urls[0][len(prefix):]\n'
                f'assert "/" not in name and (name=="SHA256SUMS" or name.startswith("voidb-{args.version}-"))\n'
                'args=[base+name if a==urls[0] else a for a in args]\n'
                'os.execv("/usr/bin/curl",["curl",*args])\n'
            )
            (shim / 'curl').chmod(0o755)
            for mode in ['clean', 'upgrade']:
                home = root / mode / 'home'
                home.mkdir(parents=True)
                dest = root / mode / 'bin'
                dest.mkdir()
                sentinel = home / 'profile-and-encrypted-credential-sentinel'
                sentinel.write_bytes(b'synthetic preserved user state')
                if mode == 'upgrade':
                    shutil.copyfile(legacy_cli, dest / 'voidb-cli')
                    shutil.copyfile(legacy_tui, dest / 'voidb')
                    (dest / 'voidb-cli').chmod(0o755)
                    (dest / 'voidb').chmod(0o755)
                env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / '.local/share'),
                           XDG_CONFIG_HOME=str(home / '.config'), INSTALL_DIR=str(dest), VOIDB_VERSION=args.version,
                           PATH=os.environ['PATH'] if args.public_release else str(shim) + os.pathsep + os.environ['PATH'])
                for key in ['VOIDB_PLUGIN_PATH', 'VOIDB_BUNDLED_PLUGIN_ROOT', 'VOIDB_ALLOW_UNSIGNED_PLUGINS',
                            'VOIDB_MASTER_PASSWORD', 'VOIDB_PLUGIN_REGISTRY_URL']:
                    env.pop(key, None)
                result = subprocess.run(['bash', str(installer)], env=env, capture_output=True, text=True, timeout=60)
                assert result.returncode == 0, result.stderr
                assert sorted(p.name for p in dest.iterdir()) == ['voidb', 'voidb-cli']
                assert subprocess.check_output([str(dest / 'voidb-cli'), '--version'], env=env, text=True).strip() == f'voidb {args.version}'
                plugins = subprocess.check_output([str(dest / 'voidb-cli'), 'plugin', 'list', '--format', 'json'], env=env, text=True)
                assert json.loads(plugins)['data']['plugins'] == []
                assert sentinel.read_bytes() == b'synthetic preserved user state'
                report['checks'].append(f'{mode}: real candidate binaries installed, no plugins or bundled fallback, user sentinel preserved')
                if mode == 'upgrade' and not args.public_release:
                    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in dest.iterdir()}
                    (served / 'SHA256SUMS').write_text('\n'.join('0' * 64 + '  ' + p.name for p in archives) + '\n')
                    rejected = subprocess.run(['bash', str(installer)], env=env, capture_output=True, text=True, timeout=60)
                    assert rejected.returncode != 0 and 'checksum verification failed' in rejected.stderr
                    assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in dest.iterdir()}
                    report['checks'].append('invalid outer checksum refuses installation before replacing existing core binaries')
        finally:
            server.shutdown()
            server.server_close()
    report['status'] = 'passed'
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Core public clean install and v{args.legacy_version} upgrade passed' if args.public_release else f'Core clean install, v{args.legacy_version} upgrade and checksum rejection passed with actual CI assets')


if __name__ == '__main__':
    main()
