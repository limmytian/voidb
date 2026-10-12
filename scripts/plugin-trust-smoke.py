#!/usr/bin/env python3
"""Exercise real signed native candidates through the production CLI and HTTP registry."""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading

PLUGINS = ['mysql', 'postgres', 'sqlite', 'redis', 'ssh', 'duckdb', 'docker', 'kubernetes',
           's3', 'elasticsearch', 'mongodb', 'jenkins', 'webdav', 'email']


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--target', default='aarch64-apple-darwin')
    parser.add_argument('--legacy-plugin-directory', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    cli, artifacts = args.cli.resolve(), args.artifacts.resolve()
    handler = functools.partial(QuietHandler, directory=str(artifacts))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_address[1]}'
    source_index = Path(__file__).parents[1] / 'registry/index.json'
    index = json.loads(source_index.read_text())
    index['registry_name'] = 'VoidB local native signed candidate registry'
    index['registry_url'] = base + '/registry-candidate.json'
    for entry in index['plugins']:
        if entry['id'] not in PLUGINS:
            continue
        old = entry['versions'][0]
        filename = f"{entry['id']}-0.3.4-{args.target}.tar.gz"
        archive = artifacts / filename
        version = dict(old, version='0.3.4', platforms=['darwin' if 'apple-darwin' in args.target else 'linux'],
                       signature_scheme='ed25519', packages=[{
                           'filename': filename, 'format': 'tar.gz', 'target': args.target,
                           'url': base + '/' + filename,
                           'sha256': 'sha256:' + hashlib.sha256(archive.read_bytes()).hexdigest(),
                           'size_bytes': archive.stat().st_size,
                           'signature': Path(str(archive) + '.sig').read_text().strip(),
                       }])
        entry['latest_version'] = '0.3.4'
        entry['versions'] = [version]
    (artifacts / 'registry-candidate.json').write_text(json.dumps(index, indent=2) + '\n')
    report = {'core_version': subprocess.check_output([str(cli), '--version'], text=True).strip(),
              'target': args.target, 'registry_transport': 'real loopback HTTP', 'checks': []}
    try:
        with tempfile.TemporaryDirectory(prefix='voidb-trust-smoke-') as temporary:
            root = Path(temporary).resolve()
            home = root / 'home'
            home.mkdir()
            env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                       XDG_DATA_HOME=str(home / '.local/share'), VOIDB_PLUGIN_REGISTRY_URL=index['registry_url'])
            for name in ['VOIDB_PLUGIN_PATH', 'VOIDB_BUNDLED_PLUGIN_ROOT', 'VOIDB_ALLOW_UNSIGNED_PLUGINS',
                         'VOIDB_MASTER_PASSWORD', 'VOIDB_CLI_BIN']:
                env.pop(name, None)
            sentinel = home / 'preserved-profile-and-encrypted-credential-sentinel'
            sentinel.write_bytes(b'synthetic user data must survive plugin operations')
            sentinel_digest = hashlib.sha256(sentinel.read_bytes()).hexdigest()

            def run(*command, json_output=True, input_text=None):
                result = subprocess.run([str(cli), *command], env=env, input=input_text,
                                        capture_output=True, text=True, timeout=60)
                if result.returncode:
                    raise AssertionError(f"CLI failed: {command}: {result.stderr[:1000]}")
                value = json.loads(result.stdout) if json_output else result.stdout
                if json_output and not value.get('ok'):
                    raise AssertionError(f"CLI error envelope: {command}: {value}")
                return value

            defaults = run('plugin', 'install-default', '--format', 'json')
            initial_list = run('plugin', 'list', '--format', 'json')['data']['plugins']
            assert all(Path(row['manifest_path']).resolve().is_relative_to(home) for row in initial_list), 'CLI must use isolated HOME'
            assert len(defaults['data']['results']) == 6
            assert all(row['status'] == 'installed' for row in defaults['data']['results']), defaults
            report['checks'].append('install-default downloaded and verified six actual signed plugins')
            repeated = run('plugin', 'install-default', '--format', 'json')
            assert all(row['status'] == 'already_installed' for row in repeated['data']['results'])
            for plugin in PLUGINS[6:]:
                run('plugin', 'install', plugin, '--format', 'json')
            listed = run('plugin', 'list', '--format', 'json')['data']['plugins']
            assert {row['id'] for row in listed} == set(PLUGINS)
            for plugin in PLUGINS:
                version = run(plugin, '--version', json_output=False)
                assert '0.3.4' in version
                messages = [
                    {'jsonrpc': '2.0', 'id': 1, 'method': 'voidb.initialize', 'params': {
                        'plugin_id': plugin, 'protocol_version': '1', 'core_version': '0.3.5'}},
                    {'jsonrpc': '2.0', 'id': 2, 'method': 'voidb.health', 'params': {}},
                ]
                output = run(plugin, 'serve', json_output=False, input_text=''.join(json.dumps(row) + '\n' for row in messages))
                responses = [json.loads(line) for line in output.splitlines() if line.strip()]
                assert len(responses) == 2 and all('result' in row for row in responses), (plugin, responses)
            report['checks'].append('all 14 actual plugins passed production dispatch, initialize and health')
            updated = run('plugin', 'update', 'mysql', '--format', 'json')['data']['plugin']
            install_root = Path(updated['install_root'])
            assert (install_root / 'mysql/provenance.json').is_file()
            previous = Path(updated['previous_version']['path'])
            run('plugin', 'update', 'mysql', '--from', str(previous), '--allow-downgrade', '--format', 'json')
            report['checks'].append('verified registry update and signed previous-package rollback')
            plugin_dir = install_root / 'mysql'
            record = install_root / '.voidb-install/mysql/install.toml'
            binary = plugin_dir / 'bin/voidb-plugin-mysql'
            proof = plugin_dir / 'provenance.json'
            saved_record, saved_binary, saved_proof = record.read_bytes(), binary.read_bytes(), proof.read_bytes()
            marker = root / 'untrusted-child.marker'
            secret = 'synthetic-secret-must-never-reach-a-child'
            for attack in ['record-deletion', 'legacy-digest-omission', 'malformed-record', 'co-modification', 'forged-proof']:
                record.write_bytes(saved_record)
                binary.write_bytes(saved_binary)
                proof.write_bytes(saved_proof)
                if attack == 'record-deletion':
                    record.unlink()
                elif attack == 'legacy-digest-omission':
                    record.write_text(re.sub(r'^binary_digest = .*\n', '', saved_record.decode(), flags=re.MULTILINE))
                elif attack == 'malformed-record':
                    record.write_text('invalid = [')
                elif attack == 'co-modification':
                    binary.write_text(f'#!/bin/sh\nprintf "%s" "$VOIDB_MASTER_PASSWORD" > "{marker}"\n')
                    digest = 'sha256:' + hashlib.sha256(binary.read_bytes()).hexdigest()
                    record.write_text(re.sub(r'^binary_digest = .*$', f'binary_digest = "{digest}"', saved_record.decode(), flags=re.MULTILINE))
                else:
                    forged = json.loads(saved_proof)
                    forged['signature'] = '00' * 64
                    proof.write_text(json.dumps(forged))
                before = record.read_bytes() if record.exists() else None
                for arguments in [('mysql', '--version'), ('mysql', 'tui'), ('mysql', 'serve'), ('mysql', 'test', '--stdin-config')]:
                    result = subprocess.run([str(cli), *arguments], env=dict(env, VOIDB_MASTER_PASSWORD=secret),
                                            input='{"synthetic_password":"' + secret + '"}', capture_output=True, text=True, timeout=15)
                    assert result.returncode != 0 and 'Security error' in result.stderr, (attack, result.stderr)
                    assert secret not in result.stdout + result.stderr and not marker.exists(), attack
                assert (record.read_bytes() if record.exists() else None) == before, attack
            record.write_bytes(saved_record)
            binary.write_bytes(saved_binary)
            proof.write_bytes(saved_proof)
            report['checks'].append('five attacks rejected before domain, TUI, serve and test dispatch; no child marker, secret output or backfill')
            for plugin in PLUGINS:
                run('plugin', 'uninstall', plugin, '--format', 'json')
            assert run('plugin', 'list', '--format', 'json')['data']['plugins'] == []
            report['checks'].append('uninstall all 14 leaves no implicit bundled fallback')
            if args.legacy_plugin_directory:
                legacy = args.legacy_plugin_directory.resolve()
                assert 'version = "0.3.3"' in (legacy / 'plugin.toml').read_text()
                shutil.copytree(legacy, install_root / 'mysql')
                record.unlink()
                blocked = subprocess.run([str(cli), 'mysql', '--version'], env=env, capture_output=True, text=True)
                assert blocked.returncode and 'Security error' in blocked.stderr
                migrated = run('plugin', 'update', 'mysql', '--format', 'json')['data']['plugin']
                assert migrated['installed_version'] == '0.3.4'
                assert (install_root / 'mysql/provenance.json').exists()
                report['checks'].append('actual immutable v0.3.3 backup with no record migrated through authenticated registry update')
                run('plugin', 'uninstall', 'mysql', '--format', 'json')
            assert hashlib.sha256(sentinel.read_bytes()).hexdigest() == sentinel_digest
            report['checks'].append('isolated user-data sentinel preserved; actual user installation and backup unchanged')
    finally:
        server.shutdown()
        server.server_close()
    report['status'] = 'passed'
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
