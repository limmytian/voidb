#!/usr/bin/env python3
"""Verify optional onboarding and contextual installation with real PTYs and signed HTTP assets."""
import argparse
import functools
import hashlib
import http.server
import json
import os
import re
from pathlib import Path
import select
import signal
import shlex
import subprocess
import tempfile
import threading
import time


class Handler(http.server.SimpleHTTPRequestHandler):
    requests = []
    fail_next_mysql = False

    def log_message(self, *_args):
        pass

    def do_GET(self):
        Handler.requests.append(self.path)
        if self.path.startswith('/mysql-') and Handler.fail_next_mysql:
            Handler.fail_next_mysql = False
            self.send_error(503, 'Intentional candidate retry test')
            return
        super().do_GET()


class Terminal:
    def __init__(self, binary, env, width=100, height=35):
        self.output = bytearray()
        command = f"stty cols {width} rows {height}; exec {shlex.quote(str(binary))}"
        launcher = ['script', '-q', '/dev/null', '/bin/sh', '-c', command] if os.uname().sysname == 'Darwin' else ['script', '-q', '-c', command, '/dev/null']
        self.process = subprocess.Popen(
            launcher,
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.fd = self.process.stdout.fileno()

    def send(self, value):
        self.process.stdin.write(value.encode())
        self.process.stdin.flush()

    def key(self, character):
        codepoint = 13 if character == 'Enter' else ord(character)
        self.send(f'\x1b[{codepoint};1:1u')

    def wait(self, text, timeout=30):
        deadline = time.monotonic() + timeout
        start = len(self.output)
        while time.monotonic() < deadline:
            visible = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", self.output[start:])
            compact = re.sub(rb'\s+', b'', visible)
            spaced = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b' ', self.output[start:])
            matched = bool(re.search(rb'\bavailable\b', spaced)) if text == 'available' else re.sub(rb'\s+', b'', text.encode()) in compact
            if matched:
                return
            ready, _, _ = select.select([self.fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.output.extend(chunk)
                # Respond to terminal queries so keyboard feature detection is bounded.
                if b'\x1b[?u' in chunk:
                    self.send('\x1b[?0u')
                if b'\x1b[c' in chunk:
                    self.send('\x1b[?1;2c')
        raise AssertionError(f'Terminal did not display {text!r}: {bytes(self.output[-8000:])!r}')

    def close(self):
        if self.process.poll() is None:
            try:
                self.key('q')
                self.process.wait(timeout=3)
            except (subprocess.TimeoutExpired, BrokenPipeError):
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait()
        self.process.stdin.close()
        self.process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tui', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    binary, artifacts = args.tui.resolve(), args.artifacts.resolve()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=str(artifacts)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_address[1]}'
    index = json.loads((artifacts / 'registry-candidate.json').read_text())
    index['registry_url'] = base + '/registry-tui-candidate.json'
    for entry in index['plugins']:
        for version in entry['versions']:
            for package in version['packages']:
                package['url'] = base + '/' + package['filename']
    (artifacts / 'registry-tui-candidate.json').write_text(json.dumps(index, indent=2) + '\n')
    report = {'status': 'pending', 'transport': 'real PTY, production CLI, signed loopback HTTP registry', 'checks': []}
    active = []
    try:
        with tempfile.TemporaryDirectory(prefix='voidb-onboarding-smoke-') as temporary:
            root = Path(temporary).resolve()

            def environment(name):
                home = root / name
                home.mkdir()
                env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                           XDG_DATA_HOME=str(home / '.local/share'), TERM='xterm-256color',
                           VOIDB_PLUGIN_REGISTRY_URL=index['registry_url'],
                           VOIDB_MASTER_PASSWORD='synthetic-parent-password-for-install-isolation')
                for key in ['VOIDB_PLUGIN_PATH', 'VOIDB_BUNDLED_PLUGIN_ROOT', 'VOIDB_ALLOW_UNSIGNED_PLUGINS', 'VOIDB_CLI_BIN']:
                    env.pop(key, None)
                return home, env

            home, env = environment('noninteractive')
            before = len(Handler.requests)
            subprocess.run([str(binary)], env=env, input='', capture_output=True, text=True, timeout=15)
            assert len(Handler.requests) == before
            assert not list(home.rglob('provenance.json'))
            report['checks'].append('noninteractive startup performs no registry requests or installation')

            home, env = environment('onboarding-install')
            terminal = Terminal(binary, env)
            active.append(terminal)
            terminal.wait('Download and install these plugins now?')
            terminal.send('y\n')
            terminal.wait('Recommended plugins installed.')
            terminal.wait('Connection Manager')
            time.sleep(0.2)
            assert len(list(home.rglob('provenance.json'))) == 6
            assert list(home.rglob('plugin-onboarding-v1'))
            terminal.close()
            active.remove(terminal)
            report['checks'].append('first interactive install downloads six real signed packages and persists acknowledgment')

            home, env = environment('onboarding-partial')
            Handler.fail_next_mysql = True
            terminal = Terminal(binary, env)
            active.append(terminal)
            terminal.wait('Download and install these plugins now?')
            terminal.send('y\n')
            terminal.wait('Plugin installation did not complete:', timeout=60)
            terminal.wait('Connection Manager')
            time.sleep(0.2)
            assert len(list(home.rglob('provenance.json'))) == 5
            assert not list(home.rglob('plugin-onboarding-v1'))
            terminal.close()
            active.remove(terminal)
            terminal = Terminal(binary, env)
            active.append(terminal)
            terminal.wait('Download and install these plugins now?')
            terminal.send('y\n')
            terminal.wait('Recommended plugins installed.', timeout=60)
            terminal.wait('Connection Manager')
            time.sleep(0.2)
            assert len(list(home.rglob('provenance.json'))) == 6
            assert list(home.rglob('plugin-onboarding-v1'))
            terminal.close()
            active.remove(terminal)
            report['checks'].append('partial first-launch failure installs five, persists no acknowledgment and retries the missing plugin next launch')

            home, env = environment('contextual-install')
            config = home / ('Library/Application Support/voidb' if os.uname().sysname == 'Darwin' else '.config/voidb')
            config.mkdir(parents=True)
            profiles = config / 'profiles.json'
            profiles.write_text(json.dumps({'version': 1, 'profiles': [{
                'id': 'native:smoke-mysql', 'name': 'Native MySQL smoke', 'plugin_id': 'mysql',
                'metadata': {'source': 'native_profile_store'}, 'default_options': {}, 'credential_refs': [], 'policy': {},
            }]}))
            credentials = config / 'credentials.json'
            credentials.write_text(json.dumps({'version': 1, 'credentials': []}))
            before_data = [hashlib.sha256(file.read_bytes()).hexdigest() for file in (profiles, credentials)]
            terminal = Terminal(binary, env, 100, 35)
            active.append(terminal)
            terminal.wait('Download and install these plugins now?')
            terminal.send('n\n')
            terminal.wait('Connection Manager')
            time.sleep(0.2)
            terminal.key('i')
            terminal.wait('Install plugin')
            before = len(Handler.requests)
            terminal.key('n')
            time.sleep(0.3)
            assert len(Handler.requests) == before and not list(home.rglob('provenance.json'))
            terminal.close()
            active.remove(terminal)
            assert list(home.rglob('plugin-onboarding-v1'))
            report['checks'].append('skip persists and contextual cancellation creates no download')

            terminal = Terminal(binary, env, 72, 20)
            active.append(terminal)
            terminal.wait('Connection Manager')
            time.sleep(0.2)
            assert b'Download and install these plugins now?' not in terminal.output
            Handler.fail_next_mysql = True
            terminal.key('i')
            terminal.wait('Install plugin')
            terminal.key('Enter')
            terminal.wait('failed:', timeout=60)
            assert not list(home.rglob('provenance.json'))
            terminal.key('i')
            terminal.wait('Install plugin')
            terminal.key('Enter')
            terminal.wait('available', timeout=60)
            assert len(list(home.rglob('provenance.json'))) == 1
            assert [hashlib.sha256(file.read_bytes()).hexdigest() for file in (profiles, credentials)] == before_data
            terminal.close()
            active.remove(terminal)
            report['checks'].append('minimum-size contextual failure retries and installs only MySQL; profile/credential files unchanged')
    finally:
        for terminal in active:
            terminal.close()
        server.shutdown()
        server.server_close()
    report['status'] = 'passed'
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
