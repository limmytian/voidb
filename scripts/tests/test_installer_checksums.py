"""Installer must authenticate bytes before replacing any executable."""
import hashlib
import io
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

INSTALLER = pathlib.Path(__file__).parents[1] / 'install.sh'


class InstallerTests(unittest.TestCase):
    def run_installer(self, checksum):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        mocks = root / 'mocks'
        mocks.mkdir()
        archive = root / 'archive.tar.gz'
        scripts = {'voidb': '#!/bin/sh\nexit 0\n',
                   'voidb-cli': '#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/bootstrap.args"\n[ -d "$VOIDB_BUNDLED_PLUGIN_ROOT" ] || exit 5\nprintf \'{"results":[{"status": "installed"}]}\'\n',
                   'plugins/sqlite/plugin.toml': 'id = "sqlite"\n'}
        with tarfile.open(archive, 'w:gz') as package:
            for name, script in scripts.items():
                data = script.encode()
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o755
                package.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (mocks / 'curl').write_text('''#!/bin/sh
url="$2"
output="$4"
case "$url" in
  */SHA256SUMS) printf '%s  %s\\n' "$TEST_CHECKSUM" "$TEST_ARCHIVE_NAME" > "$output" ;;
  *.tar.gz) cp "$TEST_ARCHIVE" "$output" ;;
  *) exit 22 ;;
esac
''')
        (mocks / 'curl').chmod(0o755)
        system = subprocess.check_output(['uname', '-s'], text=True).strip().lower()
        machine = subprocess.check_output(['uname', '-m'], text=True).strip().lower()
        architecture = 'arm64' if machine in ('arm64', 'aarch64') else 'x64'
        env = dict(os.environ, PATH=str(mocks) + os.pathsep + os.environ['PATH'],
                   HOME=str(root / 'home'), INSTALL_DIR=str(root / 'install'), VOIDB_VERSION='0.3.3',
                   TEST_ARCHIVE=str(archive), TEST_ARCHIVE_NAME=f'voidb-0.3.3-{system}-{architecture}.tar.gz',
                   TEST_CHECKSUM=digest if checksum == 'valid' else checksum)
        result = subprocess.run(['bash', str(INSTALLER)], env=env, capture_output=True, text=True)
        return root, result

    def test_verified_bundle_uses_cli_install_records(self):
        root, result = self.run_installer('valid')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        args = (root / 'install/bootstrap.args').read_text()
        self.assertIn('install-default\n--from-bundled', args)
        self.assertTrue((root / 'install/voidb').exists())

    def test_mismatch_does_not_replace_binaries(self):
        root, result = self.run_installer('0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / 'install/voidb').exists())

    def test_missing_checksum_does_not_replace_binaries(self):
        root, result = self.run_installer('')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / 'install/voidb').exists())


if __name__ == '__main__':
    unittest.main()
