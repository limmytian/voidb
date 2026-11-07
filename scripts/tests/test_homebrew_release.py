import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLATFORMS = ('darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64')


class HomebrewReleaseTest(unittest.TestCase):
    def test_verification_render_and_downgrade_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for binary in ('vb', 'vb-tui'):
                (root / binary).write_text(binary)
            checksums = []
            for platform in PLATFORMS:
                archive = root / f'voidb-0.4.2-{platform}.tar.gz'
                with tarfile.open(archive, 'w:gz') as tar:
                    for binary in ('vb', 'vb-tui'):
                        tar.add(root / binary, arcname=binary)
                checksums.append(f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}')
            (root / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
            verify = [sys.executable, str(ROOT / 'scripts/verify-homebrew-release.py'), '--artifacts', str(root), '--version', '0.4.2']
            subprocess.run(verify, check=True, capture_output=True)
            formula = root / 'voidb.rb'
            formula.write_text((ROOT / 'packaging/homebrew/voidb.rb').read_text())
            render = [sys.executable, str(ROOT / 'scripts/update-homebrew-formula.py'), '--artifacts', str(root), '--version', '0.4.2', '--formula', str(formula), '--output', str(formula)]
            subprocess.run(render, check=True, capture_output=True)
            first = formula.read_text()
            subprocess.run(render, check=True, capture_output=True)
            self.assertEqual(first, formula.read_text())
            self.assertIn('version "0.4.2"', first)
            formula.write_text(first.replace('version "0.4.2"', 'version "0.4.3"'))
            self.assertNotEqual(subprocess.run(render, capture_output=True).returncode, 0)
            (root / f'voidb-0.4.2-{PLATFORMS[0]}.tar.gz').write_bytes(b'corrupt')
            self.assertNotEqual(subprocess.run(verify, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
