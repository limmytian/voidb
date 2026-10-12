"""Archive verification must reject corrupt and unsafe published packages."""
import hashlib
import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('staging', pathlib.Path(__file__).parents[1] / 'download-release-plugins.py')
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)


class ReleaseStagingTests(unittest.TestCase):
    def exercise(self, entries, corrupt=False, allow_legacy_unsigned=True):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary)
            target = 'aarch64-apple-darwin'
            filename = f'sqlite-0.3.3-{target}.tar.gz'
            download = output / '.downloads' / 'sqlite' / target
            download.mkdir(parents=True)
            archive = download / filename
            with tarfile.open(archive, 'w:gz') as package:
                for name in entries:
                    info = tarfile.TarInfo(name)
                    info.size = 4
                    info.mode = 0o755
                    package.addfile(info, io.BytesIO(b'test'))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (download / 'SHA256SUMS').write_text(f'{"0" * 64 if corrupt else digest}  {filename}\n')
            with patch.object(staging.subprocess, 'run') as fetch:
                staging.stage('0.3.3', target, 'sqlite', output, allow_legacy_unsigned)
                fetch.assert_called_once()
                self.assertTrue((output / target / 'plugins/sqlite/bin/voidb-plugin-sqlite').exists())

    def test_verified_archive_is_staged(self):
        self.exercise(['plugin.toml', 'bin/voidb-plugin-sqlite'])

    def test_unsigned_legacy_staging_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(ValueError, 'Missing authenticated release provenance'):
            self.exercise(['plugin.toml', 'bin/voidb-plugin-sqlite'], allow_legacy_unsigned=False)

    def test_corrupt_archive_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Checksum mismatch'):
            self.exercise(['plugin.toml', 'bin/voidb-plugin-sqlite'], corrupt=True)

    def test_parent_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsafe archive member'):
            self.exercise(['plugin.toml', 'bin/voidb-plugin-sqlite', '../escape'])


if __name__ == '__main__':
    unittest.main()
