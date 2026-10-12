"""Detached release signatures reject substituted archives and signatures."""
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('staging_signature', pathlib.Path(__file__).parents[1] / 'download-release-plugins.py')
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)


class ArchiveSignatureTests(unittest.TestCase):
    def setUp(self):
        self.openssl = os.environ.get('OPENSSL_EXECUTABLE', shutil.which('openssl'))
        if self.openssl is None:
            self.skipTest('OpenSSL is required for Ed25519 archive signature tests')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = pathlib.Path(self.temporary.name)
        self.key = root / 'test-key.pem'
        subprocess.run([self.openssl, 'genpkey', '-algorithm', 'ED25519', '-out', str(self.key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = subprocess.check_output([self.openssl, 'pkey', '-in', str(self.key), '-pubout', '-outform', 'DER'])
        self.public = public[-32:].hex()
        self.archive = root / 'package.tar.gz'
        self.archive.write_bytes(b'independent synthetic signed archive')
        self.signature = root / 'package.tar.gz.sig'
        signature = subprocess.check_output([self.openssl, 'pkeyutl', '-sign', '-rawin', '-inkey', str(self.key), '-in', str(self.archive)])
        self.signature.write_text(signature.hex() + '\n')

    def test_authentic_archive_is_verified(self):
        staging.verify_archive_signature(self.archive, self.signature, self.public, self.openssl)

    def test_modified_archive_is_rejected(self):
        self.archive.write_bytes(b'substituted archive')
        with self.assertRaises(subprocess.CalledProcessError):
            staging.verify_archive_signature(self.archive, self.signature, self.public, self.openssl)

    def test_modified_signature_is_rejected(self):
        value = bytearray.fromhex(self.signature.read_text().strip())
        value[0] ^= 1
        self.signature.write_text(value.hex())
        with self.assertRaises(subprocess.CalledProcessError):
            staging.verify_archive_signature(self.archive, self.signature, self.public, self.openssl)

    def test_invalid_signature_length_is_rejected(self):
        self.signature.write_text('00')
        with self.assertRaisesRegex(ValueError, 'signature length'):
            staging.verify_archive_signature(self.archive, self.signature, self.public, self.openssl)


if __name__ == '__main__':
    unittest.main()
