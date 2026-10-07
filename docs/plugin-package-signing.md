# VoidB Plugin Package Signing and Verification

This document specifies the cryptographic signing and verification architecture for VoidB distribution plugin packages.

## Overview

VoidB provides offline, tamper-evident cryptographic signing for distribution plugin packages (`.tar`, `.tar.gz`, `.tar.zst`).
By using **Ed25519** (Edwards-curve Digital Signature Algorithm), signatures remain compact (64 bytes raw, 128 hex characters), verification is deterministic and high-performance, and the verification key is 32 bytes (64 hex characters).

Signatures are distributed as detached signature files with a `.sig` extension (e.g. `voidb-plugin-s3-0.3.0-rc.1.tar.zst.sig`).

---

## 1. Cryptographic Scheme

- **Algorithm**: Ed25519 (Edwards 25519 curve, SHA-512)
- **Signature Encoding**: Lowercase hex (128 characters)
- **Public Key Encoding**: Lowercase hex (64 characters)
- **Detached Signature Suffix**: `<package_filename>.sig`
- **Tamper Protection**: Any bit modification to the packaged archive payload invalidates the signature.

---

## 2. CLI Tooling: `voidb plugin sign` and `voidb plugin verify`

The `voidb plugin` CLI provides native subcommands to manage keys, sign packages, and verify signatures.

### 2.1 Generating a Keypair and Signing a Package

To generate a new one-off or release keypair while signing an archive:

```bash
voidb plugin sign dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst --generate-key
```

Output (JSON or Table):
```text
Field                  Value
operation              sign
package                dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst
signature_file         dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst.sig
signature              <128-hex-characters>
public_key             <64-hex-characters>
generated_private_key  <64-hex-characters>
```

### 2.2 Signing with an Existing Private Key

You can pass a 64-hex private key directly or reference a private key file:

```bash
# Direct hex
voidb plugin sign dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst \
  --private-key "d88b4998980b62d8544e30ef00ad581373ea89d5337220556fd43b17c1bf2eb8"

# Via file
voidb plugin sign dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst \
  --private-key path/to/release.key
```

### 2.3 Verifying an Archive Signature

```bash
# Verify using default detached signature path (<archive>.sig)
voidb plugin verify dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst \
  --public-key "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Or explicitly specifying signature file/hex
voidb plugin verify dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst \
  --public-key "e3b0c442..." \
  --signature path/to/custom.sig
```

---

## 3. Installation Gate: Strict Signature Verification

During `voidb plugin install` and `voidb plugin update`, you can enforce signature verification via `--verify-key`:

```bash
# Install with verification (fails if signature is missing or invalid)
voidb plugin install dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst \
  --verify-key "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Enforce that signature file exists even if verify key is supplied
voidb plugin install dist/voidb-plugin-s3-0.3.0-rc.1.tar.zst \
  --verify-key "<pubkey>" \
  --require-signature
```

If the package signature is missing or does not match the public key, the command fails with an error and terminates before unpacking or altering existing plugin installations.

---

## 4. Registry Index Integration

The official registry manifest (`registry/index.json`) embeds the signature along with the SHA256 checksum for each artifact:

```json
{
  "filename": "voidb-plugin-s3-0.3.0-rc.1.tar.zst",
  "download_url": "https://github.com/limmytian/voidb-plugin-s3/releases/download/v0.3.0-rc.1/voidb-plugin-s3-0.3.0-rc.1.tar.zst",
  "sha256": "4722c1767e37340b...",
  "size": 425268,
  "format": "tar.zst",
  "signature": "<128-hex-signature-if-present>"
}
```
