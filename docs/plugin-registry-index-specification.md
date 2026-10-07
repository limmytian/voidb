# Plugin Registry Index & Metadata Specification

This document defines the schema, generation process, and validation mechanisms for the official VoidB Plugin Registry index (`registry/index.json`).

## 1. Overview

VoidB provides an open, decoupled process-plugin ecosystem. To allow users and agents to discover available plugins, resolve compatible versions, and verify cryptographic integrity before installation, VoidB maintains an official Registry index catalog.

The registry is hosted as a static JSON/TOML document (e.g. `https://raw.githubusercontent.com/limmytian/voidb/main/registry/index.json`), requiring no central server or proprietary backend.

## 2. Registry Index Schema (`schemas/plugin-registry.schema.json`)

The registry schema enforces standard JSON Schema draft 2020-12 compliance:

```json
{
  "$schema": "https://voidb.dev/schemas/plugin-registry.schema.json",
  "schema_version": 1,
  "registry_name": "VoidB Official Plugin Registry",
  "registry_url": "https://raw.githubusercontent.com/limmytian/voidb/main/registry/index.json",
  "updated_at": "2026-10-07T14:21:20.859039Z",
  "plugins": [
    {
      "id": "s3",
      "name": "S3 Object Storage Plugin",
      "description": "Amazon S3 and S3-compatible object storage plugin for VoidB.",
      "homepage": "https://github.com/limmytian/voidb-plugin-s3",
      "license": "Apache-2.0",
      "category": "storage",
      "tags": ["s3"],
      "capabilities": ["buckets", "list", "stat", "get", "put", "delete", "mkdir", "copy", "move", "presign", "sync_plan", "transfer", "transfer_status"],
      "latest_version": "0.3.0",
      "versions": [
        {
          "version": "0.3.0",
          "protocol_version": "1",
          "released_at": "2026-10-07T14:09:37.918337Z",
          "voidb_core": ">=0.1.0",
          "platforms": ["darwin", "linux", "windows"],
          "packages": [
            {
              "filename": "s3-0.3.0.tar.gz",
              "format": "tar.gz",
              "url": "https://github.com/limmytian/voidb-plugin-s3/releases/download/v0.3.0/s3-0.3.0.tar.gz",
              "sha256": "sha256:d554a935ea396a827435f1140924976cfec3907c1b504b28169121703cf9fb3f"
            }
          ]
        }
      ]
    }
  ]
}
```

### Fields

- `schema_version`: Registry metadata schema version (currently `1`).
- `registry_name`: Human-readable title of the catalog.
- `registry_url`: Base URL or permalink of the registry index.
- `updated_at`: ISO 8601 UTC timestamp of index regeneration.
- `plugins[]`:
  - `id`: Unique plugin identifier matching `plugin.toml`.
  - `name`: Display name.
  - `description`: Summary of features.
  - `homepage`: GitHub/Gitea repository URL.
  - `license`: SPDX license identifier.
  - `category`: Domain classification (`storage`, `infrastructure`, `search`, `database`, `communication`, `other`).
  - `tags`: Search keywords.
  - `capabilities`: Array of capability identifiers exposed by the plugin.
  - `latest_version`: SemVer string of the latest release.
  - `versions[]`: Version history array containing packages, platform targets, protocol version, and sha256 checksums.

## 3. CLI Command: `voidb-cli plugin registry-index`

The `plugin registry-index` command scans local plugin repositories or packaged distribution archives (`.tar`, `.tar.gz`, `.tar.zst`), validates their structure, and updates the registry index manifest:

```bash
# Generate registry index from plugin repositories
voidb plugin registry-index \
  ../voidb-plugin-s3 \
  ../voidb-plugin-email \
  ../voidb-plugin-docker \
  ../voidb-plugin-kubernetes \
  ../voidb-plugin-elasticsearch \
  ../voidb-plugin-mongodb \
  ../voidb-plugin-jenkins \
  ../voidb-plugin-webdav \
  --output registry/index.json \
  --format json

# Index a specific packaged artifact into an existing index
voidb plugin registry-index \
  dist/s3-0.3.0-x86_64-unknown-linux-gnu.tar.gz \
  --merge registry/index.json \
  --output registry/index.json
```

## 4. Automation Script: `scripts/build-registry-index.sh`

`scripts/build-registry-index.sh` automatically indexes the 8 official standalone plugins from sibling directories and writes the result to `registry/index.json`.

```bash
./scripts/build-registry-index.sh
```
