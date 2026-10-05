# Process Plugin Examples

These are local, secret-free process-plugin packages for SDK and discovery
testing.

- `hello-sql` demonstrates a read-only `query` capability and a mutating
  dry-run-aware `exec` capability.
- `hello-storage` demonstrates read-only, mutating, destructive, and
  external-side-effect risk declarations with synthetic responses.

Discover them with:

```bash
VOIDB_PLUGIN_PATH=examples/process-plugins cargo run -p voidb-cli -- plugin list --format json
```

The `bin/` scripts are fixtures, not production runtimes. They intentionally
avoid live databases, cloud accounts, credentials, and network calls.
