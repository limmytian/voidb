# Process Plugin Examples

These are local, secret-free process-plugin packages for SDK and discovery
testing.

- `hello-sql` demonstrates a read-only `query` capability and a mutating
  dry-run-aware `exec` capability.
- `hello-storage` demonstrates read-only, mutating, destructive, and
  external-side-effect risk declarations with synthetic responses.
- `example-python` demonstrates a lightweight, secret-free Python plugin
  implementing the stdio-jsonrpc protocol with an `echo` capability.
- `example-go` demonstrates a compiled Go plugin implementing the
  stdio-jsonrpc protocol with an `info` capability.

Discover them with:

```bash
VOIDB_PLUGIN_PATH=examples/process-plugins cargo run -p voidb-cli -- plugin list --format json
```

The example runtimes are fixtures, not production drivers. They intentionally
avoid live databases, cloud accounts, credentials, and network calls.
