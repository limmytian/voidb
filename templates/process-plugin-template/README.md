# voidb-plugin-{{plugin_name}}

{{plugin_description}}

## Capabilities

- `ping`: Health check or connectivity probe.

## Development

```bash
# Build the plugin
cargo build

# Export JSON schemas
cargo run --example export_schemas

# Run test fixture
cargo run --example fixture_smoke
```

## Running with VoidB

Unsigned development plugins must be discovered from an explicit development
root: set `VOIDB_PLUGIN_PATH` to the directory that CONTAINS the plugin's
folder and enable unsigned execution:

```bash
export VOIDB_PLUGIN_PATH=$(pwd)
VOIDB_PLUGIN_PATH=$(pwd) VOIDB_ALLOW_UNSIGNED_PLUGINS=1 vb plugin list
```

`VOIDB_PLUGIN_PATH` and `VOIDB_ALLOW_UNSIGNED_PLUGINS=1` only apply to explicit
development roots; managed installs require packaging and signing, then
`vb plugin install <plugin>`.

## License

Apache-2.0
