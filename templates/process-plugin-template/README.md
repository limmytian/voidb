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

Add to `VOIDB_PLUGIN_PATH`:

```bash
export VOIDB_PLUGIN_PATH=$(pwd)
voidb-cli plugin list
```

## License

Apache-2.0
