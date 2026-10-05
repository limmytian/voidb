## Summary

<!-- Brief description of the purpose of this PR. -->

## Changes Made

<!-- List key changes introduced by this pull request. -->
- 

## Verification

<!-- Describe how this was tested or which check commands were run. -->
- [ ] `cargo test -p <touched-crate>`
- [ ] `cargo clippy -p <touched-crate> --all-targets --no-deps`
- [ ] `bash scripts/check-agent-capability-matrix.sh` (if capability metadata changed)
- [ ] All tests and CI checks pass locally

## Checklist

- [ ] Code follows project conventions and architecture guidelines (isolated plugins, service layer pattern).
- [ ] No plaintext secrets or sensitive test data included.
- [ ] Documentation updated where appropriate.
