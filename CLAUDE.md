# ra-tls-proxy Development Guide

## Commit Requirements

**No AI attribution in commit messages.**

Do not include `Co-Authored-By: Claude` or any other AI attribution lines in commits.
AI tools may be used to assist with development, but all commits must be authored by the
human developer. A pre-push hook enforces this — see `.git/hooks/pre-push`.

New clones must install the hook manually:
```bash
cp -f hooks/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

All commits must be GPG-signed:
```bash
git config commit.gpgsign true
git config user.signingkey EC13425E92A56C29
```

## Release Gate

Do not publish to crates.io until the dstackgres sidecar has been updated to use this
crate as a dependency (dogfood requirement). This validates the public API before it is
locked in by a semver-stable release.

## Test Commands

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

## Publish Checklist

- [ ] `cargo test` passes (including integration test with live proxy connection)
- [ ] `cargo clippy -- -D warnings` clean
- [ ] Sidecar dogfood complete — path dep replaced with crates.io version
- [ ] All commits GPG-signed with no AI attribution
- [ ] Version bumped in `Cargo.toml`
- [ ] `cargo publish`
