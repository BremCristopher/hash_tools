# Contributing

Hash Tools is a Rust desktop application for file hashing and PDF signature
diagnostics. Keep contributions focused on correctness, reproducibility, and
safe handling of document data.

## Local quality checks

Use a stable Rust toolchain. On Debian or Ubuntu, the current `iced` windowing
features use X11 and Wayland, while `rfd` uses its XDG portal backend. Install
the same development packages as the Linux CI job:

```bash
sudo apt-get update
sudo apt-get install -y libxkbcommon-dev libwayland-dev libx11-dev
```

Before opening a pull request, run the checks used by CI:

```bash
cargo fmt --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

The strict Clippy command is part of the quality gate. Keep new code warning
free and review any warning cleanup as part of the focused change that needs
it.

Tests should be deterministic and runnable without a GUI session, network
access, customer files, or private credentials. Prefer small synthetic inputs
for hash, PDF, CMS, and ByteRange cases. Keep dependency and lockfile changes
limited to the reason for the pull request.

## Data and security rules

Never commit or upload customer PDF/OFD files, signature samples, diagnostic
reports, personal certificates, certificate bundles, private keys, passwords,
tokens, or other real personal or confidential data. The repository ignores
common sample and credential paths, but `.gitignore` does not remove data from
Git history. Do not bypass it with `git add -f`.

If a fixture is needed, generate it from synthetic data in a temporary local
directory and describe how to reproduce it. Review the staged diff and file
paths before pushing. Report suspected credential exposure or a security issue
privately rather than adding the material to an issue or pull request.

## Pull requests

Keep each pull request small and explain the behavior changed, why it is
needed, and how it was verified. For security or PDF-signature changes,
include negative tests for malformed, truncated, altered, or unsupported input
where practical. Do not mix dependency modernization with an unrelated UI
rewrite or release packaging change.

Start from the final reviewed pull-request commit or its reviewed `main`
result. Do not force-push `main`, push all local branches or tags, or reintroduce
the old local feature-branch history. Release and signing work is outside the
normal CI quality gate.
