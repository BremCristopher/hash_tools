# Cloud Agent Handoff

This is the execution brief for a constrained Warp Cloud Agent run with an
approximately 1,000-credit budget. Work in small, reviewable stages and stop
after the selected stage is verified.

## Starting point and verified current state

Start from the final pull-request commit while it is under review, or from the
resulting final commit on `main` after merge. This document intentionally does
not hard-code a provisional branch or SHA. Record the exact starting commit
once with:

```bash
git status --short --branch
git rev-parse --short=12 HEAD
git log --oneline --decorate -n 10
```

The current quality work has been verified in the reviewed source snapshot:

- Nine deterministic synthetic unit tests pass with
  `cargo test --all-targets --locked`.
- `cargo fmt --check` and `cargo check --all-targets --locked` pass.
- Clippy is warning free with
  `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- The only remaining toolchain notice is the `block 0.1.6` future-incompatibility
  warning; it is a dependency follow-up, not a source warning.
- P1 PDF hardening is complete: ByteRange values are strictly non-negative,
  arithmetic is checked, ranges are bounded by the file size, and signed bytes
  are hashed in 64 KiB chunks without allocation based on PDF-controlled
  lengths.
- A non-SM2 digest match no longer sets `signature_valid`; the result and UI
  distinguish a matching digest from an implemented cryptographic verification.
  SHA-512 RSA digest detection is also covered by the current implementation.
- Generic CAdES containers defer algorithm selection to CMS OIDs, and exported
  diagnostics distinguish unsupported verification from a failed signature.
  Report fields are HTML-escaped and covered by a rendering regression test.

These facts describe the reviewed snapshot. Recheck the final PR or `main`
commit once before accepting further changes. Do not describe local results as
GitHub CI results until that exact commit has a completed CI run. Cross-platform
GUI behavior and real-document interoperability remain unverified here.

## Guardrails

Use only generated, synthetic test data. Never copy customer PDF/OFD files,
signature samples, personal certificates, private keys, P12/PFX files,
passwords, tokens, generated diagnostic reports, or other confidential data
into the repository or cloud workspace. Review paths and the staged diff before
each push; `.gitignore` does not erase data from Git history, and it must not be
bypassed with `git add -f`.

Do not import, merge, or push the old local feature-branch history. Do not
force-push `main`, use `git push --all` or `git push --mirror`, modify release or
signing jobs for these tasks, or add Dependabot or other automatic upgrade
configuration. Keep `Cargo.lock` changes intentional and explain them in the
change summary. Preserve unrelated reviewed changes.

Do not spend credits reconstructing or re-investigating the nine completed
synthetic tests. Inspect and preserve their coverage, extend it only for new
behavior, and run the complete gate at the end of a stage.

## Priority and scope

With the limited budget, use this order:

1. **Dependency modernization.** Review direct and transitive versions in
   `Cargo.toml` and `Cargo.lock`. Upgrade one coherent group at a time, starting
   with security and compatibility fixes in the PDF, CMS, ASN.1, SM2, and SM3
   stack. Avoid broad lockfile churn and do not mix unrelated upgrades.
2. **GM/T modernization.** Improve algorithm and OID handling while preserving
   clear supported, unsupported, and digest-only outcomes. Add compact,
   generated tests for relevant SM2/SM3 and DER/BER cases.
3. **Remaining P2 risks.** Address SHA-384 detection and hashing, complete CMS
   and RSA cryptographic verification or keep the unsupported state explicit,
   and associate asynchronous results with the selected file or request
   generation so stale work cannot replace current results.

Out of scope are real-document interoperability claims, security
certification, UI redesign, release packaging, code signing, binary fixtures,
and broad refactors. Do not reopen completed P1 work unless a new failing test
provides evidence of a regression.

## Credit-efficient checks

Use a focused test while iterating. At the end of each selected stage, run the
complete gate once:

```bash
cargo fmt --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
git diff --check
git status --short
```

If a command fails because a dependency, platform library, or tool is missing,
record the exact failure and fix only what is needed to continue. Never weaken
or silently remove a check. Do not run release or signing jobs for this work.

### Stage 1: dependency review and upgrade

Inspect the existing dependency graph and lockfile before editing. Select one
small, justified dependency group, make the minimal manifest and lockfile
change, and run the relevant focused tests. Then run the complete gate.

Acceptance: the change summary names the group and reason, the lockfile has no
unrelated churn, all checks pass with `-D warnings`, and no document or
credential data was added.

### Stage 2: GM/T and PDF compatibility

Use generated inputs to exercise OID recognition, SM2/SM3 hashing, supported and
unsupported algorithms, and DER/BER parsing. Keep digest matching visibly
separate from cryptographic signature verification. Reuse the existing nine
tests; add only cases that prove newly changed behavior. Run focused tests and
then the complete gate.

Acceptance: supported algorithms retain their behavior, unsupported or
digest-only paths remain explicit, and malformed input is rejected safely.

### Stage 3: remaining P2 behavior and handoff

Implement and test SHA-384 handling, CMS/RSA verification or its explicit
unsupported result, and request/file association for asynchronous results.
Finish with the complete gate, inspect the final diff for secret and document
paths, and report any remaining platform or real-sample coverage as unverified.

Acceptance: changed behavior has deterministic tests, CI is green for the
reviewed commit, the final report separates verified facts from open risks, and
no old branch history or force-push was used.
