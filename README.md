# Hash Tools

Hash Tools is a local desktop utility for computing file digests and inspecting
signed PDF documents. It is written in Rust with [iced](https://github.com/iced-rs/iced).

![Hash Tools user interface](docs/screenshot.png)

[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What it does

Hash Tools has two related, but separate, workflows:

1. **File hashing** reads the selected file as raw bytes and calculates a
   digest with the selected algorithm. The result can be copied or compared
   with a pasted value.
2. **PDF signature analysis** inspects PDF signature dictionaries, reads the
   raw bytes covered by `ByteRange`, extracts PKCS#7/CMS metadata, and compares
   the calculated signed-content digest with the embedded `messageDigest`.

The PDF workflow also shows the signature block (`/Contents`) digest, detected
algorithm, OIDs, and available certificate metadata. An HTML diagnostics report
can be exported next to the input PDF.

## Algorithms

The file hashing workflow supports:

| Algorithm | Digest size | Intended use |
| --- | ---: | --- |
| SHA-256 | 256 bits | General purpose |
| SHA-512 | 512 bits | General purpose |
| SHA3-256 | 256 bits | General purpose |
| SHA3-512 | 512 bits | General purpose |
| BLAKE3 | 256 bits | Fast general-purpose hashing |
| SM3 | 256 bits | Chinese commercial cryptography workflows |
| SHA-1 | 160 bits | Compatibility only |
| MD5 | 128 bits | Compatibility or legacy identification only |

For PDF signatures, automatic detection uses PDF metadata and, for generic
PKCS#7 containers, the signer signature algorithm OID. Common recognized forms
include SM3withSM2 and SHA-1, SHA-256, or SHA-512 with RSA. The signature panel
can also override the digest used for the `ByteRange` comparison with
`SHA-256`, `SM3`, `SM3(Z||M)`, or `SHA-1`.

## What PDF verification means here

The status shown by the application must be interpreted according to the
detected algorithm:

| Case | What is checked | What is not claimed |
| --- | --- | --- |
| **SM3withSM2** | The `ByteRange` digest is compared with `messageDigest`, and the implementation attempts cryptographic SM2 verification of the CMS signed attributes with the public key found in the embedded certificate. | This is not a certificate trust, revocation, timestamp, or legal-validity decision. Unsupported encodings or signature profiles can still fail. |
| **RSA and other non-SM2 signatures** | The `ByteRange` digest is compared with `messageDigest`; the UI reports the digest result and indicates when a cryptographic verifier is unavailable. | RSA (or another non-SM2 algorithm) is **not cryptographically verified** by this project. Treat the result as a digest check only. |
| **Unknown or malformed signatures** | The application reports the metadata and parsing or range errors where possible. | An algorithm label inferred from incomplete PDF metadata is not proof of the actual signing algorithm. |

The `ByteRange` digest is calculated from raw file bytes. It is therefore
different from the whole-file digest and from a digest of the CMS `/Contents`
block. Changing the PDF can invalidate the covered range, the embedded digest,
or both.

## Quick start

### Requirements

- A current stable [Rust toolchain](https://www.rust-lang.org/tools/install)
  with Cargo.
- On Linux, the GUI build needs the system development libraries used by the
  CI workflow: `libxkbcommon-dev`, `libwayland-dev`, and `libx11-dev`.
- Windows builds use the MSVC Rust target. macOS builds use the native desktop
  toolchain.

### Build and run

```bash
git clone https://github.com/BremCristopher/hash_tools.git
cd hash_tools
cargo build --release
cargo run --release
```

Choose an algorithm, then drag a file onto the drop area or click it to browse.
For a PDF with signature dictionaries, expand **PDF Signatures** to inspect
the signed ranges and digest checks. **Export** writes a
`<input-name>.diagnostics.html` report beside the selected PDF.

This repository currently provides the source project and build configuration;
use the commands above to build a local binary.

## Supported build targets

The GitHub Actions workflow is configured for these targets:

- Linux x86_64: `x86_64-unknown-linux-gnu`
- Windows x86_64 (MSVC): `x86_64-pc-windows-msvc`
- macOS x86_64: `x86_64-apple-darwin`
- macOS Apple Silicon: `aarch64-apple-darwin`

Other targets may require additional platform dependencies or code changes.

## Development checks

Run the project checks before submitting changes:

```bash
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets --all-features
```

The current test suite uses synthetic inputs to cover PDF `ByteRange` parsing,
range and arithmetic failures, chunked hashing, algorithm classification,
digest-only verification state, and diagnostics rendering. It does not ship
real signed PDFs or customer documents as fixtures.

## Data safety

Hash Tools is intended to process files locally. The GUI reads the file you
select and writes an exported diagnostics report locally; review any report
before sharing it because it can contain the input path, signer metadata,
certificate details, and digest values.

Do not commit or upload real customer documents, signed PDF/OFD samples,
personal certificates, private keys, P12/PFX bundles, or generated reports.
The repository ignore rules exclude common document, key, certificate, sample,
and diagnostics paths, but `.gitignore` is not a substitute for reviewing the
staged diff and reachable history. Never use `git add -f` to bypass those
rules.

## Known limitations

- Cryptographic verification is implemented only for the SM3withSM2 path. RSA
  and other non-SM2 signatures receive digest comparison only.
- Certificate chains, trust anchors, revocation status, signing timestamps,
  and signer identity are not validated.
- SM2 calculations use the default user ID `1234567812345678`; signatures that
  use another user ID may not verify or may produce a different `Z` value.
- PDF signature detection and CMS parsing support the formats handled by the
  current parser. Unusual, malformed, or BER-encoded containers can fail to
  parse or expose incomplete metadata.
- Automatic algorithm detection depends on PDF filters, subfilters, and CMS
  OIDs. Unknown forms can fall back to SHA-256; use the override only when the
  expected algorithm is known independently.
- The tool is a diagnostic aid, not a replacement for a standards-compliant
  signature validator, a certificate authority, or a legal examination.

## Project layout

```text
src/hash_logic.rs       File hashing implementations
src/pdf_signature.rs    PDF ByteRange, CMS, digest, and SM2 analysis
src/main.rs             iced application and report export
templates/              HTML diagnostics report template
assets/                 Application icons, fonts, and Windows resources
docs/screenshot.png     Reviewed generic UI screenshot
docs/                   Supplementary technical and usage documents
```

## Documentation

- [Hash verification guide](docs/hash_verification_guide.html)
- [Technical implementation notes](docs/technical_implementation.html)
- [Architecture overview](docs/ARCHITECTURE.md)

The HTML documents are supplementary project material; the capability and
verification boundaries in this README reflect the current Rust implementation.

## License

Hash Tools is distributed under the [MIT License](LICENSE).
