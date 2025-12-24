# Hash Tools

A modern, cross-platform file hash calculator with a beautiful dark-themed UI.

![Hash Tools Screenshot](docs/screenshot.png)

## Features

- **Multiple Hash Algorithms**:
  - SHA-256 (default)
  - SHA-512
  - SHA-1
  - SHA3-256 / SHA3-512
  - MD5
  - BLAKE3
  - **SM3** (Chinese National Standard / 信创)

- **Modern UI**:
  - Dark "Glass" themed aesthetics
  - Embedded Google Sans Code font
  - Full Chinese (CJK) character support
  - High-DPI / Retina display support

- **User-Friendly**:
  - Drag & drop file support
  - One-click copy to clipboard
  - Hash comparison with visual Match/Mismatch indicator

## Installation

### Pre-built Binaries

Download from [Releases](../../releases):
- **Windows**: `hash_tools-windows.exe`
- **macOS**: `hash_tools-macos.dmg`
- **Linux**: `hash_tools-linux.AppImage`

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-username/hash_tools.git
cd hash_tools

# Build release version
cargo build --release

# The binary will be at target/release/hash_tools
```

## Cross-Compilation

### Build for Windows (from macOS/Linux)

```bash
# Install MinGW-w64 toolchain
# macOS: brew install mingw-w64
# Linux: apt install mingw-w64

# Add Windows target
rustup target add x86_64-pc-windows-gnu

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

## Project Structure

```
hash_tools/
├── src/
│   ├── main.rs          # Application entry point and UI
│   ├── hash_logic.rs    # Hash computation logic
│   ├── style.rs         # UI styling and colors
│   └── icons.rs         # SVG icons
├── assets/
│   ├── icon.ico         # Windows icon
│   ├── icon.icns        # macOS icon
│   ├── icon.png         # Linux icon (256x256)
│   └── app.manifest     # Windows application manifest
├── GoogleSansCode-*/     # Embedded fonts
├── build.rs             # Windows resource embedding
├── Cargo.toml           # Rust dependencies
└── README.md            # This file
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [iced](https://github.com/iced-rs/iced) - A cross-platform GUI library for Rust
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic hash implementations
- [SM3](https://crates.io/crates/sm3) - Chinese national hash algorithm implementation
