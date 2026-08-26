use anyhow::Context;
use blake3::Hasher as Blake3Hasher;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use sm3::Sm3;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Md5,
    Sha1,
    Blake3,
    Sm3,
}

impl Algorithm {
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha512 => "SHA-512",
            Algorithm::Sha3_256 => "SHA3-256",
            Algorithm::Sha3_512 => "SHA3-512",
            Algorithm::Md5 => "MD5",
            Algorithm::Sha1 => "SHA-1",
            Algorithm::Blake3 => "BLAKE3",
            Algorithm::Sm3 => "SM3 (信创)",
        }
    }

    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::Sha256,
            Algorithm::Sha512,
            Algorithm::Sha3_256,
            Algorithm::Sha3_512,
            Algorithm::Md5,
            Algorithm::Sha1,
            Algorithm::Blake3,
            Algorithm::Sm3,
        ]
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

pub async fn compute_hash(path: impl AsRef<Path>, algo: Algorithm) -> anyhow::Result<String> {
    let mut file = File::open(path).await.context("Failed to open file")?;
    let mut buffer = [0u8; 8192];

    match algo {
        Algorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        Algorithm::Sha512 => {
            let mut hasher = Sha512::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        Algorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        Algorithm::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        Algorithm::Md5 => {
            let mut hasher = Md5::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        Algorithm::Sha1 => {
            let mut hasher = Sha1::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        Algorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hasher.finalize().to_string())
        }
        Algorithm::Sm3 => {
            let mut hasher = Sm3::new();
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
    }
}
