//! PDF Signature Hash Extraction and Verification
//!
//! This module provides functionality to extract digital signature information
//! from PDF documents and calculate hashes of the signed content for verification
//! against Certificate of Completion records.
//!
//! # Key Concepts
//!
//! PDF digital signatures use a `ByteRange` array to specify which parts of the
//! document are covered by the signature. The format is `[offset1, len1, offset2, len2]`
//! where the gap between the two ranges contains the signature data itself.
//!
//! # Important
//!
//! Hash calculation MUST use raw file bytes, not lopdf-processed data, as PDF
//! parsers may normalize whitespace or reorder objects.

use lopdf::{Document, Object, ObjectId};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

use crate::hash_logic::Algorithm;

/// Errors that can occur during PDF signature operations
#[derive(Error, Debug)]
pub enum PdfSignatureError {
    #[error("Failed to load PDF: {0}")]
    LoadError(#[from] lopdf::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("No signatures found in PDF")]
    NoSignatures,

    #[error("Invalid ByteRange format")]
    InvalidByteRange,

    #[error("ByteRange extends beyond file size")]
    ByteRangeOutOfBounds,
}

/// Detected signature algorithm from PDF
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureAlgorithm {
    /// SHA-256 with RSA (most common)
    Sha256WithRsa,
    /// SHA-1 with RSA (legacy)
    Sha1WithRsa,
    /// SHA-512 with RSA
    Sha512WithRsa,
    /// SM3 with SM2 (Chinese national standard)
    Sm3WithSm2,
    /// Unknown algorithm - use the raw filter string
    Unknown(String),
}

impl SignatureAlgorithm {
    /// Parse from PDF /Filter and /SubFilter values
    pub fn from_pdf_filters(filter: Option<&str>, sub_filter: Option<&str>) -> Self {
        // Check SubFilter first (more specific)
        if let Some(sf) = sub_filter {
            let sf_lower = sf.to_lowercase();
            // Check for Chinese national standard SM2/SM3 first
            if sf_lower.contains("sm3") || sf_lower.contains("sm2") {
                return Self::Sm3WithSm2;
            }
            if sf_lower.contains("sha512") {
                return Self::Sha512WithRsa;
            }
            if sf_lower.contains("sha256") {
                return Self::Sha256WithRsa;
            }
            if sf_lower.contains("sha1") {
                return Self::Sha1WithRsa;
            }
            // Generic CMS containers do not identify a digest or signature algorithm. Detect
            // those from CMS SignerInfo OIDs instead of guessing from the PDF SubFilter.
            match sf_lower.as_str() {
                "adbe.pkcs7.detached" | "etsi.cades.detached" => {
                    return Self::Unknown(sf.to_string());
                }
                "adbe.pkcs7.sha1" => return Self::Sha1WithRsa,
                _ => {}
            }
        }

        // Check Filter
        if let Some(f) = filter {
            return Self::Unknown(f.to_string());
        }

        Self::Unknown("Unknown".to_string())
    }

    /// Detect algorithm from PKCS#7/CMS signature contents
    pub fn detect_from_pkcs7(signature_contents: &[u8]) -> Option<Self> {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::Decode;

        // Strip trailing null padding
        let mut data = signature_contents;
        while data.last() == Some(&0) {
            data = &data[..data.len() - 1];
        }

        if data.is_empty() {
            return None;
        }

        // Parse PKCS#7 ContentInfo
        let content_info = ContentInfo::from_der(data).ok()?;
        let signed_data = content_info.content.decode_as::<SignedData>().ok()?;

        // Get first signer info and check algorithm OID
        let signer = signed_data.signer_infos.0.as_slice().first()?;
        Self::from_signature_algorithm_oid(signer.signature_algorithm.oid.as_bytes())
    }

    /// Identify known signature algorithms from the CMS SignerInfo signatureAlgorithm OID.
    fn from_signature_algorithm_oid(oid_bytes: &[u8]) -> Option<Self> {
        let oid = format_oid(oid_bytes);

        if oid.contains("1.2.156.10197") {
            return Some(Self::Sm3WithSm2);
        }
        if oid.contains("1.2.840.113549.1.1.11") {
            return Some(Self::Sha256WithRsa);
        }
        if oid.contains("1.2.840.113549.1.1.13") {
            return Some(Self::Sha512WithRsa);
        }
        if oid.contains("1.2.840.113549.1.1.5") {
            return Some(Self::Sha1WithRsa);
        }

        None
    }

    /// Get the hash algorithm to use for this signature
    pub fn hash_algorithm(&self) -> Algorithm {
        match self {
            Self::Sha256WithRsa => Algorithm::Sha256,
            Self::Sha1WithRsa => Algorithm::Sha1,
            Self::Sha512WithRsa => Algorithm::Sha512,
            Self::Sm3WithSm2 => Algorithm::Sm3,
            Self::Unknown(_) => Algorithm::Sha256, // Default fallback
        }
    }

    /// Get display name
    pub fn display_name(&self) -> String {
        match self {
            Self::Sha256WithRsa => "SHA256withRSA".to_string(),
            Self::Sha1WithRsa => "SHA1withRSA".to_string(),
            Self::Sha512WithRsa => "SHA512withRSA".to_string(),
            Self::Sm3WithSm2 => "SM3withSM2".to_string(),
            Self::Unknown(s) => s.clone(),
        }
    }
}

/// Represents the byte ranges covered by a PDF signature
#[derive(Debug, Clone)]
pub struct ByteRange {
    /// Vector of (offset, length) tuples
    pub ranges: Vec<(u64, u64)>,
}

impl ByteRange {
    /// Parse ByteRange from lopdf Object array
    /// Expected format: [offset1, len1, offset2, len2, ...]
    pub fn from_object(obj: &Object) -> Result<Self, PdfSignatureError> {
        let array = match obj {
            Object::Array(arr) => arr,
            _ => return Err(PdfSignatureError::InvalidByteRange),
        };

        if array.len() < 4 || array.len() % 2 != 0 {
            return Err(PdfSignatureError::InvalidByteRange);
        }

        let mut ranges = Vec::new();
        for chunk in array.chunks(2) {
            let offset = Self::extract_integer(&chunk[0])?;
            let length = Self::extract_integer(&chunk[1])?;
            ranges.push((offset, length));
        }

        Ok(Self { ranges })
    }

    fn extract_integer(obj: &Object) -> Result<u64, PdfSignatureError> {
        match obj {
            Object::Integer(n) if *n >= 0 => Ok(*n as u64),
            _ => Err(PdfSignatureError::InvalidByteRange),
        }
    }

    /// Calculate total bytes covered by this ByteRange
    pub fn total_bytes(&self) -> Result<u64, PdfSignatureError> {
        self.ranges.iter().try_fold(0u64, |total, (_, length)| {
            total
                .checked_add(*length)
                .ok_or(PdfSignatureError::ByteRangeOutOfBounds)
        })
    }

    /// Check that every range has an in-file end offset without overflow.
    fn validate_file_size(&self, file_size: u64) -> Result<(), PdfSignatureError> {
        // Keep aggregate accounting checked as well, even though chunked reads never allocate it.
        self.total_bytes()?;

        for (offset, length) in &self.ranges {
            let end = offset
                .checked_add(*length)
                .ok_or(PdfSignatureError::ByteRangeOutOfBounds)?;
            if end > file_size {
                return Err(PdfSignatureError::ByteRangeOutOfBounds);
            }
        }
        Ok(())
    }
}

/// Information about a PDF signature
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// The object ID of the signature in the PDF
    #[allow(dead_code)]
    pub object_id: ObjectId,

    /// The byte ranges covered by this signature
    pub byte_range: ByteRange,

    /// Detected signature algorithm
    pub algorithm: SignatureAlgorithm,

    /// Raw signature block contents (from /Contents field)
    /// This is the PKCS#7/CMS signature data
    pub signature_contents: Vec<u8>,

    /// Signer name, if available
    pub signer_name: Option<String>,

    /// Signing reason, if available
    #[allow(dead_code)]
    pub reason: Option<String>,

    /// Signing location, if available
    #[allow(dead_code)]
    pub location: Option<String>,

    /// Signing date string (raw from PDF)
    pub sign_date: Option<String>,
}

impl SignatureInfo {
    /// Extract signature info from a PDF signature dictionary
    fn from_sig_dict(
        object_id: ObjectId,
        dict: &lopdf::Dictionary,
    ) -> Result<Option<Self>, PdfSignatureError> {
        // ByteRange is required for hash calculation
        let byte_range = match dict.get(b"ByteRange") {
            Ok(obj) => ByteRange::from_object(obj)?,
            Err(_) => return Ok(None), // Skip signatures without ByteRange
        };

        // Extract /Contents (the actual signature block)
        let signature_contents = match dict.get(b"Contents") {
            Ok(Object::String(bytes, _)) => bytes.clone(),
            _ => Vec::new(), // No signature contents available
        };

        // Extract Filter and SubFilter to determine algorithm
        let filter = Self::extract_string(dict, b"Filter");
        let sub_filter = Self::extract_string(dict, b"SubFilter");
        let mut algorithm =
            SignatureAlgorithm::from_pdf_filters(filter.as_deref(), sub_filter.as_deref());

        // If SubFilter is generic (pkcs7.detached), detect actual algorithm from OID
        if matches!(algorithm, SignatureAlgorithm::Unknown(_)) && !signature_contents.is_empty() {
            if let Some(detected) = SignatureAlgorithm::detect_from_pkcs7(&signature_contents) {
                algorithm = detected;
            }
        }

        // Extract optional fields
        let signer_name = Self::extract_string(dict, b"Name");
        let reason = Self::extract_string(dict, b"Reason");
        let location = Self::extract_string(dict, b"Location");
        let sign_date = Self::extract_string(dict, b"M");

        Ok(Some(Self {
            object_id,
            byte_range,
            algorithm,
            signature_contents,
            signer_name,
            reason,
            location,
            sign_date,
        }))
    }

    fn extract_string(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
        dict.get(key).ok().and_then(|obj| match obj {
            Object::String(bytes, _) => String::from_utf8(bytes.clone()).ok(),
            Object::Name(bytes) => String::from_utf8(bytes.clone()).ok(),
            _ => None,
        })
    }

    /// Get friendly display name for signature list
    /// Priority: 1) PDF /Name field, 2) Certificate Subject CN, 3) Algorithm-based fallback
    pub fn get_display_name(&self) -> String {
        // First try the PDF /Name field
        if let Some(ref name) = self.signer_name {
            if !name.is_empty() && name != "Unknown" {
                return name.clone();
            }
        }

        // Try to extract from certificate Subject CN
        if let Ok(diag) = self.extract_signature_diagnostics() {
            if let Some(cert) = diag.certificates.first() {
                // Parse CN from subject like "CN=Name, O=Org, ..."
                if let Some(cn) = Self::extract_cn_from_subject(&cert.subject) {
                    return cn;
                }
                // Fallback to full subject if CN not found
                if !cert.subject.is_empty() {
                    let subject = cert.subject.clone();
                    // Truncate if too long
                    if subject.len() > 40 {
                        return format!("{}...", &subject[..37]);
                    }
                    return subject;
                }
            }
        }

        // Algorithm-specific fallback
        match self.algorithm {
            SignatureAlgorithm::Sm3WithSm2 => "SM2数字签名".to_string(),
            SignatureAlgorithm::Sha256WithRsa => "RSA数字签名".to_string(),
            SignatureAlgorithm::Sha1WithRsa => "RSA-SHA1签名".to_string(),
            SignatureAlgorithm::Sha512WithRsa => "RSA-SHA512签名".to_string(),
            SignatureAlgorithm::Unknown(_) => "数字签名".to_string(),
        }
    }

    /// Extract CN (Common Name) from X.509 subject string
    fn extract_cn_from_subject(subject: &str) -> Option<String> {
        // Handle formats like "CN=Name" or "CN = Name" or "2.5.4.3=Name"
        for part in subject.split(',') {
            let part = part.trim();

            // Check for "CN=xxx" format
            if let Some(cn_value) = part
                .strip_prefix("CN=")
                .or_else(|| part.strip_prefix("CN ="))
                .or_else(|| part.strip_prefix("2.5.4.3="))
            {
                let cn = cn_value.trim();
                if !cn.is_empty() {
                    return Some(cn.to_string());
                }
            }
        }
        None
    }

    /// Calculate the hash of the signature block (/Contents)
    /// This is what the Certificate of Completion usually shows
    pub fn calculate_signature_block_hash(&self, algorithm: Algorithm) -> String {
        if self.signature_contents.is_empty() {
            return "No signature contents".to_string();
        }

        calculate_hash_of_bytes(&self.signature_contents, algorithm)
    }

    /// Calculate SM3(Z || M) hash for SM3withSM2 signatures
    /// This is the proper hash that matches Certificate of Completion
    ///
    /// Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
    /// e = SM3(Z || M)
    pub fn calculate_sm3_with_sm2_hash(&self, message: &[u8]) -> Result<String, String> {
        // Try to extract SM2 public key from signature contents
        let pubkey = self.extract_sm2_public_key()?;

        // Calculate Z value using default ID "1234567812345678"
        let z = calculate_sm2_z_value(&pubkey, b"1234567812345678");

        // Calculate SM3(Z || M) - concatenate first, then hash
        let mut z_m = z.clone();
        z_m.extend_from_slice(message);

        let mut hasher = libsm::sm3::hash::Sm3Hash::new(&z_m);
        let hash = hasher.get_hash();

        Ok(hex::encode(hash))
    }

    /// Calculate SM3(Z || M) from the signed byte ranges without buffering M in memory.
    fn calculate_sm3_with_sm2_hash_from_byte_range(
        &self,
        pdf_path: &Path,
    ) -> Result<String, String> {
        use sm3::{Digest as Sm3Digest, Sm3};

        let public_key = self.extract_sm2_public_key()?;
        let z = calculate_sm2_z_value(&public_key, b"1234567812345678");
        let mut hasher = Sm3::new();
        hasher.update(&z);
        stream_byte_range_contents(pdf_path, &self.byte_range, |chunk| hasher.update(chunk))
            .map_err(|e| e.to_string())?;

        Ok(hex::encode(hasher.finalize()))
    }

    /// Extract SM2 public key from PKCS#7/CMS signature contents
    fn extract_sm2_public_key(&self) -> Result<Vec<u8>, String> {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::Decode;

        if self.signature_contents.is_empty() {
            return Err("No signature contents".to_string());
        }

        // PDF signature contents often have trailing null padding that must be stripped
        // Find the actual DER content length by trimming trailing zeros
        let mut data = &self.signature_contents[..];
        while data.last() == Some(&0) {
            data = &data[..data.len() - 1];
        }

        if data.is_empty() {
            return Err("Signature contents only contains zeros".to_string());
        }

        // Try to parse as ContentInfo (PKCS#7 wrapper)
        let content_info =
            ContentInfo::from_der(data).map_err(|e| format!("Failed to parse PKCS#7: {}", e))?;

        // Extract SignedData
        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(|e| format!("Failed to parse SignedData: {}", e))?;

        // Get first certificate
        let certs = signed_data
            .certificates
            .ok_or("No certificates in signature")?;

        // Try to extract public key from first certificate
        for cert_choice in certs.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = cert_choice {
                // Extract the SubjectPublicKeyInfo
                let spki = &cert.tbs_certificate.subject_public_key_info;
                // Return the public key bytes
                return Ok(spki.subject_public_key.raw_bytes().to_vec());
            }
        }

        Err("No certificate found in signature".to_string())
    }

    /// Extract the messageDigest attribute from PKCS#7 SignerInfo
    /// This is the original hash value that was signed by the signer
    pub fn extract_message_digest(&self) -> Result<String, String> {
        // First try DER parsing (faster, works for most signatures)
        match self.extract_message_digest_der() {
            Ok(digest) => Ok(digest),
            // If DER fails due to indefinite length, try BER parsing.
            Err(error)
                if error.contains("indefinite length") || error.contains("trailing data") =>
            {
                self.extract_message_digest_ber()
            }
            Err(error) => Err(error),
        }
    }

    /// Extract messageDigest using DER parser (cms crate)
    fn extract_message_digest_der(&self) -> Result<String, String> {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::Decode;

        if self.signature_contents.is_empty() {
            return Err("No signature contents".to_string());
        }

        // Strip trailing null padding
        let mut data = &self.signature_contents[..];
        while data.last() == Some(&0) {
            data = &data[..data.len() - 1];
        }

        if data.is_empty() {
            return Err("Signature contents only contains zeros".to_string());
        }

        // Parse PKCS#7 ContentInfo
        let content_info =
            ContentInfo::from_der(data).map_err(|e| format!("Failed to parse PKCS#7: {}", e))?;

        // Extract SignedData
        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(|e| format!("Failed to parse SignedData: {}", e))?;

        // Get first signer info
        if signed_data.signer_infos.0.is_empty() {
            return Err("No signer info found".to_string());
        }

        let signer_info = &signed_data.signer_infos.0.as_slice()[0];

        // Look for messageDigest in signed attributes
        if let Some(ref signed_attrs) = signer_info.signed_attrs {
            // messageDigest OID: 1.2.840.113549.1.9.4
            const MESSAGE_DIGEST_OID: &[u8] =
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

            for attr in signed_attrs.iter() {
                if attr.oid.as_bytes() == MESSAGE_DIGEST_OID {
                    // The value is a SET containing an OCTET STRING
                    if let Some(value) = attr.values.get(0) {
                        // Try to decode as OctetString
                        if let Ok(digest) = value.decode_as::<der::asn1::OctetString>() {
                            return Ok(hex::encode(digest.as_bytes()));
                        }
                    }
                }
            }
        }

        Err("messageDigest attribute not found".to_string())
    }

    /// Extract messageDigest using BER parser (asn1-rs crate) for signatures that use BER encoding
    fn extract_message_digest_ber(&self) -> Result<String, String> {
        use asn1_rs::Oid;

        if self.signature_contents.is_empty() {
            return Err("No signature contents".to_string());
        }

        // Strip trailing null padding
        let mut data = &self.signature_contents[..];
        while data.last() == Some(&0) {
            data = &data[..data.len() - 1];
        }

        // messageDigest OID: 1.2.840.113549.1.9.4
        let _ = Oid::from(&[1, 2, 840, 113549, 1, 9, 4][..])
            .map_err(|e| format!("Failed to create OID: {:?}", e))?;

        // When parsing fails with the high-level parser, search for the messageDigest
        // pattern directly in the binary data
        // The structure is: SEQUENCE { OID 1.2.840.113549.1.9.4, SET { OCTET STRING } }
        // OID bytes: 06 09 2a 86 48 86 f7 0d 01 09 04
        let oid_bytes: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
        ];

        // Search for the OID in the data
        if let Some(pos) = data.windows(oid_bytes.len()).position(|w| w == oid_bytes) {
            // After the OID, there should be a SET containing an OCTET STRING
            let after_oid = &data[pos + oid_bytes.len()..];

            // Look for SET tag (0x31) followed by OCTET STRING tag (0x04)
            for i in 0..after_oid.len().min(20) {
                if after_oid.get(i) == Some(&0x31) {
                    // Found SET, look for OCTET STRING inside
                    let set_start = i;
                    if let Some(set_len) = Self::parse_asn1_length(&after_oid[set_start + 1..]) {
                        let octet_string_start = set_start + 1 + set_len.0;
                        if after_oid.get(octet_string_start) == Some(&0x04) {
                            // Found OCTET STRING
                            if let Some((len_bytes, content_len)) =
                                Self::parse_asn1_length(&after_oid[octet_string_start + 1..])
                            {
                                let content_start = octet_string_start + 1 + len_bytes;
                                if content_start + content_len <= after_oid.len() {
                                    let digest =
                                        &after_oid[content_start..content_start + content_len];
                                    return Ok(hex::encode(digest));
                                }
                            }
                        }
                    }
                }
            }
        }

        Err("messageDigest not found in BER structure".to_string())
    }

    /// Parse ASN.1 length field, returns (bytes_consumed, length)
    fn parse_asn1_length(data: &[u8]) -> Option<(usize, usize)> {
        if data.is_empty() {
            return None;
        }

        let first = data[0] as usize;
        if first < 0x80 {
            // Short form
            Some((1, first))
        } else if first == 0x80 {
            // Indefinite length - not supported here
            None
        } else {
            // Long form
            let num_bytes = first & 0x7f;
            if num_bytes > 4 || data.len() < 1 + num_bytes {
                return None;
            }
            let mut length = 0usize;
            for i in 0..num_bytes {
                length = (length << 8) | (data[1 + i] as usize);
            }
            Some((1 + num_bytes, length))
        }
    }

    /// Extract comprehensive diagnostic information from PKCS#7 signature
    /// Returns structured info about OIDs, algorithms, certificate, and attributes
    pub fn extract_signature_diagnostics(&self) -> Result<SignatureDiagnostics, String> {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::Decode;

        if self.signature_contents.is_empty() {
            return Err("No signature contents".to_string());
        }

        // Strip trailing null padding
        let mut data = &self.signature_contents[..];
        while data.last() == Some(&0) {
            data = &data[..data.len() - 1];
        }

        if data.is_empty() {
            return Err("Signature contents only contains zeros".to_string());
        }

        // Parse PKCS#7 ContentInfo
        let content_info = ContentInfo::from_der(data).map_err(|e| {
            let err_str = format!("{}", e);
            if err_str.contains("indefinite length") {
                "BER encoding (OID diagnostics unavailable)".to_string()
            } else {
                format!("Failed to parse PKCS#7: {}", e)
            }
        })?;

        let content_type_oid = format_oid(content_info.content_type.as_bytes());

        // Extract SignedData
        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(|e| format!("Failed to parse SignedData: {}", e))?;

        // Get digest algorithms
        let mut digest_algorithms = Vec::new();
        for alg in signed_data.digest_algorithms.iter() {
            digest_algorithms.push(format_oid(alg.oid.as_bytes()));
        }

        // Get signer info
        let mut signer_diagnostics = Vec::new();
        for signer in signed_data.signer_infos.0.iter() {
            let sig_alg_oid = format_oid(signer.signature_algorithm.oid.as_bytes());
            let digest_alg_oid = format_oid(signer.digest_alg.oid.as_bytes());

            // Extract signed attributes OIDs
            let mut signed_attrs = Vec::new();
            if let Some(ref attrs) = signer.signed_attrs {
                for attr in attrs.iter() {
                    let attr_oid = format_oid(attr.oid.as_bytes());
                    // Try to get attribute value as hex for unknown attributes
                    let value_preview = if let Some(v) = attr.values.get(0) {
                        // First 32 bytes as hex preview
                        use der::Encode;
                        let bytes = v.to_der().unwrap_or_default();
                        if bytes.len() > 32 {
                            format!("{}... ({} bytes)", hex::encode(&bytes[..32]), bytes.len())
                        } else {
                            hex::encode(&bytes)
                        }
                    } else {
                        "empty".to_string()
                    };
                    signed_attrs.push((attr_oid, value_preview));
                }
            }

            // Extract unsigned attributes OIDs
            let mut unsigned_attrs = Vec::new();
            if let Some(ref attrs) = signer.unsigned_attrs {
                for attr in attrs.iter() {
                    unsigned_attrs.push(format_oid(attr.oid.as_bytes()));
                }
            }

            signer_diagnostics.push(SignerDiagnostics {
                signature_algorithm: sig_alg_oid,
                digest_algorithm: digest_alg_oid,
                signed_attributes: signed_attrs,
                unsigned_attributes: unsigned_attrs,
            });
        }

        // Get certificate info
        let mut cert_diagnostics = Vec::new();
        if let Some(ref certs) = signed_data.certificates {
            for cert_choice in certs.0.iter() {
                if let cms::cert::CertificateChoices::Certificate(cert) = cert_choice {
                    let subject = format_distinguished_name(&cert.tbs_certificate.subject);
                    let issuer = format_distinguished_name(&cert.tbs_certificate.issuer);
                    let sig_alg = format_oid(cert.signature_algorithm.oid.as_bytes());
                    let serial = hex::encode(cert.tbs_certificate.serial_number.as_bytes());

                    cert_diagnostics.push(CertificateDiagnostics {
                        subject,
                        issuer,
                        signature_algorithm: sig_alg,
                        serial_number: serial,
                    });
                }
            }
        }

        Ok(SignatureDiagnostics {
            content_type: content_type_oid,
            digest_algorithms,
            signers: signer_diagnostics,
            certificates: cert_diagnostics,
        })
    }

    /// Verify the PDF signature
    /// Returns a SignatureVerificationResult with detailed status
    pub fn verify_signature<P: AsRef<Path>>(&self, pdf_path: P) -> SignatureVerificationResult {
        let mut result = SignatureVerificationResult {
            is_valid: false,
            hash_valid: false,
            signature_valid: false,
            signature_verification_supported: false,
            algorithm: format!("{:?}", self.algorithm),
            calculated_hash: String::new(),
            embedded_hash: String::new(),
            error: None,
        };

        // Step 1: First extract messageDigest to determine the correct hash algorithm.
        // The length of the embedded hash tells us what algorithm was used
        let embedded_hash = match self.extract_message_digest() {
            Ok(h) => {
                result.embedded_hash = h.clone();
                Some(h)
            }
            Err(e) => {
                // Check if it's a BER encoding issue
                let error_msg = if e.contains("indefinite length") {
                    "PKCS#7 uses BER encoding (unsupported)".to_string()
                } else {
                    format!("Failed to extract messageDigest: {}", e)
                };
                result.error = Some(error_msg);
                None
            }
        };

        // Determine hash algorithm from: 1) known algorithm, 2) embedded hash length
        let detected_algo = if matches!(
            self.algorithm,
            SignatureAlgorithm::Sm3WithSm2
                | SignatureAlgorithm::Sha1WithRsa
                | SignatureAlgorithm::Sha256WithRsa
                | SignatureAlgorithm::Sha512WithRsa
        ) {
            self.algorithm.clone()
        } else if let Some(ref eh) = embedded_hash {
            // Detect from hash length: 40=SHA1, 64=SHA256/SM3, 128=SHA512.
            match eh.len() {
                40 => SignatureAlgorithm::Sha1WithRsa,
                64 => SignatureAlgorithm::Sha256WithRsa,
                128 => SignatureAlgorithm::Sha512WithRsa,
                _ => self.algorithm.clone(),
            }
        } else {
            self.algorithm.clone()
        };

        // For messageDigest comparison, use the direct ByteRange hash without SM2 Z-value
        // preprocessing. Hashing streams fixed-size chunks, so untrusted ByteRange lengths do
        // not control allocation size.
        let calculated_hash = match calculate_signature_hash(
            pdf_path.as_ref(),
            &self.byte_range,
            detected_algo.hash_algorithm(),
        ) {
            Ok(hash) => hash,
            Err(e) => {
                result.error = Some(format!("Failed to hash signed content: {}", e));
                return result;
            }
        };

        result.calculated_hash = calculated_hash.clone();

        // Compare hashes if we have embedded hash
        if let Some(ref eh) = embedded_hash {
            result.hash_valid = calculated_hash == *eh;
        }

        // Step 3: Verify the actual signature
        if matches!(self.algorithm, SignatureAlgorithm::Sm3WithSm2) {
            // SM2 signature verification
            result.signature_verification_supported = true;
            match self.verify_sm2_signature() {
                Ok(valid) => {
                    result.signature_valid = valid;
                }
                Err(e) => {
                    if result.error.is_none() {
                        result.error = Some(format!("SM2 verification: {}", e));
                    }
                }
            }
        } else {
            result.mark_signature_verification_unavailable(&detected_algo);
        }

        // Overall validity
        result.is_valid = result.hash_valid && result.signature_valid;

        result
    }

    /// Verify SM2 signature using libsm
    fn verify_sm2_signature(&self) -> Result<bool, String> {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::Decode;

        if self.signature_contents.is_empty() {
            return Err("No signature contents".to_string());
        }

        // Strip trailing null padding
        let mut data = &self.signature_contents[..];
        while data.last() == Some(&0) {
            data = &data[..data.len() - 1];
        }

        // Parse PKCS#7
        let content_info =
            ContentInfo::from_der(data).map_err(|e| format!("Failed to parse PKCS#7: {}", e))?;

        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(|e| format!("Failed to parse SignedData: {}", e))?;

        // Get signer info
        if signed_data.signer_infos.0.is_empty() {
            return Err("No signer info".to_string());
        }

        let signer_info = &signed_data.signer_infos.0.as_slice()[0];

        // Get signature value
        let signature_bytes = signer_info.signature.as_bytes();

        // Get public key
        let pubkey_bytes = self.extract_sm2_public_key()?;

        // Get the signed attributes hash (this is what's actually signed)
        let signed_attrs = signer_info
            .signed_attrs
            .as_ref()
            .ok_or("No signed attributes")?;

        // Encode signed attributes as DER for verification
        use der::Encode;
        let signed_attrs_der = signed_attrs
            .to_der()
            .map_err(|e| format!("Failed to encode signed attrs: {}", e))?;

        // Calculate SM3 hash of signed attributes with Z value
        let z_value = calculate_sm2_z_value(&pubkey_bytes, b"1234567812345678");
        let mut zm_data = z_value.clone();
        zm_data.extend_from_slice(&signed_attrs_der);

        // Use libsm for SM2 verification
        use libsm::sm2::ecc::EccCtx;
        use libsm::sm2::signature::{SigCtx, Signature};

        let ctx = EccCtx::new();

        // Parse public key (assuming uncompressed format: 04 || x || y)
        if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
            return Err(format!(
                "Invalid public key format, len={}, first byte={:02x}",
                pubkey_bytes.len(),
                pubkey_bytes.first().copied().unwrap_or(0)
            ));
        }

        let pk = ctx
            .bytes_to_point(&pubkey_bytes)
            .map_err(|e| format!("Failed to parse public key: {:?}", e))?;

        // Parse signature (DER encoded: SEQUENCE { INTEGER r, INTEGER s })
        let sig = Signature::der_decode(signature_bytes)
            .map_err(|e| format!("Failed to parse signature: {:?}", e))?;

        // Verify - SigCtx.verify returns Result<bool, Sm2Error>
        let sig_ctx = SigCtx::new();
        let is_valid = sig_ctx
            .verify(&signed_attrs_der, &pk, &sig)
            .map_err(|e| format!("SM2 verify error: {:?}", e))?;

        Ok(is_valid)
    }
}

/// Diagnostic information about a PKCS#7/CMS signature
#[derive(Debug, Clone)]
pub struct SignatureDiagnostics {
    pub content_type: String,
    pub digest_algorithms: Vec<String>,
    pub signers: Vec<SignerDiagnostics>,
    pub certificates: Vec<CertificateDiagnostics>,
}

#[derive(Debug, Clone)]
pub struct SignerDiagnostics {
    pub signature_algorithm: String,
    pub digest_algorithm: String,
    pub signed_attributes: Vec<(String, String)>, // (OID, value preview)
    #[allow(dead_code)]
    pub unsigned_attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateDiagnostics {
    pub subject: String,
    pub issuer: String,
    pub signature_algorithm: String,
    pub serial_number: String,
}

/// Result of signature verification
#[derive(Debug, Clone)]
pub struct SignatureVerificationResult {
    /// Overall validity - true only if both hash and signature are valid
    pub is_valid: bool,
    /// Whether the calculated hash matches the embedded messageDigest
    pub hash_valid: bool,
    /// Whether the cryptographic signature verification passed
    pub signature_valid: bool,
    /// Whether this algorithm has an implemented cryptographic verifier
    pub signature_verification_supported: bool,
    /// The algorithm used
    #[allow(dead_code)]
    pub algorithm: String,
    /// The hash we calculated from ByteRange content
    pub calculated_hash: String,
    /// The hash embedded in the PKCS#7 structure
    pub embedded_hash: String,
    /// Any error message
    pub error: Option<String>,
}

impl SignatureVerificationResult {
    /// Preserve a matching messageDigest while preventing it from being presented as a
    /// cryptographic signature verification result.
    fn mark_signature_verification_unavailable(&mut self, algorithm: &SignatureAlgorithm) {
        self.signature_verification_supported = false;
        self.signature_valid = false;
        self.is_valid = false;

        if self.hash_valid && self.error.is_none() {
            self.error = Some(format!(
                "Cryptographic signature verification is unavailable for {}; messageDigest matches",
                algorithm.display_name()
            ));
        }
    }
}

/// Format OID bytes as dotted decimal string
fn format_oid(bytes: &[u8]) -> String {
    // OID encoding: first byte = 40*first + second, rest uses base-128 encoding
    if bytes.is_empty() {
        return "empty".to_string();
    }

    let mut components = Vec::new();

    // First two components are encoded in first byte
    let first = bytes[0] / 40;
    let second = bytes[0] % 40;
    components.push(first as u32);
    components.push(second as u32);

    // Remaining bytes use base-128 encoding
    let mut value: u32 = 0;
    for &byte in &bytes[1..] {
        value = (value << 7) | ((byte & 0x7f) as u32);
        if byte & 0x80 == 0 {
            components.push(value);
            value = 0;
        }
    }

    // Also show known OID names
    let dotted: String = components
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(".");
    let name = match dotted.as_str() {
        "1.2.840.113549.1.7.2" => "signedData",
        "1.2.840.113549.1.7.1" => "data",
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.2.5" => "md5",
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.156.10197.1.501" => "sm3WithSM2",
        "1.2.156.10197.1.301" => "sm2",
        "1.2.156.10197.1.401" => "sm3",
        "1.2.840.113549.1.9.3" => "contentType",
        "1.2.840.113549.1.9.4" => "messageDigest",
        "1.2.840.113549.1.9.5" => "signingTime",
        "1.2.840.113549.1.9.16.2.47" => "signingCertificateV2",
        _ => "",
    };

    if name.is_empty() {
        dotted
    } else {
        format!("{} ({})", dotted, name)
    }
}

/// Format X.500 Distinguished Name (RdnSequence) as human-readable string
/// e.g. "CN=Example User, O=Example Corp, C=CN"
fn format_distinguished_name(name: &x509_cert::name::Name) -> String {
    use der::Encode;

    let mut parts = Vec::new();

    // Iterate through RDN sets
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            // Get the attribute type OID
            let oid_bytes = atv.oid.as_bytes();
            let attr_name = match format_oid(oid_bytes).as_str() {
                "2.5.4.3" | "2.5.4.3 (commonName)" => "CN",
                "2.5.4.6" | "2.5.4.6 (countryName)" => "C",
                "2.5.4.7" | "2.5.4.7 (localityName)" => "L",
                "2.5.4.8" | "2.5.4.8 (stateOrProvinceName)" => "ST",
                "2.5.4.10" | "2.5.4.10 (organizationName)" => "O",
                "2.5.4.11" | "2.5.4.11 (organizationalUnitName)" => "OU",
                "1.2.840.113549.1.9.1" => "E", // emailAddress
                _ => {
                    // For unknown OIDs, use the dotted decimal
                    let oid_str = format_oid(oid_bytes);
                    parts.push(format!("{}=?", oid_str));
                    continue;
                }
            };

            // Try to decode the value as UTF8String, PrintableString, or IA5String
            let value = if let Ok(bytes) = atv.value.to_der() {
                // The DER encoding includes tag and length, we need the actual string content
                // Tag: 0x13 = PrintableString, 0x0C = UTF8String, 0x16 = IA5String
                if bytes.len() >= 2 {
                    let tag = bytes[0];
                    let len = bytes[1] as usize;
                    if bytes.len() >= 2 + len {
                        let str_bytes = &bytes[2..2 + len];
                        match tag {
                            0x0C | 0x13 | 0x16 | 0x1E => {
                                // UTF8String, PrintableString, IA5String, or BMPString
                                String::from_utf8_lossy(str_bytes).to_string()
                            }
                            _ => {
                                // Unknown encoding, try as UTF-8 anyway
                                String::from_utf8_lossy(str_bytes).to_string()
                            }
                        }
                    } else {
                        format!("{:?}", atv.value)
                    }
                } else {
                    format!("{:?}", atv.value)
                }
            } else {
                format!("{:?}", atv.value)
            };

            parts.push(format!("{}={}", attr_name, value));
        }
    }

    if parts.is_empty() {
        "Unknown".to_string()
    } else {
        parts.join(", ")
    }
}

// SM2 curve parameters (sm2p256v1) - defined as const to avoid runtime allocation
// These are fixed values from the GM/T 0003 standard
const SM2_PARAM_A: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
];
const SM2_PARAM_B: [u8; 32] = [
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
];
const SM2_PARAM_XG: [u8; 32] = [
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
];
const SM2_PARAM_YG: [u8; 32] = [
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
];

/// Calculate SM2 Z value according to GM/T 0003.2-2012
/// Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
pub fn calculate_sm2_z_value(public_key: &[u8], user_id: &[u8]) -> Vec<u8> {
    // Extract xA, yA from public key (skip 0x04 prefix if present for uncompressed point)
    let (x_a, y_a) = if public_key.len() == 65 && public_key[0] == 0x04 {
        (&public_key[1..33], &public_key[33..65])
    } else if public_key.len() == 64 {
        (&public_key[0..32], &public_key[32..64])
    } else {
        // If we can't parse, use zeros (this will produce wrong hash but won't crash)
        return vec![0u8; 32];
    };

    // ENTL = bit length of ID as 2 bytes
    let entl = ((user_id.len() * 8) as u16).to_be_bytes();

    // Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
    let mut z_input = Vec::with_capacity(2 + user_id.len() + 32 * 6);
    z_input.extend_from_slice(&entl);
    z_input.extend_from_slice(user_id);
    z_input.extend_from_slice(&SM2_PARAM_A);
    z_input.extend_from_slice(&SM2_PARAM_B);
    z_input.extend_from_slice(&SM2_PARAM_XG);
    z_input.extend_from_slice(&SM2_PARAM_YG);
    z_input.extend_from_slice(x_a);
    z_input.extend_from_slice(y_a);

    let mut hasher = libsm::sm3::hash::Sm3Hash::new(&z_input);
    hasher.get_hash().to_vec()
}

/// Calculate hash of raw bytes
pub fn calculate_hash_of_bytes(data: &[u8], algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        Algorithm::Sha512 => {
            use sha2::Sha512;
            let mut hasher = Sha512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        Algorithm::Sha3_256 => {
            use sha3::Sha3_256;
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        Algorithm::Sha3_512 => {
            use sha3::Sha3_512;
            let mut hasher = Sha3_512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        Algorithm::Sha1 => {
            use sha1::Sha1;
            let mut hasher = Sha1::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        Algorithm::Md5 => {
            use md5::Md5;
            let mut hasher = Md5::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        Algorithm::Blake3 => {
            let hash = blake3::hash(data);
            hash.to_hex().to_string()
        }
        Algorithm::Sm3 => {
            use sm3::{Digest as Sm3Digest, Sm3};
            let mut hasher = Sm3::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
    }
}

/// Extract all signature information from a PDF file
pub fn extract_signatures<P: AsRef<Path>>(
    pdf_path: P,
) -> Result<Vec<SignatureInfo>, PdfSignatureError> {
    let doc = Document::load(pdf_path.as_ref())?;
    let mut signatures = Vec::new();

    // Iterate through all objects to find signature dictionaries
    for (object_id, object) in doc.objects.iter() {
        if let Object::Dictionary(dict) = object {
            // Check if this is a signature dictionary
            let is_sig = dict
                .get(b"Type")
                .map(|t| matches!(t, Object::Name(n) if n == b"Sig"))
                .unwrap_or(false);

            // Also check for signature value field (some PDFs don't have Type)
            let has_contents = dict.get(b"Contents").is_ok();
            let has_byte_range = dict.get(b"ByteRange").is_ok();

            if is_sig || (has_contents && has_byte_range) {
                if let Ok(Some(sig_info)) = SignatureInfo::from_sig_dict(*object_id, dict) {
                    signatures.push(sig_info);
                }
            }
        }
    }

    Ok(signatures)
}

/// Extract annotation stream data from PDF and calculate their SM3 hashes
/// Signature appearance annotations have names like <UUID>-VISIBLE
#[allow(dead_code)]
pub fn extract_annotation_hashes<P: AsRef<Path>>(
    pdf_path: P,
) -> Result<Vec<(String, String)>, PdfSignatureError> {
    let doc = Document::load(pdf_path.as_ref())?;
    let mut hashes = Vec::new();

    // Iterate through all objects looking for annotation-related streams
    for (object_id, object) in doc.objects.iter() {
        match object {
            // Look for streams that might be annotation appearances
            Object::Stream(stream) => {
                // Check if this stream has a name containing "VISIBLE" or looks like a UUID
                let name = stream.dict.get(b"Name").ok().and_then(|n| match n {
                    Object::Name(bytes) => String::from_utf8(bytes.clone()).ok(),
                    _ => None,
                });

                // Also check for /Type = /XObject and /Subtype = /Form (appearance streams)
                let is_form = stream
                    .dict
                    .get(b"Subtype")
                    .ok()
                    .map(|s| matches!(s, Object::Name(n) if n == b"Form"))
                    .unwrap_or(false);

                // Get any identifier
                let id_str = if let Some(ref n) = name {
                    format!("{} @{},{}", n, object_id.0, object_id.1)
                } else if is_form {
                    format!("Form @{},{}", object_id.0, object_id.1)
                } else {
                    continue; // Skip non-form, non-named streams
                };

                // Calculate SM3 hash of stream content
                if !stream.content.is_empty() {
                    let mut hasher = libsm::sm3::hash::Sm3Hash::new(&stream.content);
                    let hash = hasher.get_hash();
                    hashes.push((id_str, hex::encode(hash)));
                }
            }
            // Also look for dictionaries with /AP field (widget annotations)
            Object::Dictionary(dict) => {
                // Check if this has /NM (annotation name) field
                let annot_name = dict.get(b"NM").ok().and_then(|n| match n {
                    Object::String(bytes, _) => String::from_utf8(bytes.clone()).ok(),
                    _ => None,
                });

                // If annotation name contains VISIBLE, try to get its /AP stream
                if let Some(ref nm) = annot_name {
                    if nm.contains("VISIBLE") || nm.contains("-") {
                        // Try to get /AP/N stream
                        if let Ok(Object::Dictionary(ap_dict)) = dict.get(b"AP") {
                            if let Ok(n) = ap_dict.get(b"N") {
                                let stream_data = match n {
                                    Object::Reference(ref_id) => {
                                        if let Ok(Object::Stream(s)) = doc.get_object(*ref_id) {
                                            Some((ref_id.0, s.content.clone()))
                                        } else {
                                            None
                                        }
                                    }
                                    Object::Stream(s) => Some((object_id.0, s.content.clone())),
                                    _ => None,
                                };

                                if let Some((stream_id, content)) = stream_data {
                                    if !content.is_empty() {
                                        let mut hasher = libsm::sm3::hash::Sm3Hash::new(&content);
                                        let hash = hasher.get_hash();
                                        hashes.push((
                                            format!("{} @{}", nm, stream_id),
                                            hex::encode(hash),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(hashes)
}

/// Calculate the hash of the signed content using raw file bytes
///
/// # Important
/// This function reads directly from the raw binary file, NOT from lopdf's
/// parsed representation. This is critical because PDF parsers may normalize
/// content which would change the hash.
const BYTE_RANGE_CHUNK_SIZE: usize = 64 * 1024;

/// Visit each ByteRange byte sequence without allocating based on PDF-controlled lengths.
fn stream_byte_range_contents<F>(
    path: &Path,
    byte_range: &ByteRange,
    mut consume: F,
) -> Result<(), PdfSignatureError>
where
    F: FnMut(&[u8]),
{
    let file_size = fs::metadata(path)?.len();
    byte_range.validate_file_size(file_size)?;

    let mut file = fs::File::open(path)?;
    let mut buffer = [0u8; BYTE_RANGE_CHUNK_SIZE];

    for (offset, length) in &byte_range.ranges {
        file.seek(SeekFrom::Start(*offset))?;
        let mut remaining = *length;
        while remaining > 0 {
            let chunk_len = remaining.min(BYTE_RANGE_CHUNK_SIZE as u64) as usize;
            file.read_exact(&mut buffer[..chunk_len])?;
            consume(&buffer[..chunk_len]);
            remaining -= chunk_len as u64;
        }
    }

    Ok(())
}

fn calculate_byte_range_digest<D>(
    path: &Path,
    byte_range: &ByteRange,
) -> Result<String, PdfSignatureError>
where
    D: Digest + Default,
{
    let mut hasher = D::default();
    stream_byte_range_contents(path, byte_range, |chunk| hasher.update(chunk))?;
    Ok(hex::encode(hasher.finalize()))
}

pub fn calculate_signature_hash<P: AsRef<Path>>(
    pdf_path: P,
    byte_range: &ByteRange,
    algorithm: Algorithm,
) -> Result<String, PdfSignatureError> {
    let path = pdf_path.as_ref();

    match algorithm {
        Algorithm::Sha256 => calculate_byte_range_digest::<Sha256>(path, byte_range),
        Algorithm::Sha512 => calculate_byte_range_digest::<sha2::Sha512>(path, byte_range),
        Algorithm::Sha3_256 => calculate_byte_range_digest::<sha3::Sha3_256>(path, byte_range),
        Algorithm::Sha3_512 => calculate_byte_range_digest::<sha3::Sha3_512>(path, byte_range),
        Algorithm::Sha1 => calculate_byte_range_digest::<sha1::Sha1>(path, byte_range),
        Algorithm::Md5 => calculate_byte_range_digest::<md5::Md5>(path, byte_range),
        Algorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            stream_byte_range_contents(path, byte_range, |chunk| {
                hasher.update(chunk);
            })?;
            Ok(hasher.finalize().to_hex().to_string())
        }
        Algorithm::Sm3 => calculate_byte_range_digest::<sm3::Sm3>(path, byte_range),
    }
}

/// Convenience function to get all signature hashes from a PDF
///
/// This function automatically uses the correct hash algorithm based on
/// the detected signature algorithm (e.g., SM3 for SM3withSM2).
pub fn get_all_signature_hashes<P: AsRef<Path>>(
    pdf_path: P,
    _fallback_algorithm: Algorithm, // Kept for API compatibility but not used
) -> Result<Vec<(SignatureInfo, String)>, PdfSignatureError> {
    let signatures = extract_signatures(&pdf_path)?;

    if signatures.is_empty() {
        return Err(PdfSignatureError::NoSignatures);
    }

    let mut results = Vec::new();
    for sig in signatures {
        // Use the detected algorithm from the signature, not the passed-in one
        let algorithm = sig.algorithm.hash_algorithm();
        // Handle ByteRange errors gracefully - show signature with error message
        let hash = match calculate_signature_hash(&pdf_path, &sig.byte_range, algorithm) {
            Ok(h) => h,
            Err(e) => format!("Error: {}", e),
        };
        results.push((sig, hash));
    }

    Ok(results)
}

/// Get all signature hashes with an optional algorithm override
///
/// This allows users to force a specific hash algorithm when auto-detection
/// doesn't match the actual algorithm used (e.g., when PDF metadata is incorrect).
pub fn get_all_signature_hashes_with_override<P: AsRef<Path> + Sync>(
    pdf_path: P,
    override_algo: crate::PdfHashOverride,
) -> Result<Vec<(SignatureInfo, String)>, PdfSignatureError> {
    use rayon::prelude::*;

    let signatures = extract_signatures(&pdf_path)?;

    if signatures.is_empty() {
        return Err(PdfSignatureError::NoSignatures);
    }

    // Use Rayon parallel iterator for multi-signature PDFs
    let results: Vec<(SignatureInfo, String)> = signatures
        .into_par_iter()
        .map(|sig| {
            // Determine which algorithm to use and calculate hash
            let hash = match override_algo {
                crate::PdfHashOverride::ForceSm3WithSm2 => {
                    match sig.calculate_sm3_with_sm2_hash_from_byte_range(pdf_path.as_ref()) {
                        Ok(hash) => hash,
                        Err(error) => format!("Error: {}", error),
                    }
                }
                _ => {
                    // Normal hash algorithms
                    let algorithm = match override_algo {
                        crate::PdfHashOverride::Auto => sig.algorithm.hash_algorithm(),
                        crate::PdfHashOverride::ForceSha256 => Algorithm::Sha256,
                        crate::PdfHashOverride::ForceSm3 => Algorithm::Sm3,
                        crate::PdfHashOverride::ForceSha1 => Algorithm::Sha1,
                        crate::PdfHashOverride::ForceSm3WithSm2 => unreachable!(),
                    };
                    // Handle ByteRange errors gracefully - show signature with error
                    match calculate_signature_hash(&pdf_path, &sig.byte_range, algorithm) {
                        Ok(h) => h,
                        Err(e) => format!("Error: {}", e),
                    }
                }
            };
            (sig, hash) // Return tuple for Rayon collect
        })
        .collect();

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_synthetic_input(bytes: &[u8]) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hash-tools-byte-range-{}-{}.bin",
            std::process::id(),
            unique
        ));
        fs::write(&path, bytes).expect("write synthetic byte-range input");
        path
    }

    #[test]
    fn test_byte_range_parsing() {
        let obj = Object::Array(vec![
            Object::Integer(0),
            Object::Integer(500),
            Object::Integer(700),
            Object::Integer(1000),
        ]);

        let byte_range = ByteRange::from_object(&obj).unwrap();
        assert_eq!(byte_range.ranges.len(), 2);
        assert_eq!(byte_range.ranges[0], (0, 500));
        assert_eq!(byte_range.ranges[1], (700, 1000));
        assert_eq!(byte_range.total_bytes().unwrap(), 1500);
    }

    #[test]
    fn test_invalid_byte_range() {
        // Odd number of elements
        let obj = Object::Array(vec![
            Object::Integer(0),
            Object::Integer(500),
            Object::Integer(700),
        ]);

        assert!(ByteRange::from_object(&obj).is_err());
    }

    #[test]
    fn cades_metadata_requires_cms_oid_detection() {
        assert!(matches!(
            SignatureAlgorithm::from_pdf_filters(None, Some("ETSI.CAdES.detached")),
            SignatureAlgorithm::Unknown(sub_filter) if sub_filter == "ETSI.CAdES.detached"
        ));

        // rsaEncryption with SHA-512 OID: 1.2.840.113549.1.1.13
        assert_eq!(
            SignatureAlgorithm::from_signature_algorithm_oid(&[
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
            ]),
            Some(SignatureAlgorithm::Sha512WithRsa)
        );
    }

    #[test]
    fn byte_range_rejects_negative_and_non_integer_values() {
        let negative = Object::Array(vec![
            Object::Integer(0),
            Object::Integer(5),
            Object::Integer(-1),
            Object::Integer(2),
        ]);
        let real = Object::Array(vec![
            Object::Integer(0),
            Object::Integer(5),
            Object::Real(7.0),
            Object::Integer(2),
        ]);

        assert!(matches!(
            ByteRange::from_object(&negative),
            Err(PdfSignatureError::InvalidByteRange)
        ));
        assert!(matches!(
            ByteRange::from_object(&real),
            Err(PdfSignatureError::InvalidByteRange)
        ));
    }

    #[test]
    fn byte_range_hash_rejects_out_of_bounds_and_overflow() {
        let path = write_synthetic_input(b"01234567");
        let out_of_bounds = ByteRange {
            ranges: vec![(7, 2)],
        };
        let overflow = ByteRange {
            ranges: vec![(u64::MAX, 1)],
        };

        assert!(matches!(
            calculate_signature_hash(&path, &out_of_bounds, Algorithm::Sha256),
            Err(PdfSignatureError::ByteRangeOutOfBounds)
        ));
        assert!(matches!(
            calculate_signature_hash(&path, &overflow, Algorithm::Sha256),
            Err(PdfSignatureError::ByteRangeOutOfBounds)
        ));

        fs::remove_file(path).expect("remove synthetic byte-range input");
    }

    #[test]
    fn byte_range_rejects_total_length_overflow() {
        let byte_range = ByteRange {
            ranges: vec![(0, u64::MAX), (0, 1)],
        };

        assert!(matches!(
            byte_range.total_bytes(),
            Err(PdfSignatureError::ByteRangeOutOfBounds)
        ));
    }

    #[test]
    fn byte_range_hash_streams_multiple_chunks() {
        let mut bytes = vec![b'a'; BYTE_RANGE_CHUNK_SIZE + 17];
        bytes.extend_from_slice(b"suffix");
        let path = write_synthetic_input(&bytes);
        let byte_range = ByteRange {
            ranges: vec![
                (0, BYTE_RANGE_CHUNK_SIZE as u64 + 17),
                (bytes.len() as u64 - 6, 6),
            ],
        };
        let mut expected_bytes = vec![b'a'; BYTE_RANGE_CHUNK_SIZE + 17];
        expected_bytes.extend_from_slice(b"suffix");

        for &algorithm in Algorithm::all() {
            assert_eq!(
                calculate_signature_hash(&path, &byte_range, algorithm).unwrap(),
                calculate_hash_of_bytes(&expected_bytes, algorithm),
                "{algorithm}"
            );
        }

        fs::remove_file(path).expect("remove synthetic byte-range input");
    }

    #[tokio::test]
    async fn supported_digest_known_answer_vectors() {
        let input = b"abc";
        let expected = [
            (
                Algorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Algorithm::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                Algorithm::Sha3_256,
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            ),
            (
                Algorithm::Sha3_512,
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            ),
            (Algorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            (Algorithm::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                Algorithm::Blake3,
                "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            ),
            (
                Algorithm::Sm3,
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            ),
        ];

        let file_path = write_synthetic_input(input);
        let range_path = write_synthetic_input(b"a<excluded>bc");
        let byte_range = ByteRange {
            ranges: vec![(0, 1), (11, 2)],
        };
        for (algorithm, digest) in expected {
            assert_eq!(
                calculate_hash_of_bytes(input, algorithm),
                digest,
                "{algorithm}"
            );
            assert_eq!(
                crate::hash_logic::compute_hash(&file_path, algorithm)
                    .await
                    .unwrap(),
                digest,
                "{algorithm}"
            );
            assert_eq!(
                calculate_signature_hash(&range_path, &byte_range, algorithm).unwrap(),
                digest,
                "{algorithm}"
            );
        }
        fs::remove_file(file_path).unwrap();
        fs::remove_file(range_path).unwrap();
    }

    #[test]
    fn sm2_default_id_z_and_der_signature_known_answer() {
        // Public SM2 "message digest" test vector; no private key is required.
        let public_key = hex::decode(concat!(
            "04",
            "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020",
            "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
        ))
        .unwrap();
        let signature_der = hex::decode(concat!(
            "3046022100f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3",
            "022100b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
        ))
        .unwrap();
        let expected_z = "b2e14c5c79c6df5b85f4fe7ed8db7a262b9da7e07ccb0ea9f4747b8ccda8a4f3";
        assert_eq!(
            hex::encode(calculate_sm2_z_value(&public_key, b"1234567812345678")),
            expected_z
        );
        assert_eq!(
            hex::encode(calculate_sm2_z_value(&public_key[1..], b"1234567812345678")),
            expected_z
        );
        assert_ne!(
            calculate_sm2_z_value(&public_key, b"another user"),
            hex::decode(expected_z).unwrap()
        );

        let context = libsm::sm2::signature::SigCtx::new();
        let point = context.load_pubkey(&public_key).unwrap();
        let signature = libsm::sm2::signature::Signature::der_decode(&signature_der).unwrap();
        assert_eq!(signature.der_encode(), signature_der);
        assert!(context
            .verify(b"message digest", &point, &signature)
            .unwrap());
        assert!(!context
            .verify(b"message digesu", &point, &signature)
            .unwrap());
        // verify() must receive the message, not an already Z-prefixed digest.
        let digest = context
            .hash("1234567812345678", &point, b"message digest")
            .unwrap();
        assert!(!context.verify(&digest, &point, &signature).unwrap());
        assert!(libsm::sm2::signature::Signature::der_decode(&signature_der[2..]).is_err());
    }

    #[test]
    fn pdf_parser_preserves_signature_contents_and_raw_ranges() {
        // Construct bytes directly, not via lopdf's writer: parser upgrades must not
        // normalize the signed input or change literal/hex /Contents extraction.
        let mut pdf = b"%PDF-1.4\r\n".to_vec();
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [] /Count 0 >>",
            "<< /Type /Sig /ByteRange [0 5 7 2] /Contents <30030201010000> /SubFilter /SM3withSM2 /Name (Synthetic signer) /Reason (Testing) /Location (Local) /M (D:20250101000000Z) >>",
            "<< /ByteRange [0 5 7 2] /Contents (\\060\\003\\002\\001\\001\\000\\000) /SubFilter /adbe.pkcs7.detached >>",
        ];
        let mut offsets = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(
                format!("{} 0 obj\r\n{}\r\nendobj\r\n", index + 1, object).as_bytes(),
            );
        }
        let xref_offset = pdf.len();
        pdf.extend_from_slice(b"xref\r\n0 5\r\n0000000000 65535 f\r\n");
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n\r\n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\r\n<< /Size 5 /Root 1 0 R >>\r\nstartxref\r\n{xref_offset}\r\n%%EOF\r\n"
            )
            .as_bytes(),
        );
        let path = write_synthetic_input(&pdf);
        let signatures = extract_signatures(&path).unwrap();
        assert_eq!(signatures.len(), 2);
        for signature in &signatures {
            assert_eq!(signature.byte_range.ranges, vec![(0, 5), (7, 2)]);
            assert_eq!(signature.signature_contents, [0x30, 3, 2, 1, 1, 0, 0]);
            assert_eq!(
                calculate_signature_hash(&path, &signature.byte_range, Algorithm::Sha256).unwrap(),
                calculate_hash_of_bytes(b"%PDF-4\r", Algorithm::Sha256)
            );
        }
        assert_eq!(signatures[0].algorithm, SignatureAlgorithm::Sm3WithSm2);
        assert_eq!(
            signatures[0].signer_name.as_deref(),
            Some("Synthetic signer")
        );
        assert_eq!(signatures[0].reason.as_deref(), Some("Testing"));
        assert_eq!(signatures[0].location.as_deref(), Some("Local"));
        assert_eq!(
            signatures[0].sign_date.as_deref(),
            Some("D:20250101000000Z")
        );
        assert_eq!(
            signatures[1].algorithm,
            SignatureAlgorithm::Unknown("adbe.pkcs7.detached".into())
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn non_sm2_digest_match_is_not_a_signature_verification() {
        let mut result = SignatureVerificationResult {
            is_valid: true,
            hash_valid: true,
            signature_valid: true,
            signature_verification_supported: true,
            algorithm: "Sha256WithRsa".to_string(),
            calculated_hash: "a".repeat(64),
            embedded_hash: "a".repeat(64),
            error: None,
        };

        result.mark_signature_verification_unavailable(&SignatureAlgorithm::Sha256WithRsa);

        assert!(result.hash_valid);
        assert!(!result.signature_verification_supported);
        assert!(!result.signature_valid);
        assert!(!result.is_valid);
        assert!(result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("messageDigest matches")));
    }
}
