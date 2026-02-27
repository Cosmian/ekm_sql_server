//! Cosmian KMS client integration for the EKM provider.
//!
//! This module handles:
//! - Constructing a [`KmsClient`] with mTLS authentication
//! - Validating that the SQL Server username matches the client certificate's
//!   Subject CN or Subject Alternative Name
//! - Creating symmetric (AES) and asymmetric (RSA) keys on the Cosmian KMS
//! - Converting KMS unique identifiers to/from SQL Server key thumbprints
//!
//! All KMIP operations are **async** internally; this module drives them on
//! a per-call `tokio::runtime::Runtime` so the synchronous EKM entry points
//! in `lib.rs` can call them directly.

use crate::config::{ClientCertEntry, KmsConfig};
use cosmian_http_client::HttpClientConfig;
use cosmian_kms_client::{KmsClient, KmsClientConfig};
use tracing::info;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during KMS operations.
#[derive(Debug)]
pub enum KmsError {
    /// No `[[kms.certificates]]` entry found for this SQL login.
    NoCertForUser(String),
    /// Could not read or parse the client certificate PEM file.
    CertReadError(String),
    /// The certificate's Subject CN / SAN does not match the SQL login.
    CnMismatch { expected: String, found: String },
    /// `KmsClient` construction failed (network / TLS error).
    ClientBuildError(String),
    /// KMIP Create / CreateKeyPair failed.
    CreateKeyError(String),
    /// The unique identifier returned by the KMS is not a valid UUID.
    InvalidUniqueId(String),
    /// A required configuration value is missing.
    ConfigError(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCertForUser(u) => {
                write!(f, "no client certificate configured for user '{u}'")
            }
            Self::CertReadError(e) => write!(f, "failed to read client certificate: {e}"),
            Self::CnMismatch { expected, found } => {
                write!(
                    f,
                    "certificate CN/SAN mismatch: expected '{expected}', found '{found}'"
                )
            }
            Self::ClientBuildError(e) => write!(f, "failed to build KMS client: {e}"),
            Self::CreateKeyError(e) => write!(f, "key creation failed on KMS: {e}"),
            Self::InvalidUniqueId(e) => write!(f, "invalid unique identifier from KMS: {e}"),
            Self::ConfigError(e) => write!(f, "KMS configuration error: {e}"),
        }
    }
}

impl std::error::Error for KmsError {}

// ---------------------------------------------------------------------------
// Certificate identity validation
// ---------------------------------------------------------------------------

/// Validates that the client certificate's Subject CN or Subject Alternative
/// Names contain the expected `username` (case-insensitive comparison).
fn validate_cert_identity(cert_path: &str, expected_username: &str) -> Result<(), KmsError> {
    use x509_cert::der::DecodePem;
    use x509_cert::Certificate;

    let pem_data = std::fs::read_to_string(cert_path)
        .map_err(|e| KmsError::CertReadError(format!("{cert_path}: {e}")))?;

    let cert = Certificate::from_pem(pem_data.as_bytes())
        .map_err(|e| KmsError::CertReadError(format!("PEM parse error for {cert_path}: {e}")))?;

    // ---- Check Subject CN (OID 2.5.4.3) ----
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            // CN OID = 2.5.4.3
            if atv.oid.to_string() == "2.5.4.3" {
                // DER value octets for UTF8String / PrintableString are the
                // raw string bytes — safe to interpret as UTF-8.
                if let Ok(cn) = std::str::from_utf8(atv.value.value()) {
                    if cn.eq_ignore_ascii_case(expected_username) {
                        info!(cert_path, cn, "certificate CN matches username");
                        return Ok(());
                    }
                }
            }
        }
    }

    // ---- Check Subject Alternative Names (OID 2.5.29.17) ----
    // Best-effort: scan the raw DER extension value for the username as an
    // ASCII substring.  DNS names and email addresses are IA5String-encoded
    // inside DER GeneralName entries, so an ASCII username will appear
    // verbatim in the byte stream.
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id.to_string() == "2.5.29.17" {
                let san_text = String::from_utf8_lossy(ext.extn_value.as_bytes());
                if san_text
                    .to_lowercase()
                    .contains(&expected_username.to_lowercase())
                {
                    info!(
                        cert_path,
                        expected_username, "certificate SAN contains username"
                    );
                    return Ok(());
                }
            }
        }
    }

    // Collect CNs found for a helpful error message.
    let found_cns: Vec<String> = cert
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|atv| atv.oid.to_string() == "2.5.4.3")
        .filter_map(|atv| std::str::from_utf8(atv.value.value()).ok().map(String::from))
        .collect();

    Err(KmsError::CnMismatch {
        expected: expected_username.to_string(),
        found: if found_cns.is_empty() {
            "(no CN found in certificate)".to_string()
        } else {
            found_cns.join(", ")
        },
    })
}

// ---------------------------------------------------------------------------
// KMS client construction
// ---------------------------------------------------------------------------

/// Build a `KmsClient` configured for mTLS using the given certificate entry.
fn build_kms_client(
    kms_config: &KmsConfig,
    cert_entry: &ClientCertEntry,
) -> Result<KmsClient, KmsError> {
    let server_url = kms_config
        .server_url
        .as_deref()
        .ok_or_else(|| KmsError::ConfigError("kms.server_url not set in config.toml".into()))?;

    let http_config = HttpClientConfig {
        server_url: server_url.to_string(),
        accept_invalid_certs: kms_config.accept_invalid_certs,
        ssl_client_pem_cert_path: Some(cert_entry.client_cert.clone()),
        ssl_client_pem_key_path: Some(cert_entry.client_key.clone()),
        ..Default::default()
    };

    let config = KmsClientConfig {
        http_config,
        gmail_api_conf: None,
        print_json: Some(false),
    };

    KmsClient::new_with_config(config).map_err(|e| KmsError::ClientBuildError(e.to_string()))
}

// ---------------------------------------------------------------------------
// UUID ↔ thumbprint byte conversion
// ---------------------------------------------------------------------------

/// Parse a UUID string (with or without hyphens) into 16 raw bytes.
///
/// The Cosmian KMS returns object unique identifiers as UUID strings;
/// SQL Server expects a 16-byte opaque thumbprint.
fn uuid_str_to_bytes(uuid_str: &str) -> Result<[u8; 16], KmsError> {
    let hex: String = uuid_str
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() != 32 {
        return Err(KmsError::InvalidUniqueId(format!(
            "expected 32 hex digits, got {} from '{uuid_str}'",
            hex.len()
        )));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| KmsError::InvalidUniqueId(e.to_string()))?;
    }
    Ok(bytes)
}

/// Convert 16 thumbprint bytes back to a UUID string (for future KMS
/// operations such as Encrypt/Decrypt/Destroy).
#[allow(dead_code)]
pub fn thumbprint_to_uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 16 {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

// ---------------------------------------------------------------------------
// Key creation
// ---------------------------------------------------------------------------

/// Create a key on the Cosmian KMS.
///
/// For symmetric algorithms (AES), uses KMIP `Create` with
/// `ObjectType::SymmetricKey`.  For asymmetric algorithms (RSA), uses KMIP
/// `CreateKeyPair` and returns the **private key** unique identifier as the
/// thumbprint.
///
/// Returns a 16-byte thumbprint derived from the KMS unique identifier.
pub fn create_key(
    kms_config: &KmsConfig,
    username: &str,
    key_name: &str,
    is_symmetric: bool,
    bit_len: u32,
) -> Result<[u8; 16], KmsError> {
    // 1. Find certificate entry for this username
    let cert_entry = kms_config
        .certificates
        .iter()
        .find(|c| c.username.eq_ignore_ascii_case(username))
        .ok_or_else(|| KmsError::NoCertForUser(username.to_string()))?;

    // 2. Validate certificate CN/SAN matches the SQL login
    validate_cert_identity(&cert_entry.client_cert, username)?;

    // 3. Build KMS client with mTLS
    let kms_client = build_kms_client(kms_config, cert_entry)?;

    // 4. Create key via KMIP (sync wrapper around async operations)
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KmsError::CreateKeyError(format!("tokio runtime: {e}")))?;

    let unique_id = if is_symmetric {
        rt.block_on(create_symmetric_key(&kms_client, key_name, bit_len))?
    } else {
        rt.block_on(create_asymmetric_key_pair(&kms_client, key_name, bit_len))?
    };

    info!(
        unique_id = %unique_id,
        key_name,
        username,
        is_symmetric,
        bit_len,
        "Key created on Cosmian KMS"
    );

    // 5. Convert the KMIP unique-ID (UUID string) to a 16-byte thumbprint
    uuid_str_to_bytes(&unique_id)
}

// ---------------------------------------------------------------------------
// KMIP async helpers
// ---------------------------------------------------------------------------

/// Create a symmetric key (AES) via the KMIP `Create` operation.
/// The KMS generates the key material server-side.
async fn create_symmetric_key(
    client: &KmsClient,
    _key_name: &str,
    bit_len: u32,
) -> Result<String, KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::CryptographicUsageMask;
    use cosmian_kms_client::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::Create,
        kmip_types::CryptographicAlgorithm,
    };

    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(bit_len as i32),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    let request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    let response = client
        .create(request)
        .await
        .map_err(|e| KmsError::CreateKeyError(e.to_string()))?;

    Ok(response.unique_identifier.to_string())
}

/// Create an asymmetric key pair (RSA) via the KMIP `CreateKeyPair` operation.
/// Returns the **private key** unique identifier.
async fn create_asymmetric_key_pair(
    client: &KmsClient,
    _key_name: &str,
    bit_len: u32,
) -> Result<String, KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::CryptographicUsageMask;
    use cosmian_kms_client::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_operations::CreateKeyPair,
        kmip_types::CryptographicAlgorithm,
    };

    let common_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(bit_len as i32),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey,
        ),
        ..Default::default()
    };

    let request = CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: None,
        public_key_attributes: None,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let response = client
        .create_key_pair(request)
        .await
        .map_err(|e| KmsError::CreateKeyError(e.to_string()))?;

    // Return the private-key unique identifier as the canonical key ID.
    Ok(response.private_key_unique_identifier.to_string())
}
