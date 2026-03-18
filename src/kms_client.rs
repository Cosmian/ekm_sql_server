//! Cosmian KMS client integration for the EKM provider.
//!
//! This module handles:
//! - Constructing a [`KmsClient`] with mTLS authentication (cached per username)
//! - Validating that the SQL Server username matches the client certificate's
//!   Subject CN or Subject Alternative Name
//! - Creating symmetric (AES) and asymmetric (RSA) keys on the Cosmian KMS
//! - Converting KMS unique identifiers to/from SQL Server key thumbprints
//! - Encrypting / decrypting data entirely server-side via KMIP
//!
//! RSA operations use the Cosmian KMS KMIP `Encrypt`/`Decrypt` endpoints with
//! RSA-OAEP-SHA256 parameters.  The public key is addressed as
//! `<private_key_uuid>_pk`; the private key UUID is used for decryption.
//!
//! All KMIP operations are **async** internally; this module drives them on
//! a per-call `tokio::runtime::Runtime` so the synchronous EKM entry points
//! in `lib.rs` can call them directly.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

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
    /// KMIP Destroy / Revoke failed.
    DestroyKeyError(String),
    /// KMIP GetAttributes / Get failed.
    GetKeyError(String),
    /// KMIP Encrypt failed.
    EncryptError(String),
    /// KMIP Decrypt failed.
    DecryptError(String),
    /// KMIP Export failed.
    ExportError(String),
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
            Self::DestroyKeyError(e) => write!(f, "key destruction failed on KMS: {e}"),
            Self::GetKeyError(e) => write!(f, "get key info failed on KMS: {e}"),
            Self::EncryptError(e) => write!(f, "encryption failed on KMS: {e}"),
            Self::DecryptError(e) => write!(f, "decryption failed on KMS: {e}"),
            Self::ExportError(e) => write!(f, "key export failed on KMS: {e}"),
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
    use x509_cert::Certificate;
    use x509_cert::der::DecodePem;

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
                if let Ok(cn) = std::str::from_utf8(atv.value.value())
                    && cn.eq_ignore_ascii_case(expected_username)
                {
                    info!(cert_path, cn, "certificate CN matches username");
                    return Ok(());
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
        .filter_map(|atv| {
            std::str::from_utf8(atv.value.value())
                .ok()
                .map(String::from)
        })
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
// KMS client construction and caching
// ---------------------------------------------------------------------------

/// Per-username KMS client cache.  Each entry is an `Arc<KmsClient>` so
/// callers can cheaply clone the reference without rebuilding the HTTP stack.
static KMS_CLIENT_CACHE: OnceLock<RwLock<HashMap<String, Arc<KmsClient>>>> = OnceLock::new();

/// Return a cached `Arc<KmsClient>` for the given username, building one if
/// this is the first use.
fn get_kms_client(
    kms_config: &KmsConfig,
    cert_entry: &ClientCertEntry,
) -> Result<Arc<KmsClient>, KmsError> {
    let cache = KMS_CLIENT_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    let key = cert_entry.username.clone();

    // Fast path: already cached.
    {
        let guard = cache
            .read()
            .map_err(|_| KmsError::ClientBuildError("client cache lock poisoned".into()))?;
        if let Some(client) = guard.get(&key) {
            return Ok(Arc::clone(client));
        }
    }

    // Slow path: build, then insert.
    let client = Arc::new(build_kms_client(kms_config, cert_entry)?);
    {
        let mut guard = cache
            .write()
            .map_err(|_| KmsError::ClientBuildError("client cache lock poisoned".into()))?;
        guard.insert(key, Arc::clone(&client));
    }
    Ok(client)
}

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
pub fn uuid_str_to_bytes(uuid_str: &str) -> Result<[u8; 16], KmsError> {
    let hex: String = uuid_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
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

/// Convert 16 thumbprint bytes back to a UUID string (for KMS
/// operations such as Encrypt/Decrypt/Destroy).
pub fn thumbprint_to_uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 16 {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
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

    // 3. Build KMS client with mTLS (cached per username)
    let kms_client = get_kms_client(kms_config, cert_entry)?;

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
    key_name: &str,
    bit_len: u32,
) -> Result<String, KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::CryptographicUsageMask;
    use cosmian_kms_client::kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::ObjectType, kmip_operations::Create,
        kmip_types::CryptographicAlgorithm,
    };

    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(bit_len as i32),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };
    // Store the PROVIDER_KEY_NAME as a tag so we can retrieve it later.
    attributes
        .set_tags([key_name])
        .map_err(|e| KmsError::CreateKeyError(e.to_string()))?;

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
    key_name: &str,
    bit_len: u32,
) -> Result<String, KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::CryptographicUsageMask;
    use cosmian_kms_client::kmip_2_1::{
        kmip_attributes::Attributes, kmip_operations::CreateKeyPair,
        kmip_types::CryptographicAlgorithm,
    };

    let mut common_attributes = Attributes {
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
    // Store the PROVIDER_KEY_NAME as a tag so we can retrieve it later.
    common_attributes
        .set_tags([key_name])
        .map_err(|e| KmsError::CreateKeyError(e.to_string()))?;

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

// ---------------------------------------------------------------------------
// Key destruction
// ---------------------------------------------------------------------------

/// Revoke and destroy a key on the Cosmian KMS identified by its thumbprint.
pub fn destroy_key(
    kms_config: &KmsConfig,
    username: &str,
    thumb_bytes: &[u8],
) -> Result<(), KmsError> {
    let uuid = thumbprint_to_uuid(thumb_bytes)
        .ok_or_else(|| KmsError::InvalidUniqueId("thumbprint too short".into()))?;

    let cert_entry = kms_config
        .certificates
        .iter()
        .find(|c| c.username.eq_ignore_ascii_case(username))
        .ok_or_else(|| KmsError::NoCertForUser(username.to_string()))?;

    validate_cert_identity(&cert_entry.client_cert, username)?;
    let kms_client = get_kms_client(kms_config, cert_entry)?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KmsError::DestroyKeyError(format!("tokio runtime: {e}")))?;

    rt.block_on(async {
        use cosmian_kms_client::kmip_0::kmip_types::{RevocationReason, RevocationReasonCode};
        use cosmian_kms_client::kmip_2_1::{kmip_operations::Revoke, kmip_types::UniqueIdentifier};

        // Revoke first (required before Destroy on most KMIP servers)
        let revoke_req = Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uuid.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: Some("Dropped by SQL Server EKM".into()),
            },
            compromise_occurrence_date: None,
            cascade: true,
        };
        let _ = kms_client.revoke(revoke_req).await; // best-effort; may already be revoked

        use cosmian_kms_client::kmip_2_1::kmip_operations::Destroy;
        let destroy_req = Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(uuid.clone())),
            remove: false,
            cascade: true,
        };
        kms_client
            .destroy(destroy_req)
            .await
            .map_err(|e| KmsError::DestroyKeyError(e.to_string()))?;
        Ok(())
    })?;

    info!(uuid = %uuid, username, "Key destroyed on Cosmian KMS");
    Ok(())
}

// ---------------------------------------------------------------------------
// Key info retrieval
// ---------------------------------------------------------------------------

/// Metadata about a key returned by the KMS.
pub struct KeyInfo {
    #[allow(unused)]
    pub unique_id: String,
    /// The provider key name (the original PROVIDER_KEY_NAME from SQL Server).
    pub key_name: String,
    #[allow(unused)]
    pub algorithm_name: String,
    pub bit_len: u32,
    pub is_symmetric: bool,
}

/// Get key attributes from the KMS by unique identifier (UUID string).
pub fn get_key_info_by_id(
    kms_config: &KmsConfig,
    username: &str,
    uuid: &str,
) -> Result<KeyInfo, KmsError> {
    let cert_entry = kms_config
        .certificates
        .iter()
        .find(|c| c.username.eq_ignore_ascii_case(username))
        .ok_or_else(|| KmsError::NoCertForUser(username.to_string()))?;

    validate_cert_identity(&cert_entry.client_cert, username)?;
    let kms_client = get_kms_client(kms_config, cert_entry)?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KmsError::GetKeyError(format!("tokio runtime: {e}")))?;

    rt.block_on(get_key_info_async(&kms_client, uuid))
}

/// Get key attributes from the KMS by thumbprint bytes.
pub fn get_key_info_by_thumb(
    kms_config: &KmsConfig,
    username: &str,
    thumb_bytes: &[u8],
) -> Result<KeyInfo, KmsError> {
    let uuid = thumbprint_to_uuid(thumb_bytes)
        .ok_or_else(|| KmsError::InvalidUniqueId("thumbprint too short".into()))?;
    get_key_info_by_id(kms_config, username, &uuid)
}

async fn get_key_info_async(client: &KmsClient, uuid: &str) -> Result<KeyInfo, KmsError> {
    use cosmian_kms_client::kmip_2_1::{
        kmip_operations::GetAttributes, kmip_types::UniqueIdentifier,
    };

    let request = GetAttributes {
        unique_identifier: Some(UniqueIdentifier::TextString(uuid.to_string())),
        attribute_reference: None,
    };

    let response = client
        .get_attributes(request)
        .await
        .map_err(|e| KmsError::GetKeyError(e.to_string()))?;

    let attrs = &response.attributes;

    let algorithm_name = attrs
        .cryptographic_algorithm
        .as_ref()
        .map(|a| format!("{a:?}"))
        .unwrap_or_default();

    let bit_len = attrs.cryptographic_length.unwrap_or(0) as u32;

    let is_symmetric = attrs
        .object_type
        .as_ref()
        .map(|ot| {
            use cosmian_kms_client::kmip_2_1::kmip_objects::ObjectType;
            *ot == ObjectType::SymmetricKey
        })
        .unwrap_or(false);

    // Retrieve the PROVIDER_KEY_NAME stored as a tag during creation.
    let tags = attrs.get_tags();
    info!(
        uuid,
        tags = ?tags,
        vendor_attrs = ?attrs.vendor_attributes,
        "get_key_info_async: retrieved tags"
    );
    // Filter out system tags (start with "_") to get the user-supplied name.
    let key_name = tags
        .iter()
        .find(|t| !t.starts_with('_'))
        .cloned()
        .unwrap_or_else(|| response.unique_identifier.to_string());

    Ok(KeyInfo {
        unique_id: response.unique_identifier.to_string(),
        key_name,
        algorithm_name,
        bit_len,
        is_symmetric,
    })
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt data on the Cosmian KMS.
///
/// Returns `(ciphertext, iv)`.  For AES the KMS generates the IV server-side.
/// For RSA, no IV is returned.
pub fn encrypt(
    kms_config: &KmsConfig,
    username: &str,
    thumb_bytes: &[u8],
    plaintext: &[u8],
    iv: Option<&[u8]>,
    is_symmetric: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>), KmsError> {
    let uuid = thumbprint_to_uuid(thumb_bytes)
        .ok_or_else(|| KmsError::InvalidUniqueId("thumbprint too short".into()))?;

    let cert_entry = kms_config
        .certificates
        .iter()
        .find(|c| c.username.eq_ignore_ascii_case(username))
        .ok_or_else(|| KmsError::NoCertForUser(username.to_string()))?;

    validate_cert_identity(&cert_entry.client_cert, username)?;
    let kms_client = get_kms_client(kms_config, cert_entry)?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KmsError::EncryptError(format!("tokio runtime: {e}")))?;

    rt.block_on(encrypt_async(
        &kms_client,
        &uuid,
        plaintext,
        iv,
        is_symmetric,
    ))
}

async fn encrypt_async(
    client: &KmsClient,
    uuid: &str,
    plaintext: &[u8],
    iv: Option<&[u8]>,
    is_symmetric: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>), KmsError> {
    if is_symmetric {
        // Symmetric (AES): delegate to KMS server.
        encrypt_symmetric_async(client, uuid, plaintext, iv).await
    } else {
        // Asymmetric (RSA): encrypt on the KMS using the public key.
        // The public key UUID is the private key UUID with a "_pk" suffix.
        let pk_uuid = format!("{uuid}_pk");
        encrypt_rsa_async(client, &pk_uuid, plaintext).await
    }
}

/// RSA-OAEP-SHA256 encryption via the KMS Encrypt KMIP endpoint.
///
/// Uses the public key UUID (`<private_uuid>_pk`) so the KMS performs the
/// encryption server-side — the private key material never leaves the server.
async fn encrypt_rsa_async(
    client: &KmsClient,
    pk_uuid: &str,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>), KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod};
    use cosmian_kms_client::kmip_2_1::{
        kmip_operations::Encrypt,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    };
    use zeroize::Zeroizing;

    let crypto_params = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    };

    let request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(pk_uuid.to_string())),
        cryptographic_parameters: Some(crypto_params),
        data: Some(Zeroizing::new(plaintext.to_vec())),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    };

    let response = client
        .encrypt(request)
        .await
        .map_err(|e| KmsError::EncryptError(e.to_string()))?;

    let ciphertext = response
        .data
        .ok_or_else(|| KmsError::EncryptError("no ciphertext in KMS response".into()))?;

    Ok((ciphertext, None))
}

/// AES encryption via the KMS Encrypt KMIP endpoint.
async fn encrypt_symmetric_async(
    client: &KmsClient,
    uuid: &str,
    plaintext: &[u8],
    iv: Option<&[u8]>,
) -> Result<(Vec<u8>, Option<Vec<u8>>), KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::BlockCipherMode;
    use cosmian_kms_client::kmip_2_1::{
        kmip_operations::Encrypt,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    };
    use zeroize::Zeroizing;

    let crypto_params = Some(CryptographicParameters {
        block_cipher_mode: Some(BlockCipherMode::CBC),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Default::default()
    });

    let request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uuid.to_string())),
        cryptographic_parameters: crypto_params,
        data: Some(Zeroizing::new(plaintext.to_vec())),
        i_v_counter_nonce: iv.map(|v| v.to_vec()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    };

    let response = client
        .encrypt(request)
        .await
        .map_err(|e| KmsError::EncryptError(e.to_string()))?;

    let ciphertext = response
        .data
        .ok_or_else(|| KmsError::EncryptError("no ciphertext in response".into()))?;

    Ok((ciphertext, response.i_v_counter_nonce))
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// Decrypt data on the Cosmian KMS.
///
/// Returns the plaintext bytes.
pub fn decrypt(
    kms_config: &KmsConfig,
    username: &str,
    thumb_bytes: &[u8],
    ciphertext: &[u8],
    iv: Option<&[u8]>,
    is_symmetric: bool,
) -> Result<Vec<u8>, KmsError> {
    let uuid = thumbprint_to_uuid(thumb_bytes)
        .ok_or_else(|| KmsError::InvalidUniqueId("thumbprint too short".into()))?;

    let cert_entry = kms_config
        .certificates
        .iter()
        .find(|c| c.username.eq_ignore_ascii_case(username))
        .ok_or_else(|| KmsError::NoCertForUser(username.to_string()))?;

    validate_cert_identity(&cert_entry.client_cert, username)?;
    let kms_client = get_kms_client(kms_config, cert_entry)?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KmsError::DecryptError(format!("tokio runtime: {e}")))?;

    rt.block_on(decrypt_async(
        &kms_client,
        &uuid,
        ciphertext,
        iv,
        is_symmetric,
    ))
}

async fn decrypt_async(
    client: &KmsClient,
    uuid: &str,
    ciphertext: &[u8],
    iv: Option<&[u8]>,
    is_symmetric: bool,
) -> Result<Vec<u8>, KmsError> {
    if is_symmetric {
        // Symmetric (AES): delegate to KMS server.
        decrypt_symmetric_async(client, uuid, ciphertext, iv).await
    } else {
        // Asymmetric (RSA): decrypt on the KMS using the private key UUID directly.
        decrypt_rsa_async(client, uuid, ciphertext).await
    }
}

/// RSA-OAEP-SHA256 decryption via the KMS Decrypt KMIP endpoint.
///
/// Uses the private key UUID so the KMS performs the decryption server-side —
/// the private key material never leaves the server.
async fn decrypt_rsa_async(
    client: &KmsClient,
    sk_uuid: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod};
    use cosmian_kms_client::kmip_2_1::{
        kmip_operations::Decrypt,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    };

    let crypto_params = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    };

    let request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(sk_uuid.to_string())),
        cryptographic_parameters: Some(crypto_params),
        data: Some(ciphertext.to_vec()),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: None,
    };

    let response = client
        .decrypt(request)
        .await
        .map_err(|e| KmsError::DecryptError(e.to_string()))?;

    let plaintext = response
        .data
        .ok_or_else(|| KmsError::DecryptError("no plaintext in KMS response".into()))?;

    Ok(plaintext.to_vec())
}

/// AES decryption via the KMS Decrypt KMIP endpoint.
async fn decrypt_symmetric_async(
    client: &KmsClient,
    uuid: &str,
    ciphertext: &[u8],
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, KmsError> {
    use cosmian_kms_client::kmip_0::kmip_types::BlockCipherMode;
    use cosmian_kms_client::kmip_2_1::{
        kmip_operations::Decrypt,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    };

    let crypto_params = Some(CryptographicParameters {
        block_cipher_mode: Some(BlockCipherMode::CBC),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Default::default()
    });

    let request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uuid.to_string())),
        cryptographic_parameters: crypto_params,
        data: Some(ciphertext.to_vec()),
        i_v_counter_nonce: iv.map(|v| v.to_vec()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: None,
    };

    let response = client
        .decrypt(request)
        .await
        .map_err(|e| KmsError::DecryptError(e.to_string()))?;

    let plaintext = response
        .data
        .ok_or_else(|| KmsError::DecryptError("no plaintext in response".into()))?;

    Ok(plaintext.to_vec())
}

// ---------------------------------------------------------------------------
// Key export
// ---------------------------------------------------------------------------

/// Export the public key portion of an asymmetric key from the KMS.
///
/// Returns the DER-encoded public key blob.
pub fn export_public_key(
    kms_config: &KmsConfig,
    username: &str,
    thumb_bytes: &[u8],
) -> Result<Vec<u8>, KmsError> {
    let uuid = thumbprint_to_uuid(thumb_bytes)
        .ok_or_else(|| KmsError::InvalidUniqueId("thumbprint too short".into()))?;

    let cert_entry = kms_config
        .certificates
        .iter()
        .find(|c| c.username.eq_ignore_ascii_case(username))
        .ok_or_else(|| KmsError::NoCertForUser(username.to_string()))?;

    validate_cert_identity(&cert_entry.client_cert, username)?;
    let kms_client = get_kms_client(kms_config, cert_entry)?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KmsError::ExportError(format!("tokio runtime: {e}")))?;

    rt.block_on(export_public_key_async(&kms_client, &uuid))
}

async fn export_public_key_async(client: &KmsClient, uuid: &str) -> Result<Vec<u8>, KmsError> {
    use cosmian_kms_client::kmip_2_1::{
        kmip_objects::Object,
        kmip_operations::Get,
        kmip_types::{KeyFormatType, UniqueIdentifier},
    };

    // The thumbprint stores the private key UUID.
    // The Cosmian KMS exposes the corresponding public key under the
    // virtual identifier "<private_uuid>_pk".
    let pk_uuid = format!("{uuid}_pk");

    let get_req = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(pk_uuid)),
        key_format_type: Some(KeyFormatType::PKCS1),
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_specification: None,
    };

    let response = client
        .get(get_req)
        .await
        .map_err(|e| KmsError::ExportError(e.to_string()))?;

    // Extract the key material bytes from the KMIP Object.
    let key_block = match &response.object {
        Object::PublicKey(pk) => &pk.key_block,
        _ => {
            return Err(KmsError::ExportError(
                "unexpected object type returned by KMS (expected PublicKey)".into(),
            ));
        }
    };

    let key_bytes = key_block
        .key_bytes()
        .map_err(|e| KmsError::ExportError(format!("cannot extract key bytes: {e}")))?;
    let key_bytes = key_bytes.to_vec();

    Ok(key_bytes)
}
