//! Credential metadata and RP-isolated selection policy.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
    sync::Arc,
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{CborError, CborLimits, CborValue, decode_with_limits, encode as encode_cbor};

const STORAGE_SCHEMA_VERSION: i64 = 16;
const PIN_STATE_SCHEMA_VERSION: i64 = 9;
const CREDENTIAL_RECORD_SCHEMA_VERSION: i64 = 9;
const RESET_JOURNAL_SCHEMA_VERSION: i64 = 9;
const RESET_METADATA_KEY_CLEANUP_SCHEMA_VERSION: i64 = 11;
const PROVIDER_KEY_JOURNAL_SCHEMA_VERSION: i64 = 11;
const PROVIDER_KEY_JOURNAL_AAD_V1: &[u8] = b"ghost-fido/provider-key-journal/v1";
const CREDENTIAL_DELETION_JOURNAL_AAD_V1: &[u8] = b"ghost-fido/credential-deletion-journal/v1";
const STORAGE_AAD_V1: &[u8] = b"ghost-fido/credential-store/v1";
const STORAGE_AAD_V2: &[u8] = b"ghost-fido/credential-store/v2";
const STORAGE_AAD_V3: &[u8] = b"ghost-fido/credential-store/v3";
const STORAGE_AAD_V4: &[u8] = b"ghost-fido/credential-store/v4";
const PIN_STATE_AAD_V1: &[u8] = b"ghost-fido/pin-state/v1";
const LARGE_BLOB_ARRAY_AAD_V1: &[u8] = b"ghost-fido/large-blob-array/v1";
const RESET_JOURNAL_AAD_V1: &[u8] = b"ghost-fido/reset-journal/v1";
const PIN_RETRY_LIMIT: u8 = 8;
pub const DEFAULT_MIN_PIN_LENGTH: u8 = 4;
pub const MAX_MIN_PIN_LENGTH: u8 = 63;
pub const MAX_RP_IDS_FOR_MIN_PIN_LENGTH: usize = 8;
const MAX_PERSISTED_RECORDS: usize = 4096;
const MAX_PERSISTED_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROTECTED_BYTES: usize = MAX_PERSISTED_BYTES + 4096;
pub const MAX_SERIALIZED_LARGE_BLOB_ARRAY: usize = 64 * 1024;
const INITIAL_LARGE_BLOB_ARRAY: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];
const MAX_USER_LABEL_BYTES: usize = 256;
const MAX_RP_ID_BYTES: usize = 253;
pub const MAX_CREDENTIAL_BLOB_LENGTH: usize = 32;

pub type RpIdHash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CredentialProtectionPolicy {
    #[default]
    UserVerificationOptional = 1,
    UserVerificationOptionalWithCredentialIdList = 2,
    UserVerificationRequired = 3,
}

impl TryFrom<u64> for CredentialProtectionPolicy {
    type Error = CredentialError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UserVerificationOptional),
            2 => Ok(Self::UserVerificationOptionalWithCredentialIdList),
            3 => Ok(Self::UserVerificationRequired),
            _ => Err(CredentialError::ProtectedDataInvalid),
        }
    }
}

/// Non-secret P-256 public key coordinates for an ES256 credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Es256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKeyProtection {
    HardwareBacked,
    OsProtected,
    Software,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialKeyMetadata {
    pub protection: CredentialKeyProtection,
    pub exportable: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialId(Vec<u8>);
impl CredentialId {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CredentialError> {
        if bytes.is_empty() {
            Err(CredentialError::EmptyIdentifier)
        } else {
            Ok(Self(bytes))
        }
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialId([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct KeyHandle(Vec<u8>);
impl KeyHandle {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CredentialError> {
        if bytes.is_empty() {
            Err(CredentialError::EmptyKeyHandle)
        } else {
            Ok(Self(bytes))
        }
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeyHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyHandle([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: CredentialId,
    pub rp_id_hash: RpIdHash,
    /// Plain relying-party identifier for the local management UI. Legacy
    /// records remain unidentified until they are re-created.
    pub relying_party_id: Option<String>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub key_handle: KeyHandle,
    /// Persisted public key used by CTAP Credential Management. Legacy records
    /// are populated from their provider before enumeration.
    pub public_key: Option<Es256PublicKey>,
    /// Credential-scoped HMAC secrets. Persisted only in the protected record blob.
    pub hmac_secret: Option<HmacSecretMaterial>,
    /// Per-credential CTAP `largeBlobKey`; protected with the credential record.
    pub large_blob_key: Option<LargeBlobKey>,
    /// Opaque CTAP `credBlob` data; protected with the credential record.
    pub cred_blob: Option<CredentialBlob>,
    /// CTAP `credProtect` level. Older records default to level 1.
    pub cred_protect: CredentialProtectionPolicy,
    pub key_metadata: CredentialKeyMetadata,
    pub discoverable: bool,
    /// Store-assigned monotonic ordering used for discoverable credential selection.
    pub creation_order: u64,
    pub sign_count: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HmacSecretMaterial {
    with_uv: Zeroizing<[u8; 32]>,
    without_uv: Zeroizing<[u8; 32]>,
}

impl HmacSecretMaterial {
    #[must_use]
    pub fn new(with_uv: Zeroizing<[u8; 32]>, without_uv: Zeroizing<[u8; 32]>) -> Self {
        Self {
            with_uv,
            without_uv,
        }
    }

    #[must_use]
    pub fn for_uv(&self, user_verified: bool) -> &[u8; 32] {
        if user_verified {
            &self.with_uv
        } else {
            &self.without_uv
        }
    }
}

impl fmt::Debug for HmacSecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HmacSecretMaterial([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LargeBlobKey(Zeroizing<[u8; 32]>);

impl LargeBlobKey {
    #[must_use]
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LargeBlobKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LargeBlobKey([REDACTED])")
    }
}

/// Opaque credential-scoped CTAP `credBlob` bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialBlob(Zeroizing<Vec<u8>>);

impl CredentialBlob {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CredentialBlob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialBlob([REDACTED])")
    }
}

/// Safe local-management projection of one credential record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCredential {
    pub creation_order: u64,
    pub relying_party_id: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub key_metadata: CredentialKeyMetadata,
    pub discoverable: bool,
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("rp_id_hash", &"[REDACTED]")
            .field("user_handle", &"[REDACTED]")
            .field("user_name", &"[REDACTED]")
            .field("user_display_name", &"[REDACTED]")
            .field("key_handle", &self.key_handle)
            .field(
                "hmac_secret",
                &self.hmac_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "large_blob_key",
                &self.large_blob_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("cred_blob", &self.cred_blob.as_ref().map(|_| "[REDACTED]"))
            .field("cred_protect", &self.cred_protect)
            .field("key_metadata", &self.key_metadata)
            .field("discoverable", &self.discoverable)
            .field("creation_order", &self.creation_order)
            .field("sign_count", &self.sign_count)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    EmptyIdentifier,
    EmptyUserHandle,
    EmptyKeyHandle,
    UserLabelTooLong,
    InvalidRelyingPartyId,
    DuplicateIdentifier,
    NotFound,
    CounterOverflow,
    CreationOrderOverflow,
    ResetInProgress,
    ProviderKeyCleanupPending,
    StorageFailure,
    StorageFull,
    ProtectedDataInvalid,
    InvalidPinState,
    UnsupportedSchemaVersion(i64),
    RecordLimitExceeded,
    CborEncoding(CborError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialProtectionError {
    Failed,
}

/// Authenticated encryption boundary for credential metadata persisted by SQLite.
///
/// Implementations must authenticate ciphertext and associated data, and must
/// return an error if either is invalid. The plaintext contains credential IDs,
/// RP identifiers and hashes, user handles, opaque provider key references, and
/// credential-scoped `hmac-secret` and `largeBlobKey` material.
/// Decrypted bytes are returned in a zeroizing buffer that clears them on drop.
pub trait CredentialProtector: Send + Sync {
    fn protect(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CredentialProtectionError>;
    fn unprotect(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialProtectionError>;
    /// Erases app-managed protection key material without creating or loading a key.
    /// OS-managed protection such as DPAPI may implement this as a no-op.
    fn erase_key(&self) -> Result<(), CredentialProtectionError>;
}

pub struct CredentialStore {
    records: BTreeMap<CredentialId, CredentialRecord>,
    pin_state: PinState,
    large_blob_array: Zeroizing<Vec<u8>>,
    pending_reset_keys: Option<Vec<KeyHandle>>,
    metadata_key_cleanup_pending: bool,
    pending_provider_key: Option<KeyHandle>,
    pending_credential_deletion: Option<(CredentialId, KeyHandle)>,
    sqlite: Option<SqliteBackend>,
    next_creation_order: u64,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self {
            records: BTreeMap::new(),
            pin_state: PinState::default(),
            large_blob_array: Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec()),
            pending_reset_keys: None,
            metadata_key_cleanup_pending: false,
            pending_provider_key: None,
            pending_credential_deletion: None,
            sqlite: None,
            next_creation_order: 0,
        }
    }
}

/// Protected authenticator PIN state. Debug output intentionally omits the verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct PinState {
    verifier: Option<[u8; 16]>,
    retries: u8,
    min_pin_length: u8,
    pin_code_point_length: Option<u8>,
    force_pin_change: bool,
    min_pin_length_rp_ids: Vec<String>,
}

impl Default for PinState {
    fn default() -> Self {
        Self {
            verifier: None,
            retries: PIN_RETRY_LIMIT,
            min_pin_length: DEFAULT_MIN_PIN_LENGTH,
            pin_code_point_length: None,
            force_pin_change: false,
            min_pin_length_rp_ids: Vec::new(),
        }
    }
}

impl fmt::Debug for PinState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinState")
            .field("pin_is_set", &self.verifier.is_some())
            .field("retries", &self.retries)
            .field("min_pin_length", &self.min_pin_length)
            .field("force_pin_change", &self.force_pin_change)
            .field(
                "min_pin_length_rp_id_count",
                &self.min_pin_length_rp_ids.len(),
            )
            .finish()
    }
}

impl Drop for PinState {
    fn drop(&mut self) {
        if let Some(verifier) = self.verifier.as_mut() {
            verifier.zeroize();
        }
    }
}

impl PinState {
    #[must_use]
    pub const fn verifier(&self) -> Option<&[u8; 16]> {
        self.verifier.as_ref()
    }

    #[must_use]
    pub const fn retries(&self) -> u8 {
        self.retries
    }

    #[must_use]
    pub const fn min_pin_length(&self) -> u8 {
        self.min_pin_length
    }

    #[must_use]
    pub const fn pin_code_point_length(&self) -> Option<u8> {
        self.pin_code_point_length
    }

    #[must_use]
    pub const fn force_pin_change(&self) -> bool {
        self.force_pin_change
    }

    #[must_use]
    pub fn min_pin_length_rp_ids(&self) -> &[String] {
        &self.min_pin_length_rp_ids
    }

    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.retries > PIN_RETRY_LIMIT
            || (self.verifier.is_none() && self.retries != PIN_RETRY_LIMIT)
            || !(DEFAULT_MIN_PIN_LENGTH..=MAX_MIN_PIN_LENGTH).contains(&self.min_pin_length)
            || (self.verifier.is_none()
                && (self.pin_code_point_length.is_some() || self.force_pin_change))
            || self.pin_code_point_length.is_some_and(|length| {
                length > MAX_MIN_PIN_LENGTH || length < DEFAULT_MIN_PIN_LENGTH
            })
            || (self.verifier.is_some()
                && !self.force_pin_change
                && (self
                    .pin_code_point_length
                    .is_some_and(|length| length < self.min_pin_length)
                    || (self.pin_code_point_length.is_none()
                        && self.min_pin_length > DEFAULT_MIN_PIN_LENGTH)))
            || self.min_pin_length_rp_ids.len() > MAX_RP_IDS_FOR_MIN_PIN_LENGTH
        {
            return Err(CredentialError::InvalidPinState);
        }
        let mut seen = BTreeSet::new();
        for rp_id in &self.min_pin_length_rp_ids {
            if rp_id.is_empty() || rp_id.len() > MAX_RP_ID_BYTES || !seen.insert(rp_id) {
                return Err(CredentialError::InvalidPinState);
            }
        }
        Ok(())
    }
}

struct SqliteBackend {
    connection: Connection,
    protector: Arc<dyn CredentialProtector>,
    initialized: bool,
}

impl fmt::Debug for CredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialStore")
            .field("record_count", &self.records.len())
            .field("persistent", &self.sqlite.is_some())
            .field("reset_pending", &self.reset_is_pending())
            .finish()
    }
}

impl CredentialStore {
    /// Opens an encrypted, versioned SQLite store.
    ///
    /// No credential metadata is written unless the supplied protector
    /// successfully authenticates the complete serialized record set.
    pub fn open(
        path: impl AsRef<Path>,
        protector: Arc<dyn CredentialProtector>,
    ) -> Result<Self, CredentialError> {
        let path = path.as_ref().to_path_buf();
        let mut connection =
            Connection::open(&path).map_err(|_| CredentialError::StorageFailure)?;
        let schema_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| CredentialError::StorageFailure)?;

        let mut metadata_key_cleanup_pending = if schema_version >= RESET_JOURNAL_SCHEMA_VERSION {
            prepare_reset_journal_schema(&mut connection, schema_version)?
        } else {
            false
        };
        let mut records = if metadata_key_cleanup_pending {
            BTreeMap::new()
        } else {
            match schema_version {
                0 => {
                    connection
                        .busy_timeout(std::time::Duration::from_secs(30))
                        .map_err(|_| CredentialError::StorageFailure)?;
                    let transaction = connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(|_| CredentialError::StorageFailure)?;
                    let current_version: i64 = transaction
                        .pragma_query_value(None, "user_version", |row| row.get(0))
                        .map_err(|_| CredentialError::StorageFailure)?;
                    if current_version != 0 {
                        transaction
                            .rollback()
                            .map_err(|_| CredentialError::StorageFailure)?;
                        drop(connection);
                        return Self::open(&path, protector);
                    }
                    let user_tables: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|_| CredentialError::StorageFailure)?;
                    if user_tables != 0 {
                        return Err(CredentialError::ProtectedDataInvalid);
                    }
                    let payload = encode_records(&BTreeMap::new())?;
                    let protected = protector
                        .protect(&payload, STORAGE_AAD_V4)
                        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
                    if protected.is_empty() || protected.len() > MAX_PROTECTED_BYTES {
                        return Err(CredentialError::ProtectedDataInvalid);
                    }
                    transaction
                        .execute_batch(
                            "CREATE TABLE credential_store (
                            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                            payload BLOB NOT NULL
                        );",
                        )
                        .map_err(|_| CredentialError::StorageFailure)?;
                    transaction
                        .execute(
                            "INSERT INTO credential_store (singleton, payload) VALUES (1, ?1)",
                            params![protected],
                        )
                        .map_err(|_| CredentialError::StorageFailure)?;
                    transaction
                        .pragma_update(None, "user_version", CREDENTIAL_RECORD_SCHEMA_VERSION)
                        .map_err(|_| CredentialError::StorageFailure)?;
                    transaction
                        .commit()
                        .map_err(|_| CredentialError::StorageFailure)?;
                    connection
                        .busy_timeout(std::time::Duration::ZERO)
                        .map_err(|_| CredentialError::StorageFailure)?;
                    BTreeMap::new()
                }
                old_version @ (1 | 2 | 3) => {
                    connection
                        .busy_timeout(std::time::Duration::from_secs(30))
                        .map_err(|_| CredentialError::StorageFailure)?;
                    let transaction = connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(|_| CredentialError::StorageFailure)?;
                    let current_version: i64 = transaction
                        .pragma_query_value(None, "user_version", |row| row.get(0))
                        .map_err(|_| CredentialError::StorageFailure)?;
                    if current_version != old_version {
                        transaction
                            .rollback()
                            .map_err(|_| CredentialError::StorageFailure)?;
                        drop(connection);
                        return Self::open(&path, protector);
                    }
                    let protected = read_protected_payload(&transaction)?;
                    let old_aad = match old_version {
                        1 => STORAGE_AAD_V1,
                        2 => STORAGE_AAD_V2,
                        _ => STORAGE_AAD_V3,
                    };
                    let plaintext = protector
                        .unprotect(&protected, old_aad)
                        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
                    let mut records = decode_records(&plaintext, old_version as u8)?;
                    assign_legacy_creation_order(&mut records)?;
                    let migrated_plaintext = encode_records(&records)?;
                    let migrated_protected = protector
                        .protect(&migrated_plaintext, STORAGE_AAD_V4)
                        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
                    validate_protected_payload(&migrated_protected)?;

                    write_payload(&transaction, &migrated_protected)?;
                    transaction
                        .pragma_update(None, "user_version", CREDENTIAL_RECORD_SCHEMA_VERSION)
                        .map_err(|_| CredentialError::StorageFailure)?;
                    transaction
                        .commit()
                        .map_err(|_| CredentialError::StorageFailure)?;
                    connection
                        .busy_timeout(std::time::Duration::ZERO)
                        .map_err(|_| CredentialError::StorageFailure)?;
                    records
                }
                4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 => {
                    let protected = read_protected_payload(&connection)?;
                    let plaintext = protector
                        .unprotect(&protected, STORAGE_AAD_V4)
                        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
                    decode_records(
                        &plaintext,
                        match schema_version {
                            15 => 9,
                            14 => 8,
                            11 | 12 | 13 => 7,
                            10 => 7,
                            9 => 9,
                            8 => 8,
                            7 => 6,
                            6 => 5,
                            5 => 4,
                            _ => 4,
                        },
                    )?
                }
                other => return Err(CredentialError::UnsupportedSchemaVersion(other)),
            }
        };
        if schema_version < RESET_JOURNAL_SCHEMA_VERSION {
            metadata_key_cleanup_pending =
                prepare_reset_journal_schema(&mut connection, schema_version)?;
        }
        let large_blob_array = initialize_large_blob_array(
            &mut connection,
            protector.as_ref(),
            schema_version,
            metadata_key_cleanup_pending,
        )?;
        prepare_credential_deletion_schema(&mut connection, schema_version)?;
        let pending_reset_keys = if metadata_key_cleanup_pending {
            None
        } else {
            initialize_reset_journal(&mut connection, protector.as_ref())?
        };
        let pending_provider_key = if metadata_key_cleanup_pending || pending_reset_keys.is_some() {
            None
        } else {
            initialize_provider_key_journal(&mut connection, protector.as_ref())?
        };
        let pending_credential_deletion = if metadata_key_cleanup_pending
            || pending_reset_keys.is_some()
        {
            None
        } else {
            initialize_credential_deletion_journal(&mut connection, protector.as_ref(), &records)?
        };
        if pending_provider_key.is_some() && pending_credential_deletion.is_some() {
            return Err(CredentialError::ProtectedDataInvalid);
        }
        let mut pin_state = if metadata_key_cleanup_pending {
            PinState::default()
        } else {
            initialize_pin_state(&mut connection, protector.as_ref(), schema_version)?
        };
        let large_blob_array = if pending_reset_keys.is_some() || metadata_key_cleanup_pending {
            Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec())
        } else {
            large_blob_array
        };
        if pending_reset_keys.is_some() {
            records.clear();
            pin_state = PinState::default();
        }

        let next_creation_order = records
            .values()
            .map(|record| record.creation_order)
            .max()
            .unwrap_or(0);
        Ok(Self {
            records,
            pin_state,
            large_blob_array,
            pending_reset_keys,
            metadata_key_cleanup_pending,
            pending_provider_key,
            pending_credential_deletion,
            sqlite: Some(SqliteBackend {
                connection,
                protector,
                initialized: true,
            }),
            next_creation_order,
        })
    }

    pub fn register(&mut self, record: CredentialRecord) -> Result<(), CredentialError> {
        self.register_inner(record, None)
    }

    /// Persists a new credential and clears its pre-creation key journal in
    /// the same SQLite transaction.
    pub fn register_created_key(
        &mut self,
        record: CredentialRecord,
        key_handle: &KeyHandle,
    ) -> Result<(), CredentialError> {
        self.register_inner(record, Some(key_handle))
    }

    fn register_inner(
        &mut self,
        mut record: CredentialRecord,
        created_key: Option<&KeyHandle>,
    ) -> Result<(), CredentialError> {
        if self.reset_is_pending() {
            return Err(CredentialError::ResetInProgress);
        }
        if self.pending_provider_key.as_ref() != created_key {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        if created_key.is_some_and(|handle| handle != &record.key_handle) {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        if record.relying_party_id.as_ref().is_some_and(|rp_id| {
            rp_id.is_empty() || rp_id.len() > MAX_RP_ID_BYTES || !rp_id.is_ascii()
        }) {
            return Err(CredentialError::InvalidRelyingPartyId);
        }
        if record
            .user_name
            .as_ref()
            .is_some_and(|name| name.len() > MAX_USER_LABEL_BYTES)
            || record
                .user_display_name
                .as_ref()
                .is_some_and(|name| name.len() > MAX_USER_LABEL_BYTES)
        {
            return Err(CredentialError::UserLabelTooLong);
        }
        if self.records.contains_key(&record.id) {
            return Err(CredentialError::DuplicateIdentifier);
        }
        if self.sqlite.is_some() && self.records.len() >= MAX_PERSISTED_RECORDS {
            return Err(CredentialError::RecordLimitExceeded);
        }
        let creation_order = self
            .next_creation_order
            .checked_add(1)
            .ok_or(CredentialError::CreationOrderOverflow)?;
        record.creation_order = creation_order;
        let mut next_records = self.records.clone();
        next_records.insert(record.id.clone(), record);
        self.records = self.persist_with_provider_key_cleanup(&next_records, created_key)?;
        self.next_creation_order = self
            .records
            .values()
            .map(|record| record.creation_order)
            .max()
            .unwrap_or(0);
        if created_key.is_some() {
            self.pending_provider_key = None;
        }
        Ok(())
    }
    #[must_use]
    pub fn find(
        &self,
        rp_id_hash: RpIdHash,
        allow_list: Option<&[CredentialId]>,
    ) -> Vec<&CredentialRecord> {
        self.records
            .values()
            .filter(|record| {
                record.rp_id_hash == rp_id_hash
                    && allow_list.is_none_or(|ids| ids.iter().any(|id| id == &record.id))
            })
            .collect()
    }
    #[must_use]
    pub fn find_discoverable(&self, rp_id_hash: RpIdHash) -> Vec<&CredentialRecord> {
        self.records
            .values()
            .filter(|record| record.rp_id_hash == rp_id_hash && record.discoverable)
            .collect()
    }

    /// Returns a snapshot of discoverable credentials for protocol management.
    #[must_use]
    pub fn discoverable_records(&self) -> Vec<CredentialRecord> {
        self.records
            .values()
            .filter(|record| record.discoverable)
            .cloned()
            .collect()
    }

    /// Removes a credential by its protocol identifier after provider-key deletion.
    pub fn remove_by_id(&mut self, id: &CredentialId) -> Result<CredentialRecord, CredentialError> {
        let removed = self
            .records
            .get(id)
            .cloned()
            .ok_or(CredentialError::NotFound)?;
        let mut next_records = self.records.clone();
        next_records.remove(id);
        self.records = self.persist(&next_records)?;
        Ok(removed)
    }

    /// Changes only the mutable CTAP user labels while preserving the user handle.
    pub fn update_user_labels(
        &mut self,
        id: &CredentialId,
        expected_user_handle: &[u8],
        name: Option<String>,
        display_name: Option<String>,
    ) -> Result<(), CredentialError> {
        if name
            .as_ref()
            .is_some_and(|value| value.len() > MAX_USER_LABEL_BYTES)
            || display_name
                .as_ref()
                .is_some_and(|value| value.len() > MAX_USER_LABEL_BYTES)
        {
            return Err(CredentialError::UserLabelTooLong);
        }
        let record = self.records.get(id).ok_or(CredentialError::NotFound)?;
        if !record.discoverable || record.user_handle != expected_user_handle {
            return Err(CredentialError::NotFound);
        }
        let mut next_records = self.records.clone();
        let record = next_records.get_mut(id).ok_or(CredentialError::NotFound)?;
        record.user_name = name;
        record.user_display_name = display_name;
        self.records = self.persist(&next_records)?;
        Ok(())
    }

    /// Selects assertion credentials without disclosing non-discoverable ones.
    #[must_use]
    pub fn find_for_assertion(
        &self,
        rp_id_hash: RpIdHash,
        allow_list: Option<&[Vec<u8>]>,
    ) -> Vec<&CredentialRecord> {
        self.records
            .values()
            .filter(|record| {
                record.rp_id_hash == rp_id_hash
                    && match allow_list {
                        Some(ids) => ids.iter().any(|id| id.as_slice() == record.id.as_bytes()),
                        None => record.discoverable,
                    }
            })
            .collect()
    }

    #[must_use]
    pub fn has_matching_credentials(
        &self,
        rp_id_hash: RpIdHash,
        credential_ids: &[Vec<u8>],
    ) -> bool {
        self.records.values().any(|record| {
            record.rp_id_hash == rp_id_hash
                && credential_ids
                    .iter()
                    .any(|id| id.as_slice() == record.id.as_bytes())
        })
    }

    /// Returns only fields intended for local credential management. Protocol
    /// credential IDs, user handles, and provider key references are omitted.
    #[must_use]
    pub fn managed_credentials(&self) -> Vec<ManagedCredential> {
        let mut credentials = self
            .records
            .values()
            .map(|record| ManagedCredential {
                creation_order: record.creation_order,
                relying_party_id: record.relying_party_id.clone(),
                user_name: record.user_name.clone(),
                user_display_name: record.user_display_name.clone(),
                key_metadata: record.key_metadata,
                discoverable: record.discoverable,
            })
            .collect::<Vec<_>>();
        credentials.sort_by_key(|credential| credential.creation_order);
        credentials
    }

    /// Removes a credential by its stable, non-secret store-assigned selector.
    /// Returns the removed record so the caller can delete its provider key.
    pub fn remove_by_creation_order(
        &mut self,
        creation_order: u64,
    ) -> Result<CredentialRecord, CredentialError> {
        let id = self
            .records
            .values()
            .find(|record| record.creation_order == creation_order)
            .map(|record| record.id.clone())
            .ok_or(CredentialError::NotFound)?;
        let removed = self
            .records
            .get(&id)
            .cloned()
            .ok_or(CredentialError::NotFound)?;
        let mut next_records = self.records.clone();
        next_records.remove(&id);
        self.records = self.persist(&next_records)?;
        Ok(removed)
    }

    /// Returns provider key handles for an internal full-reset operation.
    /// Callers must keep the handles out of logs and external UI responses.
    #[must_use]
    pub fn provider_key_handles(&self) -> Vec<KeyHandle> {
        let mut handles = self
            .records
            .values()
            .map(|record| record.key_handle.clone())
            .collect::<Vec<_>>();
        if let Some(pending) = self.pending_provider_key.as_ref() {
            handles.push(pending.clone());
        }
        if let Some((_, pending)) = self.pending_credential_deletion.as_ref() {
            handles.push(pending.clone());
        }
        handles
    }

    #[must_use]
    pub fn reset_is_pending(&self) -> bool {
        self.pending_reset_keys.is_some() || self.metadata_key_cleanup_pending
    }

    #[must_use]
    pub fn pending_provider_key_handle(&self) -> Option<&KeyHandle> {
        self.pending_provider_key.as_ref()
    }

    #[must_use]
    pub fn provider_key_cleanup_pending(&self) -> bool {
        self.pending_provider_key.is_some() || self.pending_credential_deletion.is_some()
    }

    /// Returns the pending credential selector and provider handle for internal recovery.
    /// Callers must keep both values out of logs and external responses.
    #[must_use]
    pub fn pending_credential_deletion(&self) -> Option<(CredentialId, KeyHandle)> {
        self.pending_credential_deletion.clone()
    }

    /// Persists an authenticated deletion intent before removing the provider key.
    pub fn begin_credential_deletion(
        &mut self,
        id: &CredentialId,
    ) -> Result<KeyHandle, CredentialError> {
        if self.reset_is_pending() || self.provider_key_cleanup_pending() {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        let record = self.records.get(id).ok_or(CredentialError::NotFound)?;
        let handle = record.key_handle.clone();
        let backend = self
            .sqlite
            .as_mut()
            .ok_or(CredentialError::StorageFailure)?;
        let plaintext = encode_credential_deletion_journal(id, &handle)?;
        let protected = backend
            .protector
            .protect(&plaintext, CREDENTIAL_DELETION_JOURNAL_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected)?;
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        let conflicting_cleanup_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM provider_key_journal WHERE singleton = 1)
                    OR EXISTS (SELECT 1 FROM reset_journal WHERE singleton = 1)
                    OR EXISTS (SELECT 1 FROM credential_deletion_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if conflicting_cleanup_pending {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        let current_records = read_credential_records(&transaction, backend.protector.as_ref())?;
        if current_records.get(id).map(|record| &record.key_handle) != Some(&handle) {
            return Err(CredentialError::NotFound);
        }
        transaction
            .execute(
                "INSERT INTO credential_deletion_journal (singleton, payload) VALUES (1, ?1)",
                params![protected],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        self.next_creation_order = current_records
            .values()
            .map(|record| record.creation_order)
            .max()
            .unwrap_or(0);
        self.records = current_records;
        self.pending_credential_deletion = Some((id.clone(), handle.clone()));
        Ok(handle)
    }

    /// Atomically removes the credential and its journal after provider deletion succeeds.
    /// Callers must not invoke this before the provider confirms key deletion.
    pub fn finish_credential_deletion(
        &mut self,
        id: &CredentialId,
        handle: &KeyHandle,
    ) -> Result<(), CredentialError> {
        if self.pending_credential_deletion.as_ref() != Some(&(id.clone(), handle.clone())) {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        let backend = self
            .sqlite
            .as_mut()
            .ok_or(CredentialError::StorageFailure)?;
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        let conflicting_cleanup_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM provider_key_journal WHERE singleton = 1)
                    OR EXISTS (SELECT 1 FROM reset_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if conflicting_cleanup_pending {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        let journal_payload = read_protected_table_payload(
            &transaction,
            ProtectedPayloadTable::CredentialDeletionJournal,
        )?;
        let current_records = read_credential_records(&transaction, backend.protector.as_ref())?;
        let Some(journal_payload) = journal_payload else {
            if current_records
                .get(id)
                .is_some_and(|record| &record.key_handle == handle)
            {
                return Err(CredentialError::ProviderKeyCleanupPending);
            }
            transaction
                .commit()
                .map_err(|_| CredentialError::StorageFailure)?;
            self.next_creation_order = current_records
                .values()
                .map(|record| record.creation_order)
                .max()
                .unwrap_or(0);
            self.records = current_records;
            self.pending_credential_deletion = None;
            return Ok(());
        };
        validate_protected_payload(&journal_payload)?;
        let journal_plaintext = backend
            .protector
            .unprotect(&journal_payload, CREDENTIAL_DELETION_JOURNAL_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        if decode_credential_deletion_journal(&journal_plaintext)? != (id.clone(), handle.clone()) {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        let mut next_records = current_records;
        if let Some(record) = next_records.get(id) {
            if &record.key_handle != handle {
                return Err(CredentialError::ProviderKeyCleanupPending);
            }
            next_records.remove(id);
        }
        let plaintext = encode_records(&next_records)?;
        let protected = backend
            .protector
            .protect(&plaintext, STORAGE_AAD_V4)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected)?;
        write_payload(&transaction, &protected)?;
        transaction
            .execute(
                "DELETE FROM credential_deletion_journal WHERE singleton = 1",
                [],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        self.next_creation_order = next_records
            .values()
            .map(|record| record.creation_order)
            .max()
            .unwrap_or(0);
        self.records = next_records;
        self.pending_credential_deletion = None;
        Ok(())
    }

    /// Durably reserves the opaque provider reference before key creation.
    pub fn begin_provider_key_creation(
        &mut self,
        handle: KeyHandle,
    ) -> Result<(), CredentialError> {
        if self.reset_is_pending() || self.provider_key_cleanup_pending() {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        let backend = self
            .sqlite
            .as_mut()
            .ok_or(CredentialError::StorageFailure)?;
        let protected = backend
            .protector
            .protect(handle.as_bytes(), PROVIDER_KEY_JOURNAL_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected)?;
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        let conflicting_cleanup_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM credential_deletion_journal WHERE singleton = 1
                ) OR EXISTS (SELECT 1 FROM reset_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if conflicting_cleanup_pending {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        transaction
            .execute(
                "INSERT INTO provider_key_journal (singleton, payload) VALUES (1, ?1)",
                params![protected],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        self.pending_provider_key = Some(handle);
        Ok(())
    }

    /// Clears a reserved key reference only after its provider key is deleted.
    pub fn mark_provider_key_deleted(&mut self, handle: &KeyHandle) -> Result<(), CredentialError> {
        if self.pending_provider_key.as_ref() != Some(handle) {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        let backend = self
            .sqlite
            .as_mut()
            .ok_or(CredentialError::StorageFailure)?;
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        if read_provider_key_journal(&transaction, backend.protector.as_ref())?.as_ref()
            != Some(handle)
        {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        transaction
            .execute("DELETE FROM provider_key_journal WHERE singleton = 1", [])
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        self.pending_provider_key = None;
        Ok(())
    }

    #[must_use]
    pub fn metadata_key_cleanup_pending(&self) -> bool {
        self.metadata_key_cleanup_pending
    }

    #[must_use]
    pub fn pending_reset_key_handles(&self) -> Option<&[KeyHandle]> {
        self.pending_reset_keys.as_deref()
    }

    /// Durably records the key references before reset starts deleting keys.
    pub fn begin_reset(&mut self) -> Result<(), CredentialError> {
        if self.provider_key_cleanup_pending() {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        if self.metadata_key_cleanup_pending {
            return Err(CredentialError::ResetInProgress);
        }
        if let Some(handles) = self.pending_reset_keys.clone() {
            self.persist_reset_journal(&handles)?;
            return Ok(());
        }
        let local_handles = self.provider_key_handles();
        if !local_handles.is_empty() && self.sqlite.is_none() {
            return Err(CredentialError::StorageFailure);
        }
        if local_handles.is_empty()
            && self
                .sqlite
                .as_ref()
                .is_some_and(|backend| !backend.initialized)
        {
            return Ok(());
        }
        let handles = if self.sqlite.is_some() {
            self.begin_reset_journal_from_storage()?
        } else {
            local_handles
        };
        self.pending_reset_keys = Some(handles.clone());
        self.records.clear();
        self.pin_state = PinState::default();
        self.large_blob_array = Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec());
        self.next_creation_order = 0;
        if self.sqlite.is_none() {
            self.persist_reset_journal(&handles)?;
        }
        Ok(())
    }

    /// Removes a key from the durable cleanup journal after provider deletion.
    pub fn mark_reset_key_deleted(&mut self, handle: &KeyHandle) -> Result<(), CredentialError> {
        let pending = self
            .pending_reset_keys
            .as_ref()
            .ok_or(CredentialError::ResetInProgress)?;
        if !pending.contains(handle) {
            return Err(CredentialError::NotFound);
        }
        let remaining: Vec<_> = pending
            .iter()
            .filter(|candidate| *candidate != handle)
            .cloned()
            .collect();
        self.persist_reset_journal(&remaining)?;
        self.pending_reset_keys = Some(remaining);
        Ok(())
    }

    /// Completes reset only after every provider key has been removed.
    pub fn finish_reset(&mut self) -> Result<(), CredentialError> {
        if self
            .pending_reset_keys
            .as_ref()
            .is_none_or(|pending| !pending.is_empty())
        {
            return Err(CredentialError::ResetInProgress);
        }
        self.persist_reset_for_key_cleanup()?;
        self.pending_reset_keys = None;
        self.metadata_key_cleanup_pending = self.sqlite.is_some();
        self.records.clear();
        self.pin_state = PinState::default();
        self.next_creation_order = 0;
        Ok(())
    }

    /// Deletes app-managed metadata-key material and atomically clears the
    /// durable cleanup marker. Retrying never loads or creates a key before
    /// erasing the prior one.
    pub fn complete_metadata_key_cleanup(&mut self) -> Result<(), CredentialError> {
        if !self.metadata_key_cleanup_pending {
            return Ok(());
        }
        let backend = self
            .sqlite
            .as_mut()
            .ok_or(CredentialError::StorageFailure)?;
        backend
            .protector
            .erase_key()
            .map_err(|_| CredentialError::StorageFailure)?;

        let transaction = backend
            .connection
            .transaction()
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .execute_batch(
                "DROP TABLE credential_store;
                 DROP TABLE pin_state;
                 DROP TABLE IF EXISTS large_blob_state;
                 DROP TABLE reset_journal;
                 DROP TABLE provider_key_journal;",
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .pragma_update(None, "user_version", 0)
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        self.metadata_key_cleanup_pending = false;
        backend.initialized = false;
        Ok(())
    }

    /// Atomically clears persisted credential metadata without removing the
    /// protected database or its metadata-encryption key.
    pub fn clear(&mut self) -> Result<usize, CredentialError> {
        if self.reset_is_pending() {
            return Err(CredentialError::ResetInProgress);
        }
        let count = self.records.len();
        self.persist_reset()?;
        self.records.clear();
        self.pin_state = PinState::default();
        self.large_blob_array = Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec());
        Ok(count)
    }

    #[must_use]
    pub fn pin_state(&self) -> &PinState {
        &self.pin_state
    }

    #[must_use]
    pub fn large_blob_array(&self) -> &[u8] {
        &self.large_blob_array
    }

    #[must_use]
    pub fn supports_large_blobs(&self) -> bool {
        self.sqlite
            .as_ref()
            .is_some_and(|backend| backend.initialized)
            && !self.reset_is_pending()
            && !self.metadata_key_cleanup_pending
    }

    /// Replaces the protected LargeBlobs array after the caller validates its digest.
    pub fn replace_large_blob_array(&mut self, array: &[u8]) -> Result<(), CredentialError> {
        if !(17..=MAX_SERIALIZED_LARGE_BLOB_ARRAY).contains(&array.len()) {
            return Err(CredentialError::ProtectedDataInvalid);
        }
        if !valid_serialized_large_blob_array(array) {
            return Err(CredentialError::ProtectedDataInvalid);
        }
        if self.reset_is_pending() || self.metadata_key_cleanup_pending {
            return Err(CredentialError::ResetInProgress);
        }
        self.ensure_sqlite_initialized()?;
        let Some(backend) = self.sqlite.as_mut() else {
            return Err(CredentialError::StorageFailure);
        };
        let protected = backend
            .protector
            .protect(array, LARGE_BLOB_ARRAY_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected)?;
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        let reset_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM reset_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if reset_pending {
            return Err(CredentialError::ResetInProgress);
        }
        let current = read_large_blob_array(&transaction, backend.protector.as_ref())?;
        if current.as_slice() != self.large_blob_array.as_slice() {
            self.large_blob_array = current;
            return Err(CredentialError::StorageFailure);
        }
        write_large_blob_array(&transaction, &protected)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        self.large_blob_array = Zeroizing::new(array.to_vec());
        Ok(())
    }

    /// Refreshes credential and PIN state from the shared protected store.
    ///
    /// Returns whether credential or PIN state changed, or stale cached
    /// cleanup state was cleared after its journal disappeared. A newly
    /// observed cleanup journal is rejected so the caller fails closed.
    pub fn refresh_shared_state(&mut self) -> Result<bool, CredentialError> {
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(false);
        };

        let snapshot = {
            let transaction = backend
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| CredentialError::StorageFailure)?;
            let metadata_key_cleanup_pending: i64 = transaction
                .query_row(
                    "SELECT COALESCE((
                        SELECT metadata_key_cleanup FROM reset_journal WHERE singleton = 1
                    ), 0)",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| CredentialError::StorageFailure)?;
            if !(0..=1).contains(&metadata_key_cleanup_pending) {
                return Err(CredentialError::ProtectedDataInvalid);
            }

            let protected_reset =
                read_protected_table_payload(&transaction, ProtectedPayloadTable::ResetJournal)?;
            let metadata_key_cleanup_pending = metadata_key_cleanup_pending != 0;
            let pending_reset_keys = if metadata_key_cleanup_pending {
                None
            } else if let Some(protected) = protected_reset.as_deref() {
                validate_protected_payload(protected)?;
                let plaintext = backend
                    .protector
                    .unprotect(protected, RESET_JOURNAL_AAD_V1)
                    .map_err(|_| CredentialError::ProtectedDataInvalid)?;
                Some(decode_reset_journal(&plaintext)?)
            } else {
                None
            };

            let has_provider_key_journal: bool = transaction
                .query_row(
                    "SELECT EXISTS (
                        SELECT 1 FROM provider_key_journal WHERE singleton = 1
                    )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| CredentialError::StorageFailure)?;
            let has_credential_deletion_journal: bool = transaction
                .query_row(
                    "SELECT EXISTS (
                        SELECT 1 FROM credential_deletion_journal WHERE singleton = 1
                    )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| CredentialError::StorageFailure)?;
            if (metadata_key_cleanup_pending || pending_reset_keys.is_some())
                && (has_provider_key_journal || has_credential_deletion_journal)
            {
                return Err(CredentialError::ProtectedDataInvalid);
            }

            let (
                records,
                pin_state,
                large_blob_array,
                pending_provider_key,
                pending_credential_deletion,
            ) = if metadata_key_cleanup_pending || pending_reset_keys.is_some() {
                (None, None, None, None, None)
            } else {
                let records = read_credential_records(&transaction, backend.protector.as_ref())?;
                let pin_state = read_pin_state(&transaction, backend.protector.as_ref())?;
                let large_blob_array =
                    read_large_blob_array(&transaction, backend.protector.as_ref())?;
                let pending_provider_key =
                    read_provider_key_journal(&transaction, backend.protector.as_ref())?;
                let pending_credential_deletion = read_credential_deletion_journal(
                    &transaction,
                    backend.protector.as_ref(),
                    &records,
                )?;
                (
                    Some(records),
                    Some(pin_state),
                    Some(large_blob_array),
                    pending_provider_key,
                    pending_credential_deletion,
                )
            };
            if pending_provider_key.is_some() && pending_credential_deletion.is_some() {
                return Err(CredentialError::ProtectedDataInvalid);
            }

            transaction
                .commit()
                .map_err(|_| CredentialError::StorageFailure)?;
            (
                metadata_key_cleanup_pending,
                pending_reset_keys,
                records,
                pin_state,
                large_blob_array,
                pending_provider_key,
                pending_credential_deletion,
            )
        };

        let (
            metadata_key_cleanup_pending,
            pending_reset_keys,
            records,
            pin_state,
            large_blob_array,
            pending_provider_key,
            pending_credential_deletion,
        ) = snapshot;
        let has_pending_cleanup = metadata_key_cleanup_pending
            || pending_reset_keys.is_some()
            || pending_provider_key.is_some()
            || pending_credential_deletion.is_some();
        if has_pending_cleanup {
            let matches_cached_state = self.metadata_key_cleanup_pending
                == metadata_key_cleanup_pending
                && self.pending_reset_keys == pending_reset_keys
                && self.pending_provider_key == pending_provider_key
                && self.pending_credential_deletion == pending_credential_deletion;
            if !matches_cached_state {
                return Err(
                    if metadata_key_cleanup_pending || pending_reset_keys.is_some() {
                        CredentialError::ResetInProgress
                    } else {
                        CredentialError::ProviderKeyCleanupPending
                    },
                );
            }
            return Ok(false);
        }

        let records = records.ok_or(CredentialError::StorageFailure)?;
        let pin_state = pin_state.ok_or(CredentialError::StorageFailure)?;
        let large_blob_array = large_blob_array.ok_or(CredentialError::StorageFailure)?;
        let changed = self.records != records
            || self.pin_state != pin_state
            || self.large_blob_array.as_slice() != large_blob_array.as_slice()
            || self.pending_reset_keys.is_some()
            || self.metadata_key_cleanup_pending
            || self.pending_provider_key.is_some()
            || self.pending_credential_deletion.is_some();
        self.next_creation_order = records
            .values()
            .map(|record| record.creation_order)
            .max()
            .unwrap_or(0);
        self.records = records;
        self.pin_state = pin_state;
        self.large_blob_array = large_blob_array;
        self.pending_reset_keys = None;
        self.metadata_key_cleanup_pending = false;
        self.pending_provider_key = None;
        self.pending_credential_deletion = None;
        Ok(changed)
    }

    #[must_use]
    pub fn has_protected_storage(&self) -> bool {
        self.sqlite.is_some()
    }

    /// Persists PIN verifier and retry state through the credential protector.
    pub fn set_pin_state(&mut self, pin_state: PinState) -> Result<(), CredentialError> {
        pin_state.validate()?;
        self.persist_pin_state(&pin_state)?;
        self.pin_state = pin_state;
        Ok(())
    }

    /// Persists a new retry count before the corresponding protocol response is sent.
    pub fn set_pin_retries(&mut self, retries: u8) -> Result<(), CredentialError> {
        let mut next = self.pin_state.clone();
        next.retries = retries;
        self.set_pin_state(next)
    }

    /// Replaces the verifier and restores the protocol retry budget.
    pub fn set_pin_verifier(&mut self, verifier: Option<[u8; 16]>) -> Result<(), CredentialError> {
        // This legacy API cannot know the replacement PIN's length. Keep it
        // unknown rather than carrying metadata from the previous PIN.
        let length = None;
        self.set_pin_verifier_with_length(verifier, length)
    }

    /// Stores a PIN verifier and its Unicode code-point length after successful PIN setup/change.
    pub fn set_pin_verifier_with_length(
        &mut self,
        verifier: Option<[u8; 16]>,
        pin_code_point_length: Option<u8>,
    ) -> Result<(), CredentialError> {
        let mut next = self.pin_state.clone();
        next.verifier = verifier;
        next.retries = PIN_RETRY_LIMIT;
        next.pin_code_point_length = if next.verifier.is_some() {
            pin_code_point_length
        } else {
            None
        };
        if next.verifier.is_none() {
            next.force_pin_change = false;
        } else if let Some(length) = pin_code_point_length {
            // A successfully installed PIN must satisfy the active policy.
            if length < next.min_pin_length {
                return Err(CredentialError::InvalidPinState);
            }
            next.force_pin_change = false;
        } else {
            // Legacy callers cannot report the PIN length. Preserve their
            // behavior at the default policy, but require a known-compliant
            // change before using a PIN under a higher minimum.
            next.force_pin_change |= next.min_pin_length > DEFAULT_MIN_PIN_LENGTH;
        }
        self.set_pin_state(next)
    }

    /// Atomically raises minimum-PIN policy and optionally replaces its RP allowlist.
    pub fn set_min_pin_policy(
        &mut self,
        min_pin_length: u8,
        min_pin_length_rp_ids: Option<Vec<String>>,
        force_pin_change: bool,
    ) -> Result<bool, CredentialError> {
        if force_pin_change && self.pin_state.verifier.is_none() {
            return Err(CredentialError::InvalidPinState);
        }
        if !(DEFAULT_MIN_PIN_LENGTH..=MAX_MIN_PIN_LENGTH).contains(&min_pin_length)
            || min_pin_length < self.pin_state.min_pin_length
        {
            return Err(CredentialError::InvalidPinState);
        }
        let mut next = self.pin_state.clone();
        if let Some(rp_ids) = min_pin_length_rp_ids.filter(|ids| !ids.is_empty()) {
            if rp_ids.len() > MAX_RP_IDS_FOR_MIN_PIN_LENGTH {
                return Err(CredentialError::InvalidPinState);
            }
            next.min_pin_length_rp_ids = rp_ids;
        }
        next.min_pin_length = min_pin_length;
        let minimum_increased = min_pin_length > self.pin_state.min_pin_length;
        let current_pin_too_short = minimum_increased
            && next.verifier.is_some()
            && next
                .pin_code_point_length
                .is_none_or(|length| length < min_pin_length);
        let should_force_change =
            next.verifier.is_some() && (force_pin_change || current_pin_too_short);
        let newly_forced = should_force_change && !next.force_pin_change;
        next.force_pin_change |= should_force_change;
        self.set_pin_state(next)?;
        Ok(newly_forced)
    }

    #[must_use]
    pub fn by_creation_order(&self, creation_order: u64) -> Option<&CredentialRecord> {
        self.records
            .values()
            .find(|record| record.creation_order == creation_order)
    }
    pub fn increment_sign_count(&mut self, id: &CredentialId) -> Result<u32, CredentialError> {
        let record = self.records.get(id).ok_or(CredentialError::NotFound)?;
        let sign_count = record
            .sign_count
            .checked_add(1)
            .ok_or(CredentialError::CounterOverflow)?;
        let mut next_records = self.records.clone();
        next_records
            .get_mut(id)
            .ok_or(CredentialError::NotFound)?
            .sign_count = sign_count;
        self.records = self.persist(&next_records)?;
        Ok(sign_count)
    }

    /// Persists a provider-recovered public key for a legacy credential.
    pub fn set_public_key(
        &mut self,
        id: &CredentialId,
        public_key: Es256PublicKey,
    ) -> Result<(), CredentialError> {
        let record = self.records.get(id).ok_or(CredentialError::NotFound)?;
        if record.public_key.as_ref() == Some(&public_key) {
            return Ok(());
        }
        let mut next_records = self.records.clone();
        next_records
            .get_mut(id)
            .ok_or(CredentialError::NotFound)?
            .public_key = Some(public_key);
        self.persist(&next_records)?;
        self.records = next_records;
        Ok(())
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        MAX_PERSISTED_RECORDS.saturating_sub(self.records.len())
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn ensure_sqlite_initialized(&mut self) -> Result<(), CredentialError> {
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(());
        };
        if backend.initialized {
            return Ok(());
        }
        let user_tables: i64 = backend
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if user_tables != 0 {
            return Err(CredentialError::ProtectedDataInvalid);
        }
        let protected_records = backend
            .protector
            .protect(&encode_records(&BTreeMap::new())?, STORAGE_AAD_V4)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_records)?;
        let protected_pin_state = backend
            .protector
            .protect(&encode_pin_state(&PinState::default())?, PIN_STATE_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_pin_state)?;
        let protected_large_blob_array = backend
            .protector
            .protect(&INITIAL_LARGE_BLOB_ARRAY, LARGE_BLOB_ARRAY_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_large_blob_array)?;
        let transaction = backend
            .connection
            .transaction()
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .execute_batch(
                "CREATE TABLE credential_store (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL
                );
                CREATE TABLE pin_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL
                );
                CREATE TABLE large_blob_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL
                );
                CREATE TABLE reset_journal (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL,
                    metadata_key_cleanup INTEGER NOT NULL DEFAULT 0
                        CHECK (metadata_key_cleanup IN (0, 1))
                );
                CREATE TABLE provider_key_journal (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL
                );",
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .execute(
                "INSERT INTO credential_store (singleton, payload) VALUES (1, ?1)",
                params![protected_records],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .execute(
                "INSERT INTO pin_state (singleton, payload) VALUES (1, ?1)",
                params![protected_pin_state],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .execute(
                "INSERT INTO large_blob_state (singleton, payload) VALUES (1, ?1)",
                params![protected_large_blob_array],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .pragma_update(None, "user_version", STORAGE_SCHEMA_VERSION)
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        backend.initialized = true;
        Ok(())
    }

    fn persist(
        &mut self,
        records: &BTreeMap<CredentialId, CredentialRecord>,
    ) -> Result<BTreeMap<CredentialId, CredentialRecord>, CredentialError> {
        self.persist_with_provider_key_cleanup(records, None)
    }

    fn persist_with_provider_key_cleanup(
        &mut self,
        records: &BTreeMap<CredentialId, CredentialRecord>,
        created_key: Option<&KeyHandle>,
    ) -> Result<BTreeMap<CredentialId, CredentialRecord>, CredentialError> {
        if self.reset_is_pending() {
            return Err(CredentialError::ResetInProgress);
        }
        if self.pending_credential_deletion.is_some() {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        if self.pending_provider_key.as_ref() != created_key {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        self.ensure_sqlite_initialized()?;
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(records.clone());
        };
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_storage_error)?;
        let reset_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM reset_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if reset_pending {
            return Err(CredentialError::ResetInProgress);
        }
        // A different store instance may have committed a deletion journal since this one loaded.
        let credential_deletion_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM credential_deletion_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if credential_deletion_pending {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        if let Some(created_key) = created_key {
            if read_provider_key_journal(&transaction, backend.protector.as_ref())?.as_ref()
                != Some(created_key)
            {
                return Err(CredentialError::ProviderKeyCleanupPending);
            }
        }
        let current_records = read_credential_records(&transaction, backend.protector.as_ref())?;
        let merged_records =
            match merge_credential_records(&self.records, records, &current_records) {
                Ok(records) => records,
                Err(error) => {
                    drop(transaction);
                    self.records = current_records;
                    self.next_creation_order = self
                        .records
                        .values()
                        .map(|record| record.creation_order)
                        .max()
                        .unwrap_or(0);
                    return Err(error);
                }
            };
        if merged_records.len() > MAX_PERSISTED_RECORDS {
            return Err(CredentialError::RecordLimitExceeded);
        }
        let plaintext = encode_records(&merged_records)?;
        let protected = backend
            .protector
            .protect(&plaintext, STORAGE_AAD_V4)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected)?;
        write_payload(&transaction, &protected)?;
        if created_key.is_some() {
            transaction
                .execute("DELETE FROM provider_key_journal WHERE singleton = 1", [])
                .map_err(map_sqlite_storage_error)?;
        }
        transaction.commit().map_err(map_sqlite_storage_error)?;
        Ok(merged_records)
    }

    fn persist_pin_state(&mut self, pin_state: &PinState) -> Result<(), CredentialError> {
        if self.reset_is_pending() {
            return Err(CredentialError::ResetInProgress);
        }
        if self.provider_key_cleanup_pending() {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        self.ensure_sqlite_initialized()?;
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(());
        };
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        let reset_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM reset_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if reset_pending {
            return Err(CredentialError::ResetInProgress);
        }
        let current_pin_state = read_pin_state(&transaction, backend.protector.as_ref())?;
        if current_pin_state != self.pin_state {
            drop(transaction);
            self.pin_state = current_pin_state;
            return Err(CredentialError::StorageFailure);
        }
        let plaintext = encode_pin_state(pin_state)?;
        let protected = backend
            .protector
            .protect(&plaintext, PIN_STATE_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected)?;
        write_pin_payload(&transaction, &protected)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)
    }

    fn persist_reset_journal(&mut self, handles: &[KeyHandle]) -> Result<(), CredentialError> {
        self.ensure_sqlite_initialized()?;
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(());
        };
        let plaintext = encode_reset_journal(handles)?;
        let protected = backend
            .protector
            .protect(&plaintext, RESET_JOURNAL_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected)?;
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        let conflicting_cleanup_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM credential_deletion_journal WHERE singleton = 1
                ) OR EXISTS (SELECT 1 FROM provider_key_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if conflicting_cleanup_pending {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }
        transaction
            .execute(
                "INSERT INTO reset_journal (singleton, payload) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET payload = excluded.payload",
                params![protected],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)
    }

    fn begin_reset_journal_from_storage(&mut self) -> Result<Vec<KeyHandle>, CredentialError> {
        self.ensure_sqlite_initialized()?;
        let Some(backend) = self.sqlite.as_mut() else {
            return Err(CredentialError::StorageFailure);
        };
        let transaction = backend
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CredentialError::StorageFailure)?;
        let reset_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM reset_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if reset_pending {
            return Err(CredentialError::ResetInProgress);
        }
        let conflicting_cleanup_pending: bool = transaction
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM credential_deletion_journal WHERE singleton = 1
                ) OR EXISTS (SELECT 1 FROM provider_key_journal WHERE singleton = 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if conflicting_cleanup_pending {
            return Err(CredentialError::ProviderKeyCleanupPending);
        }

        let protected_records = read_protected_payload(&transaction)?;
        validate_protected_payload(&protected_records)?;
        let plaintext = backend
            .protector
            .unprotect(&protected_records, STORAGE_AAD_V4)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        let current_records = decode_records(&plaintext, 7)?;
        let handles: Vec<_> = current_records
            .values()
            .map(|record| record.key_handle.clone())
            .collect();
        let journal = encode_reset_journal(&handles)?;
        let protected_journal = backend
            .protector
            .protect(&journal, RESET_JOURNAL_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_journal)?;
        transaction
            .execute(
                "INSERT INTO reset_journal (singleton, payload) VALUES (1, ?1)",
                params![protected_journal],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)?;
        self.records = current_records;
        Ok(handles)
    }

    fn persist_reset(&mut self) -> Result<(), CredentialError> {
        self.ensure_sqlite_initialized()?;
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(());
        };
        let records = encode_records(&BTreeMap::new())?;
        let protected_records = backend
            .protector
            .protect(&records, STORAGE_AAD_V4)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_records)?;
        let pin_state = encode_pin_state(&PinState::default())?;
        let protected_pin_state = backend
            .protector
            .protect(&pin_state, PIN_STATE_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_pin_state)?;
        let protected_large_blob_array = backend
            .protector
            .protect(&INITIAL_LARGE_BLOB_ARRAY, LARGE_BLOB_ARRAY_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_large_blob_array)?;
        let transaction = backend
            .connection
            .transaction()
            .map_err(|_| CredentialError::StorageFailure)?;
        write_payload(&transaction, &protected_records)?;
        write_pin_payload(&transaction, &protected_pin_state)?;
        write_large_blob_array(&transaction, &protected_large_blob_array)?;
        transaction
            .execute("DELETE FROM reset_journal WHERE singleton = 1", [])
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)
    }

    fn persist_reset_for_key_cleanup(&mut self) -> Result<(), CredentialError> {
        self.ensure_sqlite_initialized()?;
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(());
        };
        let records = encode_records(&BTreeMap::new())?;
        let protected_records = backend
            .protector
            .protect(&records, STORAGE_AAD_V4)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_records)?;
        let pin_state = encode_pin_state(&PinState::default())?;
        let protected_pin_state = backend
            .protector
            .protect(&pin_state, PIN_STATE_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_pin_state)?;
        let protected_large_blob_array = backend
            .protector
            .protect(&INITIAL_LARGE_BLOB_ARRAY, LARGE_BLOB_ARRAY_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        validate_protected_payload(&protected_large_blob_array)?;
        let transaction = backend
            .connection
            .transaction()
            .map_err(|_| CredentialError::StorageFailure)?;
        write_payload(&transaction, &protected_records)?;
        write_pin_payload(&transaction, &protected_pin_state)?;
        write_large_blob_array(&transaction, &protected_large_blob_array)?;
        transaction
            .execute(
                "INSERT INTO reset_journal (singleton, payload, metadata_key_cleanup)
                 VALUES (1, X'', 1)
                 ON CONFLICT(singleton) DO UPDATE SET
                    payload = X'', metadata_key_cleanup = 1",
                [],
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)
    }
}

fn write_payload(transaction: &Transaction<'_>, payload: &[u8]) -> Result<(), CredentialError> {
    let updated = transaction
        .execute(
            "UPDATE credential_store SET payload = ?1 WHERE singleton = 1",
            params![payload],
        )
        .map_err(map_sqlite_storage_error)?;
    if updated != 1 {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    Ok(())
}

fn map_sqlite_storage_error(error: rusqlite::Error) -> CredentialError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
        CredentialError::StorageFull
    } else {
        CredentialError::StorageFailure
    }
}

fn read_credential_records(
    transaction: &Transaction<'_>,
    protector: &dyn CredentialProtector,
) -> Result<BTreeMap<CredentialId, CredentialRecord>, CredentialError> {
    let protected = read_protected_payload(transaction)?;
    validate_protected_payload(&protected)?;
    let plaintext = protector
        .unprotect(&protected, STORAGE_AAD_V4)
        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    decode_records(&plaintext, 7)
}

fn read_pin_state(
    transaction: &Transaction<'_>,
    protector: &dyn CredentialProtector,
) -> Result<PinState, CredentialError> {
    let protected = read_protected_table_payload(transaction, ProtectedPayloadTable::PinState)
        .map_err(|_| CredentialError::ProtectedDataInvalid)?
        .ok_or(CredentialError::ProtectedDataInvalid)?;
    validate_protected_payload(&protected)?;
    let plaintext = protector
        .unprotect(&protected, PIN_STATE_AAD_V1)
        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    decode_pin_state(&plaintext)
}

fn read_large_blob_array(
    transaction: &Transaction<'_>,
    protector: &dyn CredentialProtector,
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    let protected =
        read_protected_table_payload(transaction, ProtectedPayloadTable::LargeBlobState)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?
            .ok_or(CredentialError::ProtectedDataInvalid)?;
    validate_protected_payload(&protected)?;
    let plaintext = Zeroizing::new(
        protector
            .unprotect(&protected, LARGE_BLOB_ARRAY_AAD_V1)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?,
    );
    if !(17..=MAX_SERIALIZED_LARGE_BLOB_ARRAY).contains(&plaintext.len())
        || !valid_serialized_large_blob_array(&plaintext)
    {
        return Ok(Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec()));
    }
    Ok(Zeroizing::new(plaintext.to_vec()))
}

fn valid_serialized_large_blob_array(array: &[u8]) -> bool {
    if array.len() < 17 || array.len() > MAX_SERIALIZED_LARGE_BLOB_ARRAY {
        return false;
    }
    let content_length = array.len() - 16;
    let hash = Sha256::digest(&array[..content_length]);
    array[content_length..] == hash[..16]
}

fn write_large_blob_array(
    transaction: &Transaction<'_>,
    payload: &[u8],
) -> Result<(), CredentialError> {
    let updated = transaction
        .execute(
            "UPDATE large_blob_state SET payload = ?1 WHERE singleton = 1",
            params![payload],
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if updated != 1 {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    Ok(())
}

fn initialize_large_blob_array(
    connection: &mut Connection,
    protector: &dyn CredentialProtector,
    schema_version: i64,
    metadata_key_cleanup_pending: bool,
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CredentialError::StorageFailure)?;
    let table_exists: bool = transaction
        .query_row(
            "SELECT EXISTS (
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'large_blob_state'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if !table_exists && schema_version >= STORAGE_SCHEMA_VERSION {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    if !table_exists {
        transaction
            .execute_batch(
                "CREATE TABLE large_blob_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL
                );",
            )
            .map_err(|_| CredentialError::StorageFailure)?;
    }

    let payload =
        read_protected_table_payload(&transaction, ProtectedPayloadTable::LargeBlobState)?;
    let array = match payload {
        Some(_payload) if metadata_key_cleanup_pending => {
            Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec())
        }
        Some(payload) => {
            validate_protected_payload(&payload)?;
            let plaintext = Zeroizing::new(
                protector
                    .unprotect(&payload, LARGE_BLOB_ARRAY_AAD_V1)
                    .map_err(|_| CredentialError::ProtectedDataInvalid)?,
            );
            if !(17..=MAX_SERIALIZED_LARGE_BLOB_ARRAY).contains(&plaintext.len())
                || !valid_serialized_large_blob_array(&plaintext)
            {
                return Ok(Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec()));
            }
            Zeroizing::new(plaintext.to_vec())
        }
        None if metadata_key_cleanup_pending => Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec()),
        None if schema_version < STORAGE_SCHEMA_VERSION => {
            let protected = protector
                .protect(&INITIAL_LARGE_BLOB_ARRAY, LARGE_BLOB_ARRAY_AAD_V1)
                .map_err(|_| CredentialError::ProtectedDataInvalid)?;
            validate_protected_payload(&protected)?;
            transaction
                .execute(
                    "INSERT INTO large_blob_state (singleton, payload) VALUES (1, ?1)",
                    params![protected],
                )
                .map_err(|_| CredentialError::StorageFailure)?;
            Zeroizing::new(INITIAL_LARGE_BLOB_ARRAY.to_vec())
        }
        None => return Err(CredentialError::ProtectedDataInvalid),
    };
    transaction
        .pragma_update(None, "user_version", STORAGE_SCHEMA_VERSION)
        .map_err(|_| CredentialError::StorageFailure)?;
    transaction
        .commit()
        .map_err(|_| CredentialError::StorageFailure)?;
    Ok(array)
}

fn read_provider_key_journal(
    transaction: &Transaction<'_>,
    protector: &dyn CredentialProtector,
) -> Result<Option<KeyHandle>, CredentialError> {
    let payload =
        read_protected_table_payload(transaction, ProtectedPayloadTable::ProviderKeyJournal)?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    validate_protected_payload(&payload)?;
    let plaintext = protector
        .unprotect(&payload, PROVIDER_KEY_JOURNAL_AAD_V1)
        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    KeyHandle::new(plaintext.to_vec())
        .map(Some)
        .map_err(|_| CredentialError::ProtectedDataInvalid)
}

fn read_credential_deletion_journal(
    transaction: &Transaction<'_>,
    protector: &dyn CredentialProtector,
    records: &BTreeMap<CredentialId, CredentialRecord>,
) -> Result<Option<(CredentialId, KeyHandle)>, CredentialError> {
    let payload = read_protected_table_payload(
        transaction,
        ProtectedPayloadTable::CredentialDeletionJournal,
    )?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    validate_protected_payload(&payload)?;
    let plaintext = protector
        .unprotect(&payload, CREDENTIAL_DELETION_JOURNAL_AAD_V1)
        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    let (id, handle) = decode_credential_deletion_journal(&plaintext)?;
    if records.get(&id).map(|record| &record.key_handle) != Some(&handle) {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    Ok(Some((id, handle)))
}

fn merge_credential_records(
    base: &BTreeMap<CredentialId, CredentialRecord>,
    desired: &BTreeMap<CredentialId, CredentialRecord>,
    current: &BTreeMap<CredentialId, CredentialRecord>,
) -> Result<BTreeMap<CredentialId, CredentialRecord>, CredentialError> {
    let changed_ids: BTreeSet<_> = base.keys().chain(desired.keys()).cloned().collect();
    let mut merged = current.clone();
    let mut creation_order = current
        .values()
        .map(|record| record.creation_order)
        .max()
        .unwrap_or(0);

    for id in changed_ids {
        let before = base.get(&id);
        let after = desired.get(&id);
        if before == after {
            continue;
        }
        let persisted = current.get(&id);
        if persisted != before {
            return Err(CredentialError::StorageFailure);
        }
        match after {
            Some(record) => {
                let mut record = record.clone();
                if before.is_none() && persisted.is_none() {
                    creation_order = creation_order
                        .checked_add(1)
                        .ok_or(CredentialError::CreationOrderOverflow)?;
                    record.creation_order = creation_order;
                }
                merged.insert(id, record);
            }
            None => {
                merged.remove(&id);
            }
        }
    }

    Ok(merged)
}

fn write_pin_payload(transaction: &Transaction<'_>, payload: &[u8]) -> Result<(), CredentialError> {
    let updated = transaction
        .execute(
            "UPDATE pin_state SET payload = ?1 WHERE singleton = 1",
            params![payload],
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if updated != 1 {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    Ok(())
}

fn prepare_reset_journal_schema(
    connection: &mut Connection,
    schema_version: i64,
) -> Result<bool, CredentialError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CredentialError::StorageFailure)?;
    let table_exists: bool = transaction
        .query_row(
            "SELECT EXISTS (
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'reset_journal'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if !table_exists && schema_version >= RESET_JOURNAL_SCHEMA_VERSION {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    if !table_exists {
        transaction
            .execute_batch(
                "CREATE TABLE reset_journal (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL,
                    metadata_key_cleanup INTEGER NOT NULL DEFAULT 0
                        CHECK (metadata_key_cleanup IN (0, 1))
                );",
            )
            .map_err(|_| CredentialError::StorageFailure)?;
    } else {
        let cleanup_column_exists: bool = transaction
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM pragma_table_info('reset_journal')
                    WHERE name = 'metadata_key_cleanup'
                )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CredentialError::StorageFailure)?;
        if !cleanup_column_exists && schema_version >= RESET_METADATA_KEY_CLEANUP_SCHEMA_VERSION {
            return Err(CredentialError::ProtectedDataInvalid);
        }
        if !cleanup_column_exists {
            transaction
                .execute_batch(
                    "ALTER TABLE reset_journal ADD COLUMN metadata_key_cleanup INTEGER
                        NOT NULL DEFAULT 0 CHECK (metadata_key_cleanup IN (0, 1));",
                )
                .map_err(|_| CredentialError::StorageFailure)?;
        }
    }
    let pending: i64 = transaction
        .query_row(
            "SELECT COALESCE((
                SELECT metadata_key_cleanup FROM reset_journal WHERE singleton = 1
            ), 0)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if !(0..=1).contains(&pending) {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let creation_table_exists: bool = transaction
        .query_row(
            "SELECT EXISTS (
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'provider_key_journal'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if !creation_table_exists && schema_version >= PROVIDER_KEY_JOURNAL_SCHEMA_VERSION {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    if !creation_table_exists {
        transaction
            .execute_batch(
                "CREATE TABLE provider_key_journal (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL
                );",
            )
            .map_err(|_| CredentialError::StorageFailure)?;
    }
    transaction
        .commit()
        .map_err(|_| CredentialError::StorageFailure)?;
    Ok(pending == 1)
}

fn initialize_provider_key_journal(
    connection: &mut Connection,
    protector: &dyn CredentialProtector,
) -> Result<Option<KeyHandle>, CredentialError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CredentialError::StorageFailure)?;
    let payload =
        read_protected_table_payload(&transaction, ProtectedPayloadTable::ProviderKeyJournal)?;
    transaction
        .commit()
        .map_err(|_| CredentialError::StorageFailure)?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    validate_protected_payload(&payload)?;
    let plaintext = protector
        .unprotect(&payload, PROVIDER_KEY_JOURNAL_AAD_V1)
        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    KeyHandle::new(plaintext.to_vec()).map(Some)
}

fn prepare_credential_deletion_schema(
    connection: &mut Connection,
    schema_version: i64,
) -> Result<(), CredentialError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CredentialError::StorageFailure)?;
    let table_exists: bool = transaction
        .query_row(
            "SELECT EXISTS (
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'credential_deletion_journal'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if !table_exists && schema_version >= STORAGE_SCHEMA_VERSION {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    if !table_exists {
        transaction
            .execute_batch(
                "CREATE TABLE credential_deletion_journal (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload BLOB NOT NULL
                );",
            )
            .map_err(|_| CredentialError::StorageFailure)?;
    }
    transaction
        .pragma_update(None, "user_version", STORAGE_SCHEMA_VERSION)
        .map_err(|_| CredentialError::StorageFailure)?;
    transaction
        .commit()
        .map_err(|_| CredentialError::StorageFailure)
}

fn initialize_credential_deletion_journal(
    connection: &mut Connection,
    protector: &dyn CredentialProtector,
    records: &BTreeMap<CredentialId, CredentialRecord>,
) -> Result<Option<(CredentialId, KeyHandle)>, CredentialError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CredentialError::StorageFailure)?;
    let payload = read_protected_table_payload(
        &transaction,
        ProtectedPayloadTable::CredentialDeletionJournal,
    )?;
    transaction
        .commit()
        .map_err(|_| CredentialError::StorageFailure)?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    validate_protected_payload(&payload)?;
    let plaintext = protector
        .unprotect(&payload, CREDENTIAL_DELETION_JOURNAL_AAD_V1)
        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    let (id, handle) = decode_credential_deletion_journal(&plaintext)?;
    if records.get(&id).map(|record| &record.key_handle) != Some(&handle) {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    Ok(Some((id, handle)))
}

fn encode_credential_deletion_journal(
    id: &CredentialId,
    handle: &KeyHandle,
) -> Result<Vec<u8>, CredentialError> {
    encode_cbor(&CborValue::Array(vec![
        CborValue::Bytes(id.as_bytes().to_vec()),
        CborValue::Bytes(handle.as_bytes().to_vec()),
    ]))
    .map_err(CredentialError::CborEncoding)
}

fn decode_credential_deletion_journal(
    plaintext: &[u8],
) -> Result<(CredentialId, KeyHandle), CredentialError> {
    let value = decode_with_limits(
        plaintext,
        CborLimits {
            max_depth: 2,
            max_items: 4,
            max_bytes: MAX_PERSISTED_BYTES,
        },
    )
    .map_err(CredentialError::CborEncoding)?;
    let CborValue::Array(mut fields) = value else {
        return Err(CredentialError::ProtectedDataInvalid);
    };
    if fields.len() != 2 {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let handle = match fields.pop() {
        Some(CborValue::Bytes(bytes)) => {
            KeyHandle::new(bytes).map_err(|_| CredentialError::ProtectedDataInvalid)?
        }
        _ => return Err(CredentialError::ProtectedDataInvalid),
    };
    let id = match fields.pop() {
        Some(CborValue::Bytes(bytes)) => {
            CredentialId::new(bytes).map_err(|_| CredentialError::ProtectedDataInvalid)?
        }
        _ => return Err(CredentialError::ProtectedDataInvalid),
    };
    Ok((id, handle))
}

fn initialize_reset_journal(
    connection: &mut Connection,
    protector: &dyn CredentialProtector,
) -> Result<Option<Vec<KeyHandle>>, CredentialError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CredentialError::StorageFailure)?;
    let cleanup_pending: i64 = transaction
        .query_row(
            "SELECT COALESCE((
                SELECT metadata_key_cleanup FROM reset_journal WHERE singleton = 1
            ), 0)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    if cleanup_pending != 0 {
        return Err(CredentialError::ResetInProgress);
    }
    let protected =
        read_protected_table_payload(&transaction, ProtectedPayloadTable::ResetJournal)?;
    let pending = match protected {
        Some(protected) => {
            validate_protected_payload(&protected)?;
            let plaintext = protector
                .unprotect(&protected, RESET_JOURNAL_AAD_V1)
                .map_err(|_| CredentialError::ProtectedDataInvalid)?;
            Some(decode_reset_journal(&plaintext)?)
        }
        None => None,
    };
    transaction
        .commit()
        .map_err(|_| CredentialError::StorageFailure)?;
    Ok(pending)
}

fn encode_reset_journal(handles: &[KeyHandle]) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    if handles.len() > MAX_PERSISTED_RECORDS {
        return Err(CredentialError::RecordLimitExceeded);
    }
    let value = CborValue::Array(
        handles
            .iter()
            .map(|handle| CborValue::Bytes(handle.as_bytes().to_vec()))
            .collect(),
    );
    let encoded = Zeroizing::new(encode_cbor(&value).map_err(CredentialError::CborEncoding)?);
    if encoded.len() > MAX_PERSISTED_BYTES {
        return Err(CredentialError::RecordLimitExceeded);
    }
    Ok(encoded)
}

fn decode_reset_journal(plaintext: &[u8]) -> Result<Vec<KeyHandle>, CredentialError> {
    let value = decode_with_limits(
        plaintext,
        CborLimits {
            max_depth: 2,
            max_items: MAX_PERSISTED_RECORDS + 1,
            max_bytes: MAX_PERSISTED_BYTES,
        },
    )
    .map_err(CredentialError::CborEncoding)?;
    let CborValue::Array(handles) = value else {
        return Err(CredentialError::ProtectedDataInvalid);
    };
    if handles.len() > MAX_PERSISTED_RECORDS {
        return Err(CredentialError::RecordLimitExceeded);
    }
    handles
        .into_iter()
        .map(|handle| match handle {
            CborValue::Bytes(bytes) => {
                KeyHandle::new(bytes).map_err(|_| CredentialError::ProtectedDataInvalid)
            }
            _ => Err(CredentialError::ProtectedDataInvalid),
        })
        .collect()
}

fn initialize_pin_state(
    connection: &mut Connection,
    protector: &dyn CredentialProtector,
    schema_version: i64,
) -> Result<PinState, CredentialError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CredentialError::StorageFailure)?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS pin_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                payload BLOB NOT NULL
            );",
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    let payload = read_protected_table_payload(&transaction, ProtectedPayloadTable::PinState)?;
    let state = match payload {
        Some(protected) => {
            validate_protected_payload(&protected)?;
            let plaintext = protector
                .unprotect(&protected, PIN_STATE_AAD_V1)
                .map_err(|_| CredentialError::ProtectedDataInvalid)?;
            decode_pin_state(&plaintext)?
        }
        None if schema_version < PIN_STATE_SCHEMA_VERSION => {
            let state = PinState::default();
            let pin_state = encode_pin_state(&state)?;
            let protected = protector
                .protect(&pin_state, PIN_STATE_AAD_V1)
                .map_err(|_| CredentialError::ProtectedDataInvalid)?;
            validate_protected_payload(&protected)?;
            transaction
                .execute(
                    "INSERT INTO pin_state (singleton, payload) VALUES (1, ?1)",
                    params![protected],
                )
                .map_err(|_| CredentialError::StorageFailure)?;
            state
        }
        None => return Err(CredentialError::ProtectedDataInvalid),
    };
    transaction
        .pragma_update(None, "user_version", STORAGE_SCHEMA_VERSION)
        .map_err(|_| CredentialError::StorageFailure)?;
    transaction
        .commit()
        .map_err(|_| CredentialError::StorageFailure)?;
    Ok(state)
}

fn encode_pin_state(state: &PinState) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    state.validate()?;
    let value = Zeroizing::new(CborValue::Array(vec![
        state
            .verifier
            .as_ref()
            .map_or(CborValue::Null, |bytes| CborValue::Bytes(bytes.to_vec())),
        CborValue::Unsigned(u64::from(state.retries)),
        CborValue::Unsigned(u64::from(state.min_pin_length)),
        state
            .pin_code_point_length
            .map_or(CborValue::Null, |length| {
                CborValue::Unsigned(u64::from(length))
            }),
        CborValue::Bool(state.force_pin_change),
        CborValue::Array(
            state
                .min_pin_length_rp_ids
                .iter()
                .cloned()
                .map(CborValue::Text)
                .collect(),
        ),
    ]));
    encode_cbor(&value)
        .map(Zeroizing::new)
        .map_err(CredentialError::CborEncoding)
}

fn decode_pin_state(bytes: &[u8]) -> Result<PinState, CredentialError> {
    let value = Zeroizing::new(
        decode_with_limits(
            bytes,
            CborLimits {
                max_depth: 3,
                max_items: 32,
                max_bytes: 4096,
            },
        )
        .map_err(|_| CredentialError::ProtectedDataInvalid)?,
    );
    let CborValue::Array(fields) = &*value else {
        return Err(CredentialError::ProtectedDataInvalid);
    };
    if fields.len() != 2 && fields.len() != 6 {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let [verifier, CborValue::Unsigned(retries), rest @ ..] = fields.as_slice() else {
        return Err(CredentialError::ProtectedDataInvalid);
    };
    let verifier = match verifier {
        CborValue::Null => None,
        CborValue::Bytes(bytes) if bytes.len() == 16 => {
            Some(bytes.as_slice().try_into().expect("length checked"))
        }
        _ => return Err(CredentialError::ProtectedDataInvalid),
    };
    let retries = u8::try_from(*retries).map_err(|_| CredentialError::ProtectedDataInvalid)?;
    if retries > PIN_RETRY_LIMIT || (verifier.is_none() && retries != PIN_RETRY_LIMIT) {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let state = if rest.is_empty() {
        // Older protected records did not store PIN length. Keep it unknown so
        // a later policy increase conservatively requires a PIN change.
        PinState {
            verifier,
            retries,
            min_pin_length: DEFAULT_MIN_PIN_LENGTH,
            pin_code_point_length: None,
            force_pin_change: false,
            min_pin_length_rp_ids: Vec::new(),
        }
    } else {
        let [
            CborValue::Unsigned(min_pin_length),
            pin_code_point_length,
            CborValue::Bool(force_pin_change),
            CborValue::Array(rp_ids),
        ] = rest
        else {
            return Err(CredentialError::ProtectedDataInvalid);
        };
        let min_pin_length =
            u8::try_from(*min_pin_length).map_err(|_| CredentialError::ProtectedDataInvalid)?;
        let pin_code_point_length = match pin_code_point_length {
            CborValue::Null => None,
            CborValue::Unsigned(length) => {
                Some(u8::try_from(*length).map_err(|_| CredentialError::ProtectedDataInvalid)?)
            }
            _ => return Err(CredentialError::ProtectedDataInvalid),
        };
        let rp_ids = rp_ids
            .iter()
            .map(|rp_id| match rp_id {
                CborValue::Text(rp_id) => Ok(rp_id.clone()),
                _ => Err(CredentialError::ProtectedDataInvalid),
            })
            .collect::<Result<Vec<_>, _>>()?;
        PinState {
            verifier,
            retries,
            min_pin_length,
            pin_code_point_length,
            force_pin_change: *force_pin_change,
            min_pin_length_rp_ids: rp_ids,
        }
    };
    state
        .validate()
        .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    Ok(state)
}

#[derive(Clone, Copy)]
enum ProtectedPayloadTable {
    CredentialStore,
    PinState,
    LargeBlobState,
    ResetJournal,
    ProviderKeyJournal,
    CredentialDeletionJournal,
}

impl ProtectedPayloadTable {
    fn name(self) -> &'static str {
        match self {
            Self::CredentialStore => "credential_store",
            Self::PinState => "pin_state",
            Self::LargeBlobState => "large_blob_state",
            Self::ResetJournal => "reset_journal",
            Self::ProviderKeyJournal => "provider_key_journal",
            Self::CredentialDeletionJournal => "credential_deletion_journal",
        }
    }
}

fn read_protected_table_payload(
    connection: &Connection,
    table: ProtectedPayloadTable,
) -> Result<Option<Vec<u8>>, CredentialError> {
    let table_name = table.name();
    let payload_row: Option<(i64, Option<Vec<u8>>)> = connection
        .query_row(
            // SQLite columns can contain TEXT despite BLOB affinity. The CASE must remain lazy so
            // length() is never evaluated on an untrusted TEXT value before rejecting its type.
            // Keep the size check and payload selection in one statement so concurrent updates
            // cannot replace a checked small value with an oversized value before materializing it.
            &format!(
                "SELECT CASE WHEN typeof(payload) = 'blob' THEN length(payload) ELSE -1 END, \
                 CASE WHEN typeof(payload) = 'blob' THEN \
                     CASE WHEN length(payload) > 0 AND length(payload) <= ?1 \
                          THEN payload ELSE NULL END \
                 ELSE NULL END \
                 FROM {table_name} WHERE singleton = 1"
            ),
            [MAX_PROTECTED_BYTES as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| CredentialError::StorageFailure)?;
    let Some((payload_size, payload)) = payload_row else {
        return Ok(None);
    };
    if payload_size <= 0
        || usize::try_from(payload_size).map_or(true, |size| size > MAX_PROTECTED_BYTES)
    {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let payload = payload.ok_or(CredentialError::ProtectedDataInvalid)?;
    if payload.len()
        != usize::try_from(payload_size).map_err(|_| CredentialError::ProtectedDataInvalid)?
    {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    Ok(Some(payload))
}

fn read_protected_payload(connection: &Connection) -> Result<Vec<u8>, CredentialError> {
    read_protected_table_payload(connection, ProtectedPayloadTable::CredentialStore)?
        .ok_or(CredentialError::ProtectedDataInvalid)
}

fn validate_protected_payload(payload: &[u8]) -> Result<(), CredentialError> {
    if payload.is_empty() || payload.len() > MAX_PROTECTED_BYTES {
        Err(CredentialError::ProtectedDataInvalid)
    } else {
        Ok(())
    }
}

fn encode_records(
    records: &BTreeMap<CredentialId, CredentialRecord>,
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    if records.len() > MAX_PERSISTED_RECORDS {
        return Err(CredentialError::RecordLimitExceeded);
    }
    if records.values().any(|record| {
        record.cred_blob.as_ref().is_some_and(|blob| {
            blob.as_bytes().len() > MAX_CREDENTIAL_BLOB_LENGTH || !record.discoverable
        })
    }) {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let values = records
        .values()
        .map(|record| {
            let protection = match record.key_metadata.protection {
                CredentialKeyProtection::HardwareBacked => 0,
                CredentialKeyProtection::OsProtected => 1,
                CredentialKeyProtection::Software => 2,
            };
            CborValue::Array(vec![
                CborValue::Bytes(record.id.as_bytes().to_vec()),
                CborValue::Bytes(record.rp_id_hash.to_vec()),
                CborValue::Bytes(record.user_handle.clone()),
                CborValue::Bytes(record.key_handle.as_bytes().to_vec()),
                CborValue::Unsigned(protection),
                CborValue::Bool(record.key_metadata.exportable),
                CborValue::Bool(record.discoverable),
                CborValue::Unsigned(u64::from(record.sign_count)),
                record
                    .user_name
                    .as_ref()
                    .map_or(CborValue::Null, |name| CborValue::Text(name.clone())),
                record
                    .user_display_name
                    .as_ref()
                    .map_or(CborValue::Null, |name| CborValue::Text(name.clone())),
                CborValue::Unsigned(record.creation_order),
                record
                    .relying_party_id
                    .as_ref()
                    .map_or(CborValue::Null, |rp_id| CborValue::Text(rp_id.clone())),
                record.public_key.as_ref().map_or(CborValue::Null, |key| {
                    CborValue::Array(vec![
                        CborValue::Bytes(key.x.to_vec()),
                        CborValue::Bytes(key.y.to_vec()),
                    ])
                }),
                record
                    .hmac_secret
                    .as_ref()
                    .map_or(CborValue::Null, |secret| {
                        CborValue::Array(vec![
                            CborValue::Bytes(secret.with_uv.to_vec()),
                            CborValue::Bytes(secret.without_uv.to_vec()),
                        ])
                    }),
                CborValue::Unsigned(u64::from(record.cred_protect as u8)),
                record
                    .large_blob_key
                    .as_ref()
                    .map_or(CborValue::Null, |key| {
                        CborValue::Bytes(key.as_bytes().to_vec())
                    }),
                record.cred_blob.as_ref().map_or(CborValue::Null, |blob| {
                    CborValue::Bytes(blob.as_bytes().to_vec())
                }),
            ])
        })
        .collect::<Vec<_>>();
    let value = Zeroizing::new(CborValue::Array(values));
    let encoded = Zeroizing::new(encode_cbor(&value).map_err(CredentialError::CborEncoding)?);
    if encoded.len() > MAX_PERSISTED_BYTES {
        return Err(CredentialError::RecordLimitExceeded);
    }
    Ok(encoded)
}

fn decode_records(
    bytes: &[u8],
    version: u8,
) -> Result<BTreeMap<CredentialId, CredentialRecord>, CredentialError> {
    if bytes.len() > MAX_PERSISTED_BYTES {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let value = Zeroizing::new(
        decode_with_limits(
            bytes,
            CborLimits {
                max_depth: 4,
                max_items: MAX_PERSISTED_RECORDS * 16,
                max_bytes: MAX_PERSISTED_BYTES,
            },
        )
        .map_err(|_| CredentialError::ProtectedDataInvalid)?,
    );
    let CborValue::Array(records) = &*value else {
        return Err(CredentialError::ProtectedDataInvalid);
    };
    if records.len() > MAX_PERSISTED_RECORDS {
        return Err(CredentialError::RecordLimitExceeded);
    }
    let mut decoded = BTreeMap::new();
    let mut creation_orders = BTreeSet::new();
    let with_user_labels = version >= 2;
    let with_creation_order = version >= 3;
    for value in records {
        let CborValue::Array(fields) = value else {
            return Err(CredentialError::ProtectedDataInvalid);
        };
        let recognized_record_shape = match version {
            5 => fields.len() == 13,
            6 => fields.len() == 13 || fields.len() == 14,
            7 => (13..=15).contains(&fields.len()),
            8 => (13..=16).contains(&fields.len()),
            9.. => (13..=17).contains(&fields.len()),
            _ => false,
        };
        let record = if version >= 5 && recognized_record_shape {
            let fields = fields.as_slice();
            let (cred_blob_value, fields) = if fields.len() == 17 && version >= 9 {
                let (value, fields) = fields
                    .split_last()
                    .ok_or(CredentialError::ProtectedDataInvalid)?;
                (Some(value), fields)
            } else {
                (None, fields)
            };
            let (large_blob_key_value, fields) = if fields.len() == 16 && version >= 8 {
                let (value, fields) = fields
                    .split_last()
                    .ok_or(CredentialError::ProtectedDataInvalid)?;
                (Some(value), fields)
            } else {
                (None, fields)
            };
            let (cred_protect_value, fields) = if fields.len() == 15 && version >= 7 {
                let (value, fields) = fields
                    .split_last()
                    .ok_or(CredentialError::ProtectedDataInvalid)?;
                (Some(value), fields)
            } else {
                (None, fields)
            };
            let (hmac_secret_value, fields) = if fields.len() == 14 {
                let (value, fields) = fields
                    .split_last()
                    .ok_or(CredentialError::ProtectedDataInvalid)?;
                (Some(value), fields)
            } else {
                (None, fields)
            };
            let Some((public_key_value, base_fields)) = fields.split_last() else {
                return Err(CredentialError::ProtectedDataInvalid);
            };
            let mut record =
                decode_record_fields(base_fields, with_user_labels, with_creation_order, true)?;
            record.public_key = decode_public_key(public_key_value)?;
            record.hmac_secret = hmac_secret_value
                .map(decode_hmac_secret)
                .transpose()?
                .flatten();
            record.cred_protect = match cred_protect_value {
                Some(CborValue::Unsigned(level)) => CredentialProtectionPolicy::try_from(*level)?,
                Some(_) => return Err(CredentialError::ProtectedDataInvalid),
                None => CredentialProtectionPolicy::default(),
            };
            record.large_blob_key = large_blob_key_value
                .map(decode_large_blob_key)
                .transpose()?
                .flatten();
            record.cred_blob = cred_blob_value
                .map(decode_credential_blob)
                .transpose()?
                .flatten();
            if record.cred_blob.is_some() && !record.discoverable {
                return Err(CredentialError::ProtectedDataInvalid);
            }
            record
        } else {
            decode_record_fields(fields, with_user_labels, with_creation_order, version >= 4)?
        };
        if with_creation_order && !creation_orders.insert(record.creation_order) {
            return Err(CredentialError::ProtectedDataInvalid);
        }
        let id = record.id.clone();
        if decoded.insert(id, record).is_some() {
            return Err(CredentialError::ProtectedDataInvalid);
        }
    }
    Ok(decoded)
}

fn decode_record_fields(
    fields: &[CborValue],
    with_user_labels: bool,
    with_creation_order: bool,
    with_rp_id: bool,
) -> Result<CredentialRecord, CredentialError> {
    let (
        id,
        rp_id_hash,
        user_handle,
        key_handle,
        protection,
        exportable,
        discoverable,
        sign_count,
        user_name,
        user_display_name,
        creation_order,
        relying_party_id,
    ) = if with_user_labels {
        if with_creation_order {
            if with_rp_id {
                let [
                    CborValue::Bytes(id),
                    CborValue::Bytes(rp_id_hash),
                    CborValue::Bytes(user_handle),
                    CborValue::Bytes(key_handle),
                    CborValue::Unsigned(protection),
                    CborValue::Bool(exportable),
                    CborValue::Bool(discoverable),
                    CborValue::Unsigned(sign_count),
                    user_name,
                    user_display_name,
                    CborValue::Unsigned(creation_order),
                    relying_party_id,
                ] = fields
                else {
                    return Err(CredentialError::ProtectedDataInvalid);
                };
                (
                    id,
                    rp_id_hash,
                    user_handle,
                    key_handle,
                    protection,
                    exportable,
                    discoverable,
                    sign_count,
                    decode_user_label(user_name)?,
                    decode_user_label(user_display_name)?,
                    *creation_order,
                    decode_rp_id(relying_party_id)?,
                )
            } else {
                let [
                    CborValue::Bytes(id),
                    CborValue::Bytes(rp_id_hash),
                    CborValue::Bytes(user_handle),
                    CborValue::Bytes(key_handle),
                    CborValue::Unsigned(protection),
                    CborValue::Bool(exportable),
                    CborValue::Bool(discoverable),
                    CborValue::Unsigned(sign_count),
                    user_name,
                    user_display_name,
                    CborValue::Unsigned(creation_order),
                ] = fields
                else {
                    return Err(CredentialError::ProtectedDataInvalid);
                };
                (
                    id,
                    rp_id_hash,
                    user_handle,
                    key_handle,
                    protection,
                    exportable,
                    discoverable,
                    sign_count,
                    decode_user_label(user_name)?,
                    decode_user_label(user_display_name)?,
                    *creation_order,
                    None,
                )
            }
        } else {
            let [
                CborValue::Bytes(id),
                CborValue::Bytes(rp_id_hash),
                CborValue::Bytes(user_handle),
                CborValue::Bytes(key_handle),
                CborValue::Unsigned(protection),
                CborValue::Bool(exportable),
                CborValue::Bool(discoverable),
                CborValue::Unsigned(sign_count),
                user_name,
                user_display_name,
            ] = fields
            else {
                return Err(CredentialError::ProtectedDataInvalid);
            };
            (
                id,
                rp_id_hash,
                user_handle,
                key_handle,
                protection,
                exportable,
                discoverable,
                sign_count,
                decode_user_label(user_name)?,
                decode_user_label(user_display_name)?,
                0,
                None,
            )
        }
    } else {
        let [
            CborValue::Bytes(id),
            CborValue::Bytes(rp_id_hash),
            CborValue::Bytes(user_handle),
            CborValue::Bytes(key_handle),
            CborValue::Unsigned(protection),
            CborValue::Bool(exportable),
            CborValue::Bool(discoverable),
            CborValue::Unsigned(sign_count),
        ] = fields
        else {
            return Err(CredentialError::ProtectedDataInvalid);
        };
        (
            id,
            rp_id_hash,
            user_handle,
            key_handle,
            protection,
            exportable,
            discoverable,
            sign_count,
            None,
            None,
            0,
            None,
        )
    };

    if rp_id_hash.len() != 32 {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    if with_creation_order && creation_order == 0 {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let key_protection = match protection {
        0 => CredentialKeyProtection::HardwareBacked,
        1 => CredentialKeyProtection::OsProtected,
        2 => CredentialKeyProtection::Software,
        _ => return Err(CredentialError::ProtectedDataInvalid),
    };
    let mut rp_hash = [0; 32];
    rp_hash.copy_from_slice(rp_id_hash);
    let id = CredentialId::new(id.clone()).map_err(|_| CredentialError::ProtectedDataInvalid)?;
    Ok(CredentialRecord {
        id,
        rp_id_hash: rp_hash,
        relying_party_id,
        user_handle: user_handle.clone(),
        user_name,
        user_display_name,
        key_handle: KeyHandle::new(key_handle.clone())
            .map_err(|_| CredentialError::ProtectedDataInvalid)?,
        public_key: None,
        hmac_secret: None,
        large_blob_key: None,
        cred_blob: None,
        cred_protect: CredentialProtectionPolicy::default(),
        key_metadata: CredentialKeyMetadata {
            protection: key_protection,
            exportable: *exportable,
        },
        discoverable: *discoverable,
        creation_order,
        sign_count: u32::try_from(*sign_count)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?,
    })
}

fn decode_public_key(value: &CborValue) -> Result<Option<Es256PublicKey>, CredentialError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Array(coordinates) => {
            let [CborValue::Bytes(x), CborValue::Bytes(y)] = coordinates.as_slice() else {
                return Err(CredentialError::ProtectedDataInvalid);
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(CredentialError::ProtectedDataInvalid);
            }
            Ok(Some(Es256PublicKey {
                x: x.as_slice().try_into().expect("length checked"),
                y: y.as_slice().try_into().expect("length checked"),
            }))
        }
        _ => Err(CredentialError::ProtectedDataInvalid),
    }
}

fn decode_hmac_secret(value: &CborValue) -> Result<Option<HmacSecretMaterial>, CredentialError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Array(secrets) => {
            let [CborValue::Bytes(with_uv), CborValue::Bytes(without_uv)] = secrets.as_slice()
            else {
                return Err(CredentialError::ProtectedDataInvalid);
            };
            if with_uv.len() != 32 || without_uv.len() != 32 {
                return Err(CredentialError::ProtectedDataInvalid);
            }
            let mut with_uv_secret = Zeroizing::new([0; 32]);
            with_uv_secret.copy_from_slice(with_uv);
            let mut without_uv_secret = Zeroizing::new([0; 32]);
            without_uv_secret.copy_from_slice(without_uv);
            Ok(Some(HmacSecretMaterial::new(
                with_uv_secret,
                without_uv_secret,
            )))
        }
        _ => Err(CredentialError::ProtectedDataInvalid),
    }
}

fn decode_large_blob_key(value: &CborValue) -> Result<Option<LargeBlobKey>, CredentialError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut key = Zeroizing::new([0; 32]);
            key.copy_from_slice(bytes);
            Ok(Some(LargeBlobKey::new(key)))
        }
        _ => Err(CredentialError::ProtectedDataInvalid),
    }
}

fn decode_credential_blob(value: &CborValue) -> Result<Option<CredentialBlob>, CredentialError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Bytes(bytes) if bytes.len() <= MAX_CREDENTIAL_BLOB_LENGTH => {
            Ok(Some(CredentialBlob::new(bytes.clone())))
        }
        _ => Err(CredentialError::ProtectedDataInvalid),
    }
}

fn decode_rp_id(value: &CborValue) -> Result<Option<String>, CredentialError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Text(rp_id)
            if !rp_id.is_empty() && rp_id.len() <= MAX_RP_ID_BYTES && rp_id.is_ascii() =>
        {
            Ok(Some(rp_id.clone()))
        }
        _ => Err(CredentialError::ProtectedDataInvalid),
    }
}

fn assign_legacy_creation_order(
    records: &mut BTreeMap<CredentialId, CredentialRecord>,
) -> Result<(), CredentialError> {
    for (index, record) in records.values_mut().enumerate() {
        record.creation_order = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or(CredentialError::CreationOrderOverflow)?;
    }
    Ok(())
}

fn decode_user_label(value: &CborValue) -> Result<Option<String>, CredentialError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Text(label) if label.len() <= MAX_USER_LABEL_BYTES => Ok(Some(label.clone())),
        _ => Err(CredentialError::ProtectedDataInvalid),
    }
}
