//! Credential metadata and RP-isolated selection policy.

use std::{collections::BTreeMap, fmt, path::Path, sync::Arc};

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::cbor::{CborLimits, CborValue, decode_with_limits, encode as encode_cbor};

const STORAGE_SCHEMA_VERSION: i64 = 1;
const STORAGE_AAD: &[u8] = b"ghost-fido/credential-store/v1";
const MAX_PERSISTED_RECORDS: usize = 4096;
const MAX_PERSISTED_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROTECTED_BYTES: usize = MAX_PERSISTED_BYTES + 4096;

pub type RpIdHash = [u8; 32];

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
    pub user_handle: Vec<u8>,
    pub key_handle: KeyHandle,
    pub key_metadata: CredentialKeyMetadata,
    pub discoverable: bool,
    pub sign_count: u32,
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("rp_id_hash", &"[REDACTED]")
            .field("user_handle", &"[REDACTED]")
            .field("key_handle", &self.key_handle)
            .field("key_metadata", &self.key_metadata)
            .field("discoverable", &self.discoverable)
            .field("sign_count", &self.sign_count)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    EmptyIdentifier,
    EmptyUserHandle,
    EmptyKeyHandle,
    DuplicateIdentifier,
    NotFound,
    CounterOverflow,
    StorageFailure,
    ProtectedDataInvalid,
    UnsupportedSchemaVersion(i64),
    RecordLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialProtectionError {
    Failed,
}

/// Authenticated encryption boundary for credential metadata persisted by SQLite.
///
/// Implementations must authenticate ciphertext and associated data, and must
/// return an error if either is invalid. The plaintext contains credential IDs,
/// RP hashes, user handles, and opaque provider key references.
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
    ) -> Result<Vec<u8>, CredentialProtectionError>;
}

#[derive(Default)]
pub struct CredentialStore {
    records: BTreeMap<CredentialId, CredentialRecord>,
    sqlite: Option<SqliteBackend>,
}

struct SqliteBackend {
    connection: Connection,
    protector: Arc<dyn CredentialProtector>,
}

impl fmt::Debug for CredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialStore")
            .field("record_count", &self.records.len())
            .field("persistent", &self.sqlite.is_some())
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
        let mut connection = Connection::open(path).map_err(|_| CredentialError::StorageFailure)?;
        let schema_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| CredentialError::StorageFailure)?;

        let records = match schema_version {
            0 => {
                let user_tables: i64 = connection
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
                    .protect(&payload, STORAGE_AAD)
                    .map_err(|_| CredentialError::ProtectedDataInvalid)?;
                if protected.is_empty() || protected.len() > MAX_PROTECTED_BYTES {
                    return Err(CredentialError::ProtectedDataInvalid);
                }
                let transaction = connection
                    .transaction()
                    .map_err(|_| CredentialError::StorageFailure)?;
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
                    .pragma_update(None, "user_version", STORAGE_SCHEMA_VERSION)
                    .map_err(|_| CredentialError::StorageFailure)?;
                transaction
                    .commit()
                    .map_err(|_| CredentialError::StorageFailure)?;
                BTreeMap::new()
            }
            STORAGE_SCHEMA_VERSION => {
                let payload_size: Option<i64> = connection
                    .query_row(
                        "SELECT length(payload) FROM credential_store WHERE singleton = 1",
                        [],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|_| CredentialError::StorageFailure)?;
                let payload_size = payload_size.ok_or(CredentialError::ProtectedDataInvalid)?;
                if payload_size <= 0
                    || usize::try_from(payload_size).map_or(true, |size| size > MAX_PROTECTED_BYTES)
                {
                    return Err(CredentialError::ProtectedDataInvalid);
                }
                let stored: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT payload FROM credential_store WHERE singleton = 1",
                        [],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|_| CredentialError::StorageFailure)?;
                let protected = stored.ok_or(CredentialError::ProtectedDataInvalid)?;
                let plaintext = protector
                    .unprotect(&protected, STORAGE_AAD)
                    .map_err(|_| CredentialError::ProtectedDataInvalid)?;
                decode_records(&plaintext)?
            }
            other => return Err(CredentialError::UnsupportedSchemaVersion(other)),
        };

        Ok(Self {
            records,
            sqlite: Some(SqliteBackend {
                connection,
                protector,
            }),
        })
    }

    pub fn register(&mut self, record: CredentialRecord) -> Result<(), CredentialError> {
        if record.user_handle.is_empty() {
            return Err(CredentialError::EmptyUserHandle);
        }
        if self.records.contains_key(&record.id) {
            return Err(CredentialError::DuplicateIdentifier);
        }
        if self.sqlite.is_some() && self.records.len() >= MAX_PERSISTED_RECORDS {
            return Err(CredentialError::RecordLimitExceeded);
        }
        let mut next_records = self.records.clone();
        next_records.insert(record.id.clone(), record);
        self.persist(&next_records)?;
        self.records = next_records;
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
        self.persist(&next_records)?;
        self.records = next_records;
        Ok(sign_count)
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn persist(
        &mut self,
        records: &BTreeMap<CredentialId, CredentialRecord>,
    ) -> Result<(), CredentialError> {
        let Some(backend) = self.sqlite.as_mut() else {
            return Ok(());
        };
        let plaintext = encode_records(records)?;
        let protected = backend
            .protector
            .protect(&plaintext, STORAGE_AAD)
            .map_err(|_| CredentialError::ProtectedDataInvalid)?;
        if protected.is_empty() || protected.len() > MAX_PROTECTED_BYTES {
            return Err(CredentialError::ProtectedDataInvalid);
        }
        let transaction = backend
            .connection
            .transaction()
            .map_err(|_| CredentialError::StorageFailure)?;
        write_payload(&transaction, &protected)?;
        transaction
            .commit()
            .map_err(|_| CredentialError::StorageFailure)
    }
}

fn write_payload(transaction: &Transaction<'_>, payload: &[u8]) -> Result<(), CredentialError> {
    transaction
        .execute(
            "UPDATE credential_store SET payload = ?1 WHERE singleton = 1",
            params![payload],
        )
        .map_err(|_| CredentialError::StorageFailure)?;
    Ok(())
}

fn encode_records(
    records: &BTreeMap<CredentialId, CredentialRecord>,
) -> Result<Vec<u8>, CredentialError> {
    if records.len() > MAX_PERSISTED_RECORDS {
        return Err(CredentialError::RecordLimitExceeded);
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
            ])
        })
        .collect::<Vec<_>>();
    let encoded = encode_cbor(&CborValue::Array(values));
    if encoded.len() > MAX_PERSISTED_BYTES {
        return Err(CredentialError::RecordLimitExceeded);
    }
    Ok(encoded)
}

fn decode_records(
    bytes: &[u8],
) -> Result<BTreeMap<CredentialId, CredentialRecord>, CredentialError> {
    if bytes.len() > MAX_PERSISTED_BYTES {
        return Err(CredentialError::ProtectedDataInvalid);
    }
    let value = decode_with_limits(
        bytes,
        CborLimits {
            max_depth: 4,
            max_items: MAX_PERSISTED_RECORDS * 9,
            max_bytes: MAX_PERSISTED_BYTES,
        },
    )
    .map_err(|_| CredentialError::ProtectedDataInvalid)?;
    let CborValue::Array(records) = value else {
        return Err(CredentialError::ProtectedDataInvalid);
    };
    if records.len() > MAX_PERSISTED_RECORDS {
        return Err(CredentialError::RecordLimitExceeded);
    }
    let mut decoded = BTreeMap::new();
    for value in records {
        let CborValue::Array(fields) = value else {
            return Err(CredentialError::ProtectedDataInvalid);
        };
        let [
            CborValue::Bytes(id),
            CborValue::Bytes(rp_id_hash),
            CborValue::Bytes(user_handle),
            CborValue::Bytes(key_handle),
            CborValue::Unsigned(protection),
            CborValue::Bool(exportable),
            CborValue::Bool(discoverable),
            CborValue::Unsigned(sign_count),
        ] = fields.as_slice()
        else {
            return Err(CredentialError::ProtectedDataInvalid);
        };
        if rp_id_hash.len() != 32 || user_handle.is_empty() {
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
        let id =
            CredentialId::new(id.clone()).map_err(|_| CredentialError::ProtectedDataInvalid)?;
        let record = CredentialRecord {
            id: id.clone(),
            rp_id_hash: rp_hash,
            user_handle: user_handle.clone(),
            key_handle: KeyHandle::new(key_handle.clone())
                .map_err(|_| CredentialError::ProtectedDataInvalid)?,
            key_metadata: CredentialKeyMetadata {
                protection: key_protection,
                exportable: *exportable,
            },
            discoverable: *discoverable,
            sign_count: u32::try_from(*sign_count)
                .map_err(|_| CredentialError::ProtectedDataInvalid)?,
        };
        if decoded.insert(id, record).is_some() {
            return Err(CredentialError::ProtectedDataInvalid);
        }
    }
    Ok(decoded)
}
