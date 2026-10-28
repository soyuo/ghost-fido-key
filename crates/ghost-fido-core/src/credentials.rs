//! Credential metadata and RP-isolated selection policy.

use std::{collections::BTreeMap, fmt};

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
}

#[derive(Debug, Default)]
pub struct CredentialStore {
    records: BTreeMap<CredentialId, CredentialRecord>,
}

impl CredentialStore {
    pub fn register(&mut self, record: CredentialRecord) -> Result<(), CredentialError> {
        if record.user_handle.is_empty() {
            return Err(CredentialError::EmptyUserHandle);
        }
        if self.records.contains_key(&record.id) {
            return Err(CredentialError::DuplicateIdentifier);
        }
        self.records.insert(record.id.clone(), record);
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
        let record = self.records.get_mut(id).ok_or(CredentialError::NotFound)?;
        record.sign_count = record
            .sign_count
            .checked_add(1)
            .ok_or(CredentialError::CounterOverflow)?;
        Ok(record.sign_count)
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}
