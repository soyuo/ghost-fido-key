//! Credential metadata and RP-isolated selection policy.

use std::collections::BTreeMap;

pub type RpIdHash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: CredentialId,
    pub rp_id_hash: RpIdHash,
    pub user_handle: Vec<u8>,
    pub key_handle: KeyHandle,
    pub discoverable: bool,
    pub sign_count: u32,
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
