//! Secret Service-backed metadata-key storage for Linux.

use std::collections::HashMap;

use dbus_secret_service::{EncryptionType, SecretService};
use ghost_fido_core::{CredentialProtectionError, CredentialProtector};
use zeroize::Zeroizing;

use crate::credential_protector::{AesGcmCredentialProtector, MetadataKeyStore};

const KEY_SIZE: usize = 32;
const ENVELOPE_AAD_PREFIX: &[u8] = b"ghost-fido/linux-credential-protector/v1\0";
const KEY_LABEL: &str = "Ghost FIDO Key credential metadata key";
const ATTRIBUTE_APPLICATION: &str = "ghost-fido-key";
const ATTRIBUTE_PURPOSE: &str = "credential-store-encryption-key";

#[derive(Debug, Default)]
struct LinuxSecretServiceKeyStore;

#[derive(Debug)]
pub struct LinuxCredentialProtector(AesGcmCredentialProtector<LinuxSecretServiceKeyStore>);

impl LinuxCredentialProtector {
    #[must_use]
    pub const fn new() -> Self {
        Self(AesGcmCredentialProtector::new(
            LinuxSecretServiceKeyStore,
            ENVELOPE_AAD_PREFIX,
        ))
    }
}

impl Default for LinuxCredentialProtector {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialProtector for LinuxCredentialProtector {
    fn protect(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CredentialProtectionError> {
        self.0.protect(plaintext, associated_data)
    }

    fn unprotect(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialProtectionError> {
        self.0.unprotect(ciphertext, associated_data)
    }
}

impl MetadataKeyStore for LinuxSecretServiceKeyStore {
    fn load_or_create_key(&self) -> Result<Zeroizing<[u8; KEY_SIZE]>, CredentialProtectionError> {
        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|_| CredentialProtectionError::Failed)?;
        let attributes = HashMap::from([
            ("application", ATTRIBUTE_APPLICATION),
            ("purpose", ATTRIBUTE_PURPOSE),
        ]);
        let found = service
            .search_items(attributes.clone())
            .map_err(|_| CredentialProtectionError::Failed)?;
        let item_count = found.unlocked.len() + found.locked.len();
        if item_count > 1 {
            return Err(CredentialProtectionError::Failed);
        }
        if let Some(item) = found.unlocked.first() {
            return decode_key(
                item.get_secret()
                    .map_err(|_| CredentialProtectionError::Failed)?,
            );
        }
        if let Some(item) = found.locked.first() {
            item.unlock()
                .map_err(|_| CredentialProtectionError::Failed)?;
            return decode_key(
                item.get_secret()
                    .map_err(|_| CredentialProtectionError::Failed)?,
            );
        }

        let collection = service
            .get_default_collection()
            .map_err(|_| CredentialProtectionError::Failed)?;
        if collection
            .is_locked()
            .map_err(|_| CredentialProtectionError::Failed)?
        {
            collection
                .unlock()
                .map_err(|_| CredentialProtectionError::Failed)?;
        }
        let mut generated_key = Zeroizing::new([0_u8; KEY_SIZE]);
        getrandom::fill(generated_key.as_mut()).map_err(|_| CredentialProtectionError::Failed)?;
        collection
            .create_item(
                KEY_LABEL,
                attributes.clone(),
                generated_key.as_ref(),
                false,
                "application/octet-stream",
            )
            .map_err(|_| CredentialProtectionError::Failed)?;

        let found = service
            .search_items(attributes)
            .map_err(|_| CredentialProtectionError::Failed)?;
        if found.unlocked.len() + found.locked.len() != 1 {
            return Err(CredentialProtectionError::Failed);
        }
        if let Some(item) = found.unlocked.first() {
            decode_key(
                item.get_secret()
                    .map_err(|_| CredentialProtectionError::Failed)?,
            )
        } else if let Some(item) = found.locked.first() {
            item.unlock()
                .map_err(|_| CredentialProtectionError::Failed)?;
            decode_key(
                item.get_secret()
                    .map_err(|_| CredentialProtectionError::Failed)?,
            )
        } else {
            Err(CredentialProtectionError::Failed)
        }
    }
}

fn decode_key(secret: Vec<u8>) -> Result<Zeroizing<[u8; KEY_SIZE]>, CredentialProtectionError> {
    let secret = Zeroizing::new(secret);
    let key: [u8; KEY_SIZE] = secret
        .as_slice()
        .try_into()
        .map_err(|_| CredentialProtectionError::Failed)?;
    Ok(Zeroizing::new(key))
}
