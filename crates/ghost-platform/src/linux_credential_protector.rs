//! Secret Service and AES-GCM protection for Linux credential metadata.

use std::collections::HashMap;

use aes_gcm::{Aes256Gcm, Nonce, aead::Aead, aead::KeyInit};
use ghost_fido_core::{CredentialProtectionError, CredentialProtector};
use secret_service::{EncryptionType, blocking::SecretService};
use zeroize::Zeroizing;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROTECTED_BYTES: usize = MAX_METADATA_BYTES + NONCE_SIZE + TAG_SIZE + 1;
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_AAD_PREFIX: &[u8] = b"ghost-fido/linux-credential-protector/v1\0";
const KEY_LABEL: &str = "Ghost FIDO Key credential metadata key";
const ATTRIBUTE_APPLICATION: &str = "ghost-fido-key";
const ATTRIBUTE_PURPOSE: &str = "credential-store-encryption-key";

#[derive(Debug, Default)]
pub struct LinuxCredentialProtector;

impl LinuxCredentialProtector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

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

        // Re-read by stable attributes so concurrent first use cannot silently
        // leave this process encrypting under a key that is not the stored one.
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

impl CredentialProtector for LinuxCredentialProtector {
    fn protect(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CredentialProtectionError> {
        if plaintext.len() > MAX_METADATA_BYTES || associated_data.len() > 4096 {
            return Err(CredentialProtectionError::Failed);
        }
        let key = self.load_or_create_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| CredentialProtectionError::Failed)?;
        let mut nonce = [0_u8; NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| CredentialProtectionError::Failed)?;
        let aad = make_aad(associated_data);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CredentialProtectionError::Failed)?;
        if ciphertext.len() + NONCE_SIZE + 1 > MAX_PROTECTED_BYTES {
            return Err(CredentialProtectionError::Failed);
        }
        let mut protected = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
        protected.push(ENVELOPE_VERSION);
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&ciphertext);
        Ok(protected)
    }

    fn unprotect(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CredentialProtectionError> {
        if ciphertext.len() < 1 + NONCE_SIZE + TAG_SIZE
            || ciphertext.len() > MAX_PROTECTED_BYTES
            || ciphertext[0] != ENVELOPE_VERSION
            || associated_data.len() > 4096
        {
            return Err(CredentialProtectionError::Failed);
        }
        let key = self.load_or_create_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| CredentialProtectionError::Failed)?;
        let nonce = Nonce::from_slice(&ciphertext[1..1 + NONCE_SIZE]);
        let aad = make_aad(associated_data);
        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &ciphertext[1 + NONCE_SIZE..],
                    aad: &aad,
                },
            )
            .map_err(|_| CredentialProtectionError::Failed)?;
        if plaintext.len() > MAX_METADATA_BYTES {
            return Err(CredentialProtectionError::Failed);
        }
        Ok(plaintext)
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

fn make_aad(associated_data: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_PREFIX.len() + associated_data.len());
    aad.extend_from_slice(ENVELOPE_AAD_PREFIX);
    aad.extend_from_slice(associated_data);
    aad
}
