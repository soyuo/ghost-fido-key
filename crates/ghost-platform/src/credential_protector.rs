//! Shared authenticated-encryption envelope for OS-managed metadata keys.

use aes_gcm::{Aes256Gcm, Nonce, aead::Aead, aead::KeyInit};
use ghost_fido_core::{CredentialProtectionError, CredentialProtector};
use zeroize::Zeroizing;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROTECTED_BYTES: usize = MAX_METADATA_BYTES + NONCE_SIZE + TAG_SIZE + 1;
const ENVELOPE_VERSION: u8 = 1;

pub(crate) trait MetadataKeyStore: Send + Sync {
    fn load_or_create_key(&self) -> Result<Zeroizing<[u8; KEY_SIZE]>, CredentialProtectionError>;
}

#[derive(Debug)]
pub(crate) struct AesGcmCredentialProtector<K> {
    key_store: K,
    associated_data_prefix: &'static [u8],
}

impl<K> AesGcmCredentialProtector<K> {
    pub(crate) const fn new(key_store: K, associated_data_prefix: &'static [u8]) -> Self {
        Self {
            key_store,
            associated_data_prefix,
        }
    }
}

impl<K: MetadataKeyStore> CredentialProtector for AesGcmCredentialProtector<K> {
    fn protect(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CredentialProtectionError> {
        if plaintext.len() > MAX_METADATA_BYTES || associated_data.len() > 4096 {
            return Err(CredentialProtectionError::Failed);
        }
        let key = self.key_store.load_or_create_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| CredentialProtectionError::Failed)?;
        let mut nonce = [0_u8; NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| CredentialProtectionError::Failed)?;
        let aad = self.make_aad(associated_data);
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
    ) -> Result<Zeroizing<Vec<u8>>, CredentialProtectionError> {
        if ciphertext.len() < 1 + NONCE_SIZE + TAG_SIZE
            || ciphertext.len() > MAX_PROTECTED_BYTES
            || ciphertext[0] != ENVELOPE_VERSION
            || associated_data.len() > 4096
        {
            return Err(CredentialProtectionError::Failed);
        }
        let key = self.key_store.load_or_create_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| CredentialProtectionError::Failed)?;
        let nonce = Nonce::from_slice(&ciphertext[1..1 + NONCE_SIZE]);
        let aad = self.make_aad(associated_data);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    aes_gcm::aead::Payload {
                        msg: &ciphertext[1 + NONCE_SIZE..],
                        aad: &aad,
                    },
                )
                .map_err(|_| CredentialProtectionError::Failed)?,
        );
        if plaintext.len() > MAX_METADATA_BYTES {
            return Err(CredentialProtectionError::Failed);
        }
        Ok(plaintext)
    }
}

impl<K> AesGcmCredentialProtector<K> {
    fn make_aad(&self, associated_data: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.associated_data_prefix.len() + associated_data.len());
        aad.extend_from_slice(self.associated_data_prefix);
        aad.extend_from_slice(associated_data);
        aad
    }
}
