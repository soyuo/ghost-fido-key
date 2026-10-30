//! Default Keychain-backed metadata-key storage for macOS.

use ghost_fido_core::{CredentialProtectionError, CredentialProtector};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
use zeroize::Zeroizing;

use crate::credential_protector::{AesGcmCredentialProtector, MetadataKeyStore};

const KEY_SIZE: usize = 32;
const ENVELOPE_AAD_PREFIX: &[u8] = b"ghost-fido/macos-credential-protector/v1\0";
const KEYCHAIN_SERVICE: &str = "com.ghost-fido-key.credential-store";
const KEYCHAIN_ACCOUNT: &str = "metadata-encryption-key-v1";

#[derive(Debug, Default)]
struct MacOsKeychainKeyStore;

#[derive(Debug)]
pub struct MacOsCredentialProtector(AesGcmCredentialProtector<MacOsKeychainKeyStore>);

impl MacOsCredentialProtector {
    #[must_use]
    pub const fn new() -> Self {
        Self(AesGcmCredentialProtector::new(
            MacOsKeychainKeyStore,
            ENVELOPE_AAD_PREFIX,
        ))
    }
}

impl Default for MacOsCredentialProtector {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialProtector for MacOsCredentialProtector {
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

impl MetadataKeyStore for MacOsKeychainKeyStore {
    fn load_or_create_key(&self) -> Result<Zeroizing<[u8; KEY_SIZE]>, CredentialProtectionError> {
        let keychain = SecKeychain::default().map_err(|_| CredentialProtectionError::Failed)?;
        match keychain.find_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
            Ok((password, _item)) => decode_key(password.as_ref().to_vec()),
            Err(error) if error.code() == errSecItemNotFound => {
                let mut generated_key = Zeroizing::new([0_u8; KEY_SIZE]);
                getrandom::fill(generated_key.as_mut())
                    .map_err(|_| CredentialProtectionError::Failed)?;
                match keychain.add_generic_password(
                    KEYCHAIN_SERVICE,
                    KEYCHAIN_ACCOUNT,
                    generated_key.as_ref(),
                ) {
                    Ok(()) => Ok(generated_key),
                    Err(error) if error.code() == errSecDuplicateItem => keychain
                        .find_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
                        .map_err(|_| CredentialProtectionError::Failed)
                        .and_then(|(password, _item)| decode_key(password.as_ref().to_vec())),
                    Err(_) => Err(CredentialProtectionError::Failed),
                }
            }
            Err(_) => Err(CredentialProtectionError::Failed),
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
