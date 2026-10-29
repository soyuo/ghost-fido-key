//! Consent-gated software signing keys stored in the default Secret Service collection.

use std::collections::HashMap;

use ghost_fido_core::Es256PublicKey;
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use p256::elliptic_curve::sec1::ToSec1Point;
use secret_service::{EncryptionType, blocking::SecretService};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    CreatedSigningKey, HostPlatform, KeyCreationPolicy, KeyMetadata, KeyProtection, KeyReference,
    KeyStore, PlatformError, PlatformErrorKind, SigningAlgorithm, SoftwareKeyConsent,
};

const KEY_REFERENCE_PREFIX: &str = "secret-service:";
const KEY_LABEL: &str = "Ghost FIDO Key software signing key";
const ATTRIBUTE_APPLICATION: &str = "ghost-fido-key";
const ATTRIBUTE_PURPOSE: &str = "credential-signing-key";
const ATTRIBUTE_KEY_ID: &str = "key-id";
const PRIVATE_KEY_SIZE: usize = 32;

#[derive(Debug, Default)]
pub struct LinuxKeyStore;

impl LinuxKeyStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn fail(detail: impl Into<String>) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::Linux,
            detail,
        )
    }

    fn key_id(reference: &KeyReference) -> Result<String, PlatformError> {
        let id = reference
            .as_provider_reference()
            .strip_prefix(KEY_REFERENCE_PREFIX)
            .ok_or_else(|| Self::fail("key reference is not owned by the Linux provider"))?;
        let parsed =
            Uuid::parse_str(id).map_err(|_| Self::fail("invalid Secret Service key reference"))?;
        if parsed.to_string() != id {
            return Err(Self::fail("non-canonical Secret Service key reference"));
        }
        Ok(id.to_owned())
    }

    fn load_private_key(
        reference: &KeyReference,
    ) -> Result<Zeroizing<[u8; PRIVATE_KEY_SIZE]>, PlatformError> {
        let key_id = Self::key_id(reference)?;
        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|_| Self::fail("could not connect to Secret Service"))?;
        let attributes = HashMap::from([
            ("application", ATTRIBUTE_APPLICATION),
            ("purpose", ATTRIBUTE_PURPOSE),
            (ATTRIBUTE_KEY_ID, key_id.as_str()),
        ]);
        let found = service
            .search_items(attributes)
            .map_err(|_| Self::fail("could not search Secret Service signing keys"))?;
        if found.unlocked.len() + found.locked.len() != 1 {
            return Err(Self::fail(
                "Secret Service signing key is missing or ambiguous",
            ));
        }
        let item = if let Some(item) = found.unlocked.first() {
            item
        } else {
            let item = &found.locked[0];
            item.unlock()
                .map_err(|_| Self::fail("Secret Service signing key could not be unlocked"))?;
            item
        };
        let secret = Zeroizing::new(
            item.get_secret()
                .map_err(|_| Self::fail("Secret Service signing key could not be read"))?,
        );
        let key: [u8; PRIVATE_KEY_SIZE] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Self::fail("Secret Service signing key has an invalid size"))?;
        Ok(Zeroizing::new(key))
    }

    fn ensure_unlocked(service: &SecretService<'_>) -> Result<(), PlatformError> {
        let collection = service
            .get_default_collection()
            .map_err(|_| Self::fail("default Secret Service collection is unavailable"))?;
        if collection
            .is_locked()
            .map_err(|_| Self::fail("default Secret Service collection state is unavailable"))?
        {
            collection.unlock().map_err(|_| {
                Self::fail("default Secret Service collection could not be unlocked")
            })?;
        }
        Ok(())
    }
}

impl KeyStore for LinuxKeyStore {
    fn create_signing_key(
        &self,
        algorithm: SigningAlgorithm,
        policy: KeyCreationPolicy,
        consent: Option<SoftwareKeyConsent>,
    ) -> Result<CreatedSigningKey, PlatformError> {
        let SigningAlgorithm::Es256 = algorithm;
        if policy != KeyCreationPolicy::SoftwareKeyAfterExplicitConsent || consent.is_none() {
            return Err(Self::fail(
                "Linux has no hardware key provider; software-key creation needs explicit consent",
            ));
        }

        let mut private_bytes = Zeroizing::new([0_u8; PRIVATE_KEY_SIZE]);
        let mut signing_key = None;
        for _ in 0..16 {
            getrandom::fill(private_bytes.as_mut())
                .map_err(|_| Self::fail("could not generate signing-key randomness"))?;
            if let Ok(key) = SigningKey::from_slice(private_bytes.as_ref()) {
                signing_key = Some(key);
                break;
            }
        }
        let signing_key =
            signing_key.ok_or_else(|| Self::fail("could not generate a valid P-256 scalar"))?;
        let point = signing_key.verifying_key().to_sec1_point(false);
        let encoded_point = point.as_bytes();
        if encoded_point.len() != 65 || encoded_point[0] != 0x04 {
            return Err(Self::fail(
                "P-256 provider returned invalid public coordinates",
            ));
        }
        let public_key = Es256PublicKey {
            x: encoded_point[1..33]
                .try_into()
                .expect("validated 32-byte X coordinate"),
            y: encoded_point[33..65]
                .try_into()
                .expect("validated 32-byte Y coordinate"),
        };

        let key_id = Uuid::new_v4().to_string();
        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|_| Self::fail("could not connect to Secret Service"))?;
        Self::ensure_unlocked(&service)?;
        let attributes = HashMap::from([
            ("application", ATTRIBUTE_APPLICATION),
            ("purpose", ATTRIBUTE_PURPOSE),
            (ATTRIBUTE_KEY_ID, key_id.as_str()),
        ]);
        let collection = service
            .get_default_collection()
            .map_err(|_| Self::fail("default Secret Service collection is unavailable"))?;
        let item = collection
            .create_item(
                KEY_LABEL,
                attributes,
                private_bytes.as_ref(),
                false,
                "application/octet-stream",
            )
            .map_err(|_| Self::fail("could not persist the software signing key"))?;
        drop(item);

        Ok(CreatedSigningKey {
            reference: KeyReference::new(format!("{KEY_REFERENCE_PREFIX}{key_id}")),
            metadata: KeyMetadata {
                protection: KeyProtection::Software,
                exportable: true,
            },
            public_key,
        })
    }

    fn sign(
        &self,
        reference: &KeyReference,
        algorithm: SigningAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        let SigningAlgorithm::Es256 = algorithm;
        if digest.len() != 32 {
            return Err(Self::fail("ES256 requires a 32-byte SHA-256 digest"));
        }
        let private_bytes = Self::load_private_key(reference)?;
        let signing_key = SigningKey::from_slice(private_bytes.as_ref())
            .map_err(|_| Self::fail("stored software signing key is invalid"))?;
        let signature: Signature = signing_key
            .sign_prehash(digest)
            .map_err(|_| Self::fail("software signing operation failed"))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key(&self, reference: &KeyReference) -> Result<Es256PublicKey, PlatformError> {
        let private_bytes = Self::load_private_key(reference)?;
        let signing_key = SigningKey::from_slice(private_bytes.as_ref())
            .map_err(|_| Self::fail("stored software signing key is invalid"))?;
        let encoded = signing_key.verifying_key().to_sec1_point(false);
        if encoded.as_bytes().len() != 65 || encoded.as_bytes()[0] != 0x04 {
            return Err(Self::fail(
                "stored key returned invalid P-256 public coordinates",
            ));
        }
        Ok(Es256PublicKey {
            x: encoded.as_bytes()[1..33]
                .try_into()
                .expect("length checked"),
            y: encoded.as_bytes()[33..65]
                .try_into()
                .expect("length checked"),
        })
    }

    fn delete_key(&self, reference: &KeyReference) -> Result<(), PlatformError> {
        let key_id = Self::key_id(reference)?;
        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|_| Self::fail("could not connect to Secret Service"))?;
        let attributes = HashMap::from([
            ("application", ATTRIBUTE_APPLICATION),
            ("purpose", ATTRIBUTE_PURPOSE),
            (ATTRIBUTE_KEY_ID, key_id.as_str()),
        ]);
        let found = service
            .search_items(attributes)
            .map_err(|_| Self::fail("could not search Secret Service signing keys"))?;
        if found.unlocked.len() + found.locked.len() > 1 {
            return Err(Self::fail("Secret Service signing key is ambiguous"));
        }
        if found.unlocked.is_empty() && found.locked.is_empty() {
            return Ok(());
        }
        let item = found
            .unlocked
            .first()
            .or_else(|| found.locked.first())
            .unwrap();
        item.delete()
            .map_err(|_| Self::fail("Secret Service signing key could not be deleted"))
    }
}
