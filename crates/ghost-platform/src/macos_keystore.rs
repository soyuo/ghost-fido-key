//! Security.framework P-256 key provider for macOS.

use std::fmt::Display;

use ghost_fido_core::Es256PublicKey;
use security_framework::{
    item::{ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
};

use crate::{
    CreatedSigningKey, HostPlatform, KeyCreationPolicy, KeyMetadata, KeyProtection, KeyReference,
    KeyStore, PlatformError, PlatformErrorKind, SigningAlgorithm, SoftwareKeyConsent,
};

const KEY_REFERENCE_PREFIX: &str = "macos-security:";

#[derive(Debug, Default)]
pub struct MacOsKeyStore;

impl MacOsKeyStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn fail(error: impl Display) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::MacOs,
            error.to_string(),
        )
    }

    fn key_label(reference: &KeyReference) -> Result<&str, PlatformError> {
        let label = reference
            .as_provider_reference()
            .strip_prefix(KEY_REFERENCE_PREFIX)
            .ok_or_else(|| Self::fail("key reference is not owned by the macOS provider"))?;
        if label.is_empty() || label.len() > 128 || label.contains(['/', '\\', '\0']) {
            return Err(Self::fail("invalid macOS key reference"));
        }
        Ok(label)
    }

    fn find_key(reference: &KeyReference) -> Result<Option<SecKey>, PlatformError> {
        let label = Self::key_label(reference)?;
        let mut options = ItemSearchOptions::new();
        options
            .key_class(KeyClass::private())
            .label(label)
            .ignore_legacy_keychains()
            .load_refs(true)
            .limit(2);
        let mut matches = options.search().map_err(Self::fail)?.into_iter();
        let key = match matches.next() {
            None => return Ok(None),
            Some(SearchResult::Ref(Reference::Key(key))) => key,
            Some(_) => return Err(Self::fail("macOS key search returned a non-key item")),
        };
        if matches.next().is_some() {
            return Err(Self::fail("macOS key label is not unique"));
        }
        Ok(Some(key))
    }

    fn open_key(reference: &KeyReference) -> Result<SecKey, PlatformError> {
        Self::find_key(reference)?.ok_or_else(|| Self::fail("macOS private key was not found"))
    }

    fn public_key(key: &SecKey) -> Result<Es256PublicKey, PlatformError> {
        let public_key = key
            .public_key()
            .and_then(|key| key.external_representation())
            .ok_or_else(|| Self::fail("Security.framework could not export public coordinates"))?
            .to_vec();
        if public_key.len() != 65 || public_key[0] != 0x04 {
            return Err(Self::fail(
                "Security.framework returned an invalid P-256 public key",
            ));
        }
        Ok(Es256PublicKey {
            x: public_key[1..33]
                .try_into()
                .expect("validated 32-byte X coordinate"),
            y: public_key[33..65]
                .try_into()
                .expect("validated 32-byte Y coordinate"),
        })
    }
}

impl KeyStore for MacOsKeyStore {
    fn create_signing_key(
        &self,
        algorithm: SigningAlgorithm,
        policy: KeyCreationPolicy,
        consent: Option<SoftwareKeyConsent>,
    ) -> Result<CreatedSigningKey, PlatformError> {
        let SigningAlgorithm::Es256 = algorithm;
        let (token, protection, exportable) = match policy {
            KeyCreationPolicy::PlatformProtectedOnly => {
                (Token::SecureEnclave, KeyProtection::HardwareBacked, false)
            }
            KeyCreationPolicy::SoftwareKeyAfterExplicitConsent if consent.is_some() => {
                (Token::Software, KeyProtection::Software, true)
            }
            KeyCreationPolicy::SoftwareKeyAfterExplicitConsent => {
                return Err(Self::fail("explicit software-key consent is required"));
            }
        };

        let label = uuid::Uuid::new_v4().to_string();
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(&label)
            .set_location(Location::DataProtectionKeychain)
            .set_token(token);
        let key = SecKey::new(&options).map_err(Self::fail)?;
        let public_key = match Self::public_key(&key) {
            Ok(public_key) => public_key,
            Err(error) => {
                let _ = key.delete();
                return Err(error);
            }
        };

        Ok(CreatedSigningKey {
            reference: KeyReference::new(format!("{KEY_REFERENCE_PREFIX}{label}")),
            metadata: KeyMetadata {
                protection,
                exportable,
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
        let key = Self::open_key(reference)?;
        let der_signature = key
            .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, digest)
            .map_err(Self::fail)?;
        der_to_p1363(&der_signature)
    }

    fn public_key(&self, reference: &KeyReference) -> Result<Es256PublicKey, PlatformError> {
        Self::public_key(&Self::open_key(reference)?)
    }

    fn delete_key(&self, reference: &KeyReference) -> Result<(), PlatformError> {
        match Self::find_key(reference)? {
            Some(key) => key.delete().map_err(Self::fail),
            None => Ok(()),
        }
    }
}

fn der_to_p1363(signature: &[u8]) -> Result<Vec<u8>, PlatformError> {
    if signature.len() < 8 || signature[0] != 0x30 || signature[1] as usize != signature.len() - 2 {
        return Err(MacOsKeyStore::fail(
            "Security.framework returned malformed ECDSA signature",
        ));
    }
    let mut cursor = 2;
    let r = read_der_integer(signature, &mut cursor)?;
    let s = read_der_integer(signature, &mut cursor)?;
    if cursor != signature.len() {
        return Err(MacOsKeyStore::fail(
            "Security.framework returned trailing signature data",
        ));
    }
    let mut output = Vec::with_capacity(64);
    output.extend_from_slice(&r);
    output.extend_from_slice(&s);
    Ok(output)
}

fn read_der_integer(signature: &[u8], cursor: &mut usize) -> Result<[u8; 32], PlatformError> {
    if signature.get(*cursor) != Some(&0x02) {
        return Err(MacOsKeyStore::fail(
            "Security.framework returned malformed ECDSA integer",
        ));
    }
    *cursor += 1;
    let length = usize::from(*signature.get(*cursor).ok_or_else(|| {
        MacOsKeyStore::fail("Security.framework returned a truncated ECDSA integer")
    })?);
    *cursor += 1;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| MacOsKeyStore::fail("ECDSA integer length overflow"))?;
    let mut bytes = signature.get(*cursor..end).ok_or_else(|| {
        MacOsKeyStore::fail("Security.framework returned a truncated ECDSA integer")
    })?;
    *cursor = end;
    if bytes.is_empty() || bytes.len() > 33 || bytes[0] & 0x80 != 0 {
        return Err(MacOsKeyStore::fail(
            "Security.framework returned an invalid ECDSA integer",
        ));
    }
    if bytes.len() == 33 {
        if bytes[0] != 0 || bytes[1] & 0x80 == 0 {
            return Err(MacOsKeyStore::fail(
                "Security.framework returned a non-canonical ECDSA integer",
            ));
        }
        bytes = &bytes[1..];
    } else if bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        return Err(MacOsKeyStore::fail(
            "Security.framework returned a non-canonical ECDSA integer",
        ));
    }
    let mut output = [0; 32];
    let offset = output
        .len()
        .checked_sub(bytes.len())
        .ok_or_else(|| MacOsKeyStore::fail("ECDSA integer exceeds the P-256 scalar size"))?;
    output[offset..].copy_from_slice(bytes);
    Ok(output)
}
