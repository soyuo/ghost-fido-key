//! Windows CNG key storage provider.
#![allow(unsafe_code)]

use crate::{
    CreatedSigningKey, HostPlatform, KeyCreationPolicy, KeyMetadata, KeyProtection, KeyReference,
    KeyStore, PlatformError, PlatformErrorKind, SigningAlgorithm, SoftwareKeyConsent,
};
use ghost_fido_core::Es256PublicKey;

use std::os::windows::ffi::OsStrExt;

use windows::{
    Win32::Security::Cryptography::{
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, CERT_KEY_SPEC,
        NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_ECC_CURVE_NAME_PROPERTY, NCRYPT_ECDSA_ALGORITHM,
        NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_PROV_HANDLE,
        NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
        NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty, NCryptSignHash,
    },
    core::PCWSTR,
};

#[derive(Debug, Default)]
pub struct WindowsKeyStore;

impl WindowsKeyStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub const fn preferred_provider() -> &'static str {
        "Microsoft Platform Crypto Provider"
    }

    const fn software_provider() -> &'static str {
        "Microsoft Software Key Storage Provider"
    }

    fn is_missing_key_error(error: &windows::core::Error) -> bool {
        // NCryptOpenKey documents NTE_BAD_KEYSET as "The specified key was not found."
        // Do not treat other provider errors as successful deletion.
        error.code().0 as u32 == 0x8009_0016
    }

    fn fail(error: impl std::fmt::Display) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::Windows,
            error.to_string(),
        )
    }

    fn open_provider(
        &self,
        provider_name: &str,
        classify_protection_unavailable: bool,
    ) -> Result<NCRYPT_PROV_HANDLE, PlatformError> {
        let name: Vec<u16> = std::ffi::OsStr::new(provider_name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut handle = NCRYPT_PROV_HANDLE(0);
        // SAFETY: `name` is NUL terminated and `handle` is a valid writable out pointer.
        unsafe { NCryptOpenStorageProvider(&mut handle, PCWSTR(name.as_ptr()), 0) }.map_err(
            |error| {
                if classify_protection_unavailable && Self::is_device_not_ready(&error) {
                    Self::protection_unavailable(error)
                } else {
                    Self::fail(error)
                }
            },
        )?;
        Ok(handle)
    }

    fn is_device_not_ready(error: &windows::core::Error) -> bool {
        error.code().0 as u32 == 0x8009_0030
    }

    fn protection_unavailable(error: impl std::fmt::Display) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::PlatformKeyProtectionUnavailable,
            HostPlatform::Windows,
            error.to_string(),
        )
    }

    fn discard_incomplete_key(
        key: NCRYPT_KEY_HANDLE,
        provider: NCRYPT_PROV_HANDLE,
    ) -> windows::core::Result<()> {
        // Deleting a persisted key also releases its key handle. If deletion fails,
        // release the handle explicitly, but do not permit software fallback: the
        // incomplete protected key may still remain in the provider.
        let deletion = unsafe { NCryptDeleteKey(key, 0) };
        let key_release = if deletion.is_err() {
            unsafe { NCryptFreeObject(key.into()) }
        } else {
            Ok(())
        };
        let provider_release = unsafe { NCryptFreeObject(provider.into()) };
        deletion.and(key_release).and(provider_release)
    }

    fn key_setup_failure(
        error: windows::core::Error,
        classify_protection_unavailable: bool,
        cleanup: windows::core::Result<()>,
    ) -> PlatformError {
        if let Err(cleanup_error) = cleanup {
            return Self::fail(format!(
                "{error}; failed to clean up the incomplete CNG key: {cleanup_error}"
            ));
        }
        if classify_protection_unavailable && Self::is_device_not_ready(&error) {
            Self::protection_unavailable(error)
        } else {
            Self::fail(error)
        }
    }

    fn provider_for_key(reference: &KeyReference) -> Result<&'static str, PlatformError> {
        if reference.as_provider_reference().starts_with("cng:tpm:") {
            Ok(Self::preferred_provider())
        } else if reference
            .as_provider_reference()
            .starts_with("cng:software:")
        {
            Ok(Self::software_provider())
        } else {
            Err(Self::fail(
                "key reference is not owned by a Windows CNG provider",
            ))
        }
    }

    fn key_name(reference: &KeyReference) -> Result<Vec<u16>, PlatformError> {
        let name = reference.as_provider_reference();
        let Some(name) = name
            .strip_prefix("cng:tpm:")
            .or_else(|| name.strip_prefix("cng:software:"))
        else {
            return Err(Self::fail(
                "key reference is not owned by the Windows TPM provider",
            ));
        };
        if name.is_empty() || name.contains(['\\', '/', ':']) {
            return Err(Self::fail("invalid CNG key reference"));
        }
        Ok(std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(Some(0))
            .collect())
    }

    fn export_public_key(key: NCRYPT_KEY_HANDLE) -> Result<Es256PublicKey, PlatformError> {
        let mut required = 0;
        // SAFETY: key is finalized and valid; a null output requests the required blob size.
        unsafe {
            NCryptExportKey(
                key,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                None,
                &mut required,
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(Self::fail)?;
        if required != 72 {
            return Err(Self::fail("unexpected P-256 public-key blob size"));
        }
        let mut blob = vec![0; required as usize];
        let mut written = 0;
        // SAFETY: output buffer has the provider-reported size and `written` is writable.
        unsafe {
            NCryptExportKey(
                key,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                Some(&mut blob),
                &mut written,
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(Self::fail)?;
        if written != 72
            || u32::from_le_bytes(blob[0..4].try_into().expect("four-byte header"))
                != BCRYPT_ECDSA_PUBLIC_P256_MAGIC
            || u32::from_le_bytes(blob[4..8].try_into().expect("four-byte header")) != 32
        {
            return Err(Self::fail("CNG did not return a P-256 ECDSA public key"));
        }
        Ok(Es256PublicKey {
            x: blob[8..40]
                .try_into()
                .expect("validated 32-byte X coordinate"),
            y: blob[40..72]
                .try_into()
                .expect("validated 32-byte Y coordinate"),
        })
    }
}

impl KeyStore for WindowsKeyStore {
    fn allocate_signing_key_reference(
        &self,
        policy: KeyCreationPolicy,
        consent: Option<SoftwareKeyConsent>,
    ) -> Result<KeyReference, PlatformError> {
        let prefix = match policy {
            KeyCreationPolicy::PlatformProtectedOnly => "cng:tpm:",
            KeyCreationPolicy::SoftwareKeyAfterExplicitConsent if consent.is_some() => {
                "cng:software:"
            }
            KeyCreationPolicy::SoftwareKeyAfterExplicitConsent => {
                return Err(Self::fail("explicit software-key consent is required"));
            }
        };
        Ok(KeyReference::new(format!(
            "{prefix}GhostFido-{}",
            uuid::Uuid::new_v4()
        )))
    }

    fn create_signing_key(
        &self,
        reference: &KeyReference,
        algorithm: SigningAlgorithm,
        policy: KeyCreationPolicy,
        consent: Option<SoftwareKeyConsent>,
    ) -> Result<CreatedSigningKey, PlatformError> {
        let (provider_name, reference_prefix, protection, exportable, classify_unavailable) =
            match policy {
                KeyCreationPolicy::PlatformProtectedOnly => (
                    Self::preferred_provider(),
                    "cng:tpm:",
                    KeyProtection::HardwareBacked,
                    false,
                    true,
                ),
                KeyCreationPolicy::SoftwareKeyAfterExplicitConsent if consent.is_some() => (
                    Self::software_provider(),
                    "cng:software:",
                    KeyProtection::Software,
                    false,
                    false,
                ),
                KeyCreationPolicy::SoftwareKeyAfterExplicitConsent => {
                    return Err(Self::fail("explicit software-key consent is required"));
                }
            };
        let SigningAlgorithm::Es256 = algorithm;
        if !reference
            .as_provider_reference()
            .starts_with(reference_prefix)
        {
            return Err(Self::fail(
                "CNG key reference does not match its selected provider",
            ));
        }
        let provider = self.open_provider(provider_name, classify_unavailable)?;
        let wide_name = Self::key_name(reference)?;
        let mut key = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider is valid, both strings are NUL terminated, and key is a valid output pointer.
        let creation_result = unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                NCRYPT_ECDSA_ALGORITHM,
                PCWSTR(wide_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if let Err(error) = creation_result {
            // SAFETY: creation failed before a key handle was returned; release the provider.
            let _ = unsafe { NCryptFreeObject(provider.into()) };
            return Err(
                if classify_unavailable && Self::is_device_not_ready(&error) {
                    Self::protection_unavailable(error)
                } else {
                    Self::fail(error)
                },
            );
        }
        let usage = NCRYPT_ALLOW_SIGNING_FLAG.to_ne_bytes();
        // SAFETY: key is valid and the property bytes remain alive for this call.
        let configured = unsafe {
            NCryptSetProperty(
                key.into(),
                NCRYPT_KEY_USAGE_PROPERTY,
                &usage,
                NCRYPT_FLAGS(0),
            )
        }
        .and_then(|_| unsafe {
            NCryptSetProperty(
                key.into(),
                NCRYPT_ECC_CURVE_NAME_PROPERTY,
                &wide_curve(),
                NCRYPT_FLAGS(0),
            )
        });
        if let Err(error) = configured {
            let cleanup = Self::discard_incomplete_key(key, provider);
            return Err(Self::key_setup_failure(
                error,
                classify_unavailable,
                cleanup,
            ));
        }
        // SAFETY: key is a valid persisted CNG key handle.
        if let Err(error) = unsafe { NCryptFinalizeKey(key, NCRYPT_FLAGS(0)) } {
            let cleanup = Self::discard_incomplete_key(key, provider);
            return Err(Self::key_setup_failure(
                error,
                classify_unavailable,
                cleanup,
            ));
        }
        let public_key = match Self::export_public_key(key) {
            Ok(public_key) => public_key,
            Err(error) => {
                let _ = unsafe { NCryptDeleteKey(key, 0) };
                let _ = unsafe { NCryptFreeObject(provider.into()) };
                return Err(error);
            }
        };
        // SAFETY: CNG handles are released after the persisted key is finalized.
        unsafe { NCryptFreeObject(key.into()) }.map_err(Self::fail)?;
        unsafe { NCryptFreeObject(provider.into()) }.map_err(Self::fail)?;
        Ok(CreatedSigningKey {
            reference: reference.clone(),
            metadata: KeyMetadata {
                protection,
                exportable,
            },
            public_key,
        })
    }

    fn sign(
        &self,
        key: &KeyReference,
        algorithm: SigningAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        let SigningAlgorithm::Es256 = algorithm;
        if digest.len() != 32 {
            return Err(Self::fail("ES256 requires a 32-byte SHA-256 digest"));
        }
        let name = Self::key_name(key)?;
        let provider = self.open_provider(Self::provider_for_key(key)?, false)?;
        let mut handle = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider and NUL-terminated key name are valid; handle is writable.
        unsafe {
            NCryptOpenKey(
                provider,
                &mut handle,
                PCWSTR(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(Self::fail)?;
        let mut signature = vec![0u8; 64];
        let mut written = 0;
        // SAFETY: message and signature buffers are valid for their declared lengths.
        unsafe {
            NCryptSignHash(
                handle,
                None,
                digest,
                Some(&mut signature),
                &mut written,
                NCRYPT_SILENT_FLAG,
            )
        }
        .map_err(Self::fail)?;
        signature.truncate(written as usize);
        // SAFETY: both handles were opened successfully and are now being released.
        unsafe { NCryptFreeObject(handle.into()) }.map_err(Self::fail)?;
        unsafe { NCryptFreeObject(provider.into()) }.map_err(Self::fail)?;
        if signature.len() != 64 {
            return Err(Self::fail(
                "CNG did not return a fixed-width ES256 signature",
            ));
        }
        Ok(signature)
    }

    fn public_key(&self, key: &KeyReference) -> Result<Es256PublicKey, PlatformError> {
        let name = Self::key_name(key)?;
        let provider = self.open_provider(Self::provider_for_key(key)?, false)?;
        let mut handle = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider and NUL-terminated key name are valid; handle is writable.
        unsafe {
            NCryptOpenKey(
                provider,
                &mut handle,
                PCWSTR(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(Self::fail)?;
        let public_key = Self::export_public_key(handle);
        // SAFETY: both handles were opened successfully and are now being released.
        unsafe { NCryptFreeObject(handle.into()) }.map_err(Self::fail)?;
        unsafe { NCryptFreeObject(provider.into()) }.map_err(Self::fail)?;
        public_key
    }

    fn delete_key(&self, key: &KeyReference) -> Result<(), PlatformError> {
        let name = Self::key_name(key)?;
        let provider = self.open_provider(Self::provider_for_key(key)?, false)?;
        let mut handle = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider and NUL-terminated key name are valid; handle is writable.
        let open_result = unsafe {
            NCryptOpenKey(
                provider,
                &mut handle,
                PCWSTR(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if let Err(error) = open_result {
            // SAFETY: provider was opened successfully and no key handle was returned.
            let _ = unsafe { NCryptFreeObject(provider.into()) };
            return if Self::is_missing_key_error(&error) {
                Ok(())
            } else {
                Err(Self::fail(error))
            };
        }
        // SAFETY: handle is an opened key and ownership transfers to delete.
        unsafe { NCryptDeleteKey(handle, 0) }.map_err(Self::fail)?;
        // SAFETY: provider was opened successfully.
        unsafe { NCryptFreeObject(provider.into()) }.map_err(Self::fail)
    }
}

fn wide_curve() -> Vec<u8> {
    let text: Vec<u16> = std::ffi::OsStr::new("nistP256")
        .encode_wide()
        .chain(Some(0))
        .collect();
    text.iter().flat_map(|unit| unit.to_ne_bytes()).collect()
}
