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

struct CngProviderHandle(Option<NCRYPT_PROV_HANDLE>);

impl CngProviderHandle {
    fn new(handle: NCRYPT_PROV_HANDLE) -> Self {
        Self(Some(handle))
    }

    fn raw(&self) -> NCRYPT_PROV_HANDLE {
        self.0.expect("CNG provider handle remains owned")
    }

    fn release(&mut self) -> windows::core::Result<()> {
        let Some(handle) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: this wrapper owns the provider handle and releases it at most once.
        unsafe { NCryptFreeObject(handle.into()) }
    }
}

impl Drop for CngProviderHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: this wrapper owns the provider handle and releases it at most once.
            let _ = unsafe { NCryptFreeObject(handle.into()) };
        }
    }
}

struct CngKeyHandle(Option<NCRYPT_KEY_HANDLE>);

impl CngKeyHandle {
    fn new(handle: NCRYPT_KEY_HANDLE) -> Self {
        Self(Some(handle))
    }

    fn raw(&self) -> NCRYPT_KEY_HANDLE {
        self.0.expect("CNG key handle remains owned")
    }

    fn release(&mut self) -> windows::core::Result<()> {
        let Some(handle) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: this wrapper owns the key handle and releases it at most once.
        unsafe { NCryptFreeObject(handle.into()) }
    }

    fn delete(&mut self) -> windows::core::Result<()> {
        // SAFETY: this wrapper owns the persisted key handle.
        unsafe { NCryptDeleteKey(self.raw(), 0) }?;
        // NCryptDeleteKey releases the key handle on success.
        self.0 = None;
        Ok(())
    }
}

impl Drop for CngKeyHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: this wrapper owns the key handle and releases it at most once.
            let _ = unsafe { NCryptFreeObject(handle.into()) };
        }
    }
}

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
        mut key: CngKeyHandle,
        mut provider: CngProviderHandle,
    ) -> windows::core::Result<()> {
        // Deleting a persisted key also releases its key handle. If deletion fails,
        // release the handle explicitly, but do not permit software fallback: the
        // incomplete protected key may still remain in the provider.
        let deletion = key.delete();
        let key_release = if deletion.is_err() {
            key.release()
        } else {
            Ok(())
        };
        let provider_release = provider.release();
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
        let mut provider =
            CngProviderHandle::new(self.open_provider(provider_name, classify_unavailable)?);
        let wide_name = Self::key_name(reference)?;
        let mut key = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider is valid, both strings are NUL terminated, and key is a valid output pointer.
        let creation_result = unsafe {
            NCryptCreatePersistedKey(
                provider.raw(),
                &mut key,
                NCRYPT_ECDSA_ALGORITHM,
                PCWSTR(wide_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if let Err(error) = creation_result {
            // The provider guard releases the handle on this error path.
            return Err(
                if classify_unavailable && Self::is_device_not_ready(&error) {
                    Self::protection_unavailable(error)
                } else {
                    Self::fail(error)
                },
            );
        }
        let mut key = CngKeyHandle::new(key);
        let usage = NCRYPT_ALLOW_SIGNING_FLAG.to_ne_bytes();
        // SAFETY: key is valid and the property bytes remain alive for this call.
        let configured = unsafe {
            NCryptSetProperty(
                key.raw().into(),
                NCRYPT_KEY_USAGE_PROPERTY,
                &usage,
                NCRYPT_FLAGS(0),
            )
        }
        .and_then(|_| unsafe {
            NCryptSetProperty(
                key.raw().into(),
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
        if let Err(error) = unsafe { NCryptFinalizeKey(key.raw(), NCRYPT_FLAGS(0)) } {
            let cleanup = Self::discard_incomplete_key(key, provider);
            return Err(Self::key_setup_failure(
                error,
                classify_unavailable,
                cleanup,
            ));
        }
        let public_key = match Self::export_public_key(key.raw()) {
            Ok(public_key) => public_key,
            Err(error) => {
                if key.delete().is_err() {
                    let _ = key.release();
                }
                let _ = provider.release();
                return Err(error);
            }
        };
        let key_release = key.release();
        let provider_release = provider.release();
        key_release.map_err(Self::fail)?;
        provider_release.map_err(Self::fail)?;
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
        let mut provider =
            CngProviderHandle::new(self.open_provider(Self::provider_for_key(key)?, false)?);
        let mut handle = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider and NUL-terminated key name are valid; handle is writable.
        unsafe {
            NCryptOpenKey(
                provider.raw(),
                &mut handle,
                PCWSTR(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(Self::fail)?;
        let mut handle = CngKeyHandle::new(handle);
        let mut signature = vec![0u8; 64];
        let mut written = 0;
        // SAFETY: message and signature buffers are valid for their declared lengths.
        let signing_result = unsafe {
            NCryptSignHash(
                handle.raw(),
                None,
                digest,
                Some(&mut signature),
                &mut written,
                NCRYPT_SILENT_FLAG,
            )
        };
        let key_release = handle.release();
        let provider_release = provider.release();
        signing_result.map_err(Self::fail)?;
        key_release.map_err(Self::fail)?;
        provider_release.map_err(Self::fail)?;
        signature.truncate(written as usize);
        if signature.len() != 64 {
            return Err(Self::fail(
                "CNG did not return a fixed-width ES256 signature",
            ));
        }
        Ok(signature)
    }

    fn public_key(&self, key: &KeyReference) -> Result<Es256PublicKey, PlatformError> {
        let name = Self::key_name(key)?;
        let mut provider =
            CngProviderHandle::new(self.open_provider(Self::provider_for_key(key)?, false)?);
        let mut handle = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider and NUL-terminated key name are valid; handle is writable.
        unsafe {
            NCryptOpenKey(
                provider.raw(),
                &mut handle,
                PCWSTR(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(Self::fail)?;
        let mut handle = CngKeyHandle::new(handle);
        let public_key = Self::export_public_key(handle.raw());
        let key_release = handle.release();
        let provider_release = provider.release();
        let public_key = public_key?;
        key_release.map_err(Self::fail)?;
        provider_release.map_err(Self::fail)?;
        Ok(public_key)
    }

    fn delete_key(&self, key: &KeyReference) -> Result<(), PlatformError> {
        let name = Self::key_name(key)?;
        let mut provider =
            CngProviderHandle::new(self.open_provider(Self::provider_for_key(key)?, false)?);
        let mut handle = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider and NUL-terminated key name are valid; handle is writable.
        let open_result = unsafe {
            NCryptOpenKey(
                provider.raw(),
                &mut handle,
                PCWSTR(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if let Err(error) = open_result {
            // Release the provider even when the key is missing or cannot be opened.
            let _ = provider.release();
            return if Self::is_missing_key_error(&error) {
                Ok(())
            } else {
                Err(Self::fail(error))
            };
        }
        let mut handle = CngKeyHandle::new(handle);
        let deletion = handle.delete();
        let key_release = if deletion.is_err() {
            handle.release()
        } else {
            Ok(())
        };
        let provider_release = provider.release();
        deletion.map_err(Self::fail)?;
        key_release.map_err(Self::fail)?;
        provider_release.map_err(Self::fail)
    }
}

fn wide_curve() -> Vec<u8> {
    let text: Vec<u16> = std::ffi::OsStr::new("nistP256")
        .encode_wide()
        .chain(Some(0))
        .collect();
    text.iter().flat_map(|unit| unit.to_ne_bytes()).collect()
}
