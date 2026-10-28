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

    fn fail(error: impl std::fmt::Display) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::Windows,
            error.to_string(),
        )
    }

    fn open_provider(&self) -> Result<NCRYPT_PROV_HANDLE, PlatformError> {
        let name: Vec<u16> = std::ffi::OsStr::new(Self::preferred_provider())
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut handle = NCRYPT_PROV_HANDLE(0);
        // SAFETY: `name` is NUL terminated and `handle` is a valid writable out pointer.
        unsafe { NCryptOpenStorageProvider(&mut handle, PCWSTR(name.as_ptr()), 0) }
            .map_err(Self::fail)?;
        Ok(handle)
    }

    fn key_name(reference: &KeyReference) -> Result<Vec<u16>, PlatformError> {
        let name = reference.as_provider_reference();
        let Some(name) = name.strip_prefix("cng:tpm:") else {
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
    fn create_signing_key(
        &self,
        algorithm: SigningAlgorithm,
        policy: KeyCreationPolicy,
        consent: Option<SoftwareKeyConsent>,
    ) -> Result<CreatedSigningKey, PlatformError> {
        if policy != KeyCreationPolicy::PlatformProtectedOnly {
            if consent.is_none() {
                return Err(Self::fail("explicit software-key consent is required"));
            }
            return Err(Self::fail(
                "software provider is not implemented; no fallback was performed",
            ));
        }
        let SigningAlgorithm::Es256 = algorithm;
        let provider = self.open_provider()?;
        let name = format!("GhostFido-{}", uuid::Uuid::new_v4());
        let wide_name: Vec<u16> = std::ffi::OsStr::new(&name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut key = NCRYPT_KEY_HANDLE(0);
        // SAFETY: provider is valid, both strings are NUL terminated, and key is a valid output pointer.
        unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                NCRYPT_ECDSA_ALGORITHM,
                PCWSTR(wide_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(Self::fail)?;
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
            let _ = unsafe { NCryptDeleteKey(key, 0) };
            let _ = unsafe { NCryptFreeObject(provider.into()) };
            return Err(Self::fail(error));
        }
        // SAFETY: key is a valid persisted CNG key handle.
        if let Err(error) = unsafe { NCryptFinalizeKey(key, NCRYPT_FLAGS(0)) } {
            let _ = unsafe { NCryptDeleteKey(key, 0) };
            let _ = unsafe { NCryptFreeObject(provider.into()) };
            return Err(Self::fail(error));
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
            reference: KeyReference::new(format!("cng:tpm:{name}")),
            metadata: KeyMetadata {
                protection: KeyProtection::HardwareBacked,
                exportable: false,
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
        let provider = self.open_provider()?;
        let name = Self::key_name(key)?;
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

    fn delete_key(&self, key: &KeyReference) -> Result<(), PlatformError> {
        let provider = self.open_provider()?;
        let name = Self::key_name(key)?;
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
