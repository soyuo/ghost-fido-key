//! Current-user DPAPI protection for encrypted credential metadata.
#![allow(unsafe_code)]

use std::{ptr, slice};

use ghost_fido_core::{CredentialProtectionError, CredentialProtector};
use windows::{
    Win32::Foundation::{HLOCAL, LocalFree},
    Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
    core::PCWSTR,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROTECTED_BYTES: usize = MAX_METADATA_BYTES + 4096;

#[derive(Debug, Default)]
pub struct WindowsCredentialProtector;

impl WindowsCredentialProtector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CredentialProtector for WindowsCredentialProtector {
    fn protect(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CredentialProtectionError> {
        if plaintext.len() > MAX_METADATA_BYTES {
            return Err(CredentialProtectionError::Failed);
        }
        let input = input_blob(plaintext)?;
        let entropy = input_blob(associated_data)?;
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input and entropy point to live immutable slices for the call;
        // `output` is writable, and DPAPI owns its allocated output afterward.
        let result = unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        let output = DpapiBuffer(output);
        result.map_err(|_| CredentialProtectionError::Failed)?;
        Ok(output.to_vec(MAX_PROTECTED_BYTES)?.to_vec())
    }

    fn unprotect(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialProtectionError> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_PROTECTED_BYTES {
            return Err(CredentialProtectionError::Failed);
        }
        let input = input_blob(ciphertext)?;
        let entropy = input_blob(associated_data)?;
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input and entropy point to live immutable slices for the call;
        // `output` is writable, and DPAPI owns its allocated output afterward.
        let result = unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        let output = DpapiBuffer(output);
        result.map_err(|_| CredentialProtectionError::Failed)?;
        output.to_vec(MAX_METADATA_BYTES)
    }

    fn erase_key(&self) -> Result<(), CredentialProtectionError> {
        // DPAPI uses OS-managed per-user master keys; the authenticator does
        // not own or remove those keys.
        Ok(())
    }
}

fn input_blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, CredentialProtectionError> {
    let cb_data = u32::try_from(bytes.len()).map_err(|_| CredentialProtectionError::Failed)?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: cb_data,
        // The Windows API treats input blobs as read-only; it requires this
        // pointer type for its C-compatible DATA_BLOB structure.
        pbData: if bytes.is_empty() {
            ptr::null_mut()
        } else {
            bytes.as_ptr().cast_mut()
        },
    })
}

struct DpapiBuffer(CRYPT_INTEGER_BLOB);

impl DpapiBuffer {
    fn to_vec(&self, maximum: usize) -> Result<Zeroizing<Vec<u8>>, CredentialProtectionError> {
        let length =
            usize::try_from(self.0.cbData).map_err(|_| CredentialProtectionError::Failed)?;
        if length > maximum || (length > 0 && self.0.pbData.is_null()) {
            return Err(CredentialProtectionError::Failed);
        }
        if length == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        // SAFETY: a successful DPAPI call returned `cbData` readable bytes at `pbData`.
        Ok(Zeroizing::new(
            unsafe { slice::from_raw_parts(self.0.pbData, length) }.to_vec(),
        ))
    }
}

impl Drop for DpapiBuffer {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            let length = self.0.cbData as usize;
            if length > 0 {
                // SAFETY: DPAPI allocated a writable `cbData`-byte output buffer,
                // which remains valid until `LocalFree` below.
                unsafe { slice::from_raw_parts_mut(self.0.pbData, length) }.zeroize();
            }
            // SAFETY: DPAPI allocated `pbData` with the Windows local allocator.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.pbData.cast()))) };
        }
    }
}
