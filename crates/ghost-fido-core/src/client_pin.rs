//! CTAP2 ClientPIN Protocol 1 cryptographic primitives.

use aes::{
    Aes256,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding},
};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use p256::{PublicKey, ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::cbor::{CborValue, encode};

type HmacSha256 = Hmac<Sha256>;

pub const PIN_UV_AUTH_PROTOCOL: u8 = 1;
pub const PIN_UV_AUTH_PARAMETER_SIZE: usize = 16;
pub const PIN_HASH_SIZE: usize = 16;
pub const PIN_ENCRYPTED_SIZE: usize = 64;
pub const PIN_MIN_CODEPOINTS: usize = 4;
pub const PIN_MAX_UTF8_BYTES: usize = 63;

/// An ephemeral P-256 key agreement for one ClientPIN command exchange.
pub struct PinKeyAgreement {
    secret: EphemeralSecret,
    public_key: PublicKey,
}

impl PinKeyAgreement {
    #[must_use]
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    #[must_use]
    pub fn cose_public_key(&self) -> Vec<u8> {
        let point = self.public_key.to_encoded_point(false);
        encode(&CborValue::Map(vec![
            (CborValue::Unsigned(1), CborValue::Unsigned(2)),
            (CborValue::Unsigned(3), CborValue::Negative(-25)),
            (CborValue::Negative(-1), CborValue::Unsigned(1)),
            (
                CborValue::Negative(-2),
                CborValue::Bytes(point.x().expect("uncompressed point").to_vec()),
            ),
            (
                CborValue::Negative(-3),
                CborValue::Bytes(point.y().expect("uncompressed point").to_vec()),
            ),
        ]))
    }

    pub fn derive_shared_secret(
        &self,
        peer_cose_key: &CborValue,
    ) -> Result<[u8; 32], PinCryptoError> {
        let peer = parse_peer_key(peer_cose_key)?;
        let raw = self.secret.diffie_hellman(&peer);
        Ok(Sha256::digest(raw.raw_secret_bytes()).into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCryptoError {
    InvalidPeerKey,
    InvalidCiphertext,
    InvalidPin,
}

pub fn encrypt(shared_secret: &[u8; 32], plaintext: &mut [u8]) -> Result<(), PinCryptoError> {
    crypt::<true>(shared_secret, plaintext)
}

pub fn decrypt(shared_secret: &[u8; 32], ciphertext: &mut [u8]) -> Result<(), PinCryptoError> {
    crypt::<false>(shared_secret, ciphertext)
}

fn crypt<const ENCRYPT: bool>(key: &[u8; 32], data: &mut [u8]) -> Result<(), PinCryptoError> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(PinCryptoError::InvalidCiphertext);
    }
    let iv = [0_u8; 16];
    if ENCRYPT {
        Encryptor::<Aes256>::new(key.into(), (&iv).into())
            .encrypt_padded_mut::<NoPadding>(data, data.len())
            .map_err(|_| PinCryptoError::InvalidCiphertext)?;
    } else {
        Decryptor::<Aes256>::new(key.into(), (&iv).into())
            .decrypt_padded_mut::<NoPadding>(data)
            .map_err(|_| PinCryptoError::InvalidCiphertext)?;
    }
    Ok(())
}

#[must_use]
pub fn authenticate(shared_secret: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(shared_secret).expect("HMAC accepts a 32-byte key");
    mac.update(message);
    let full = mac.finalize().into_bytes();
    full[..16].try_into().expect("fixed HMAC truncation length")
}

#[must_use]
pub fn verify_authentication(shared_secret: &[u8; 32], message: &[u8], auth: &[u8]) -> bool {
    if auth.len() != PIN_UV_AUTH_PARAMETER_SIZE {
        return false;
    }
    authenticate(shared_secret, message).ct_eq(auth).into()
}

#[must_use]
pub fn pin_hash(pin: &[u8]) -> [u8; PIN_HASH_SIZE] {
    Sha256::digest(pin)[..PIN_HASH_SIZE]
        .try_into()
        .expect("fixed PIN hash length")
}

pub fn validate_pin(pin: &[u8]) -> Result<(), PinCryptoError> {
    let text = core::str::from_utf8(pin).map_err(|_| PinCryptoError::InvalidPin)?;
    if text.len() > PIN_MAX_UTF8_BYTES
        || text.chars().count() < PIN_MIN_CODEPOINTS
        || text.contains('\0')
    {
        return Err(PinCryptoError::InvalidPin);
    }
    Ok(())
}

pub fn decrypt_pin(
    shared_secret: &[u8; 32],
    encrypted: &mut [u8],
) -> Result<Vec<u8>, PinCryptoError> {
    if encrypted.len() != PIN_ENCRYPTED_SIZE {
        return Err(PinCryptoError::InvalidCiphertext);
    }
    decrypt(shared_secret, encrypted)?;
    let end = encrypted
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(encrypted.len());
    if encrypted[end..].iter().any(|byte| *byte != 0) {
        encrypted.zeroize();
        return Err(PinCryptoError::InvalidPin);
    }
    let mut pin = encrypted[..end].to_vec();
    encrypted.zeroize();
    if validate_pin(&pin).is_err() {
        pin.zeroize();
        return Err(PinCryptoError::InvalidPin);
    }
    Ok(pin)
}

fn parse_peer_key(value: &CborValue) -> Result<PublicKey, PinCryptoError> {
    let CborValue::Map(fields) = value else {
        return Err(PinCryptoError::InvalidPeerKey);
    };
    let get = |key: &CborValue| {
        fields
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    };
    if get(&CborValue::Unsigned(1)) != Some(&CborValue::Unsigned(2))
        || get(&CborValue::Unsigned(3)) != Some(&CborValue::Negative(-25))
        || get(&CborValue::Negative(-1)) != Some(&CborValue::Unsigned(1))
    {
        return Err(PinCryptoError::InvalidPeerKey);
    }
    let (Some(CborValue::Bytes(x)), Some(CborValue::Bytes(y))) =
        (get(&CborValue::Negative(-2)), get(&CborValue::Negative(-3)))
    else {
        return Err(PinCryptoError::InvalidPeerKey);
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(PinCryptoError::InvalidPeerKey);
    }
    let mut encoded = Vec::with_capacity(65);
    encoded.push(4);
    encoded.extend_from_slice(x);
    encoded.extend_from_slice(y);
    PublicKey::from_sec1_bytes(&encoded).map_err(|_| PinCryptoError::InvalidPeerKey)
}
