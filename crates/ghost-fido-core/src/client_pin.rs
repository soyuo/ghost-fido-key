//! CTAP2 ClientPIN Protocol 1 cryptographic primitives.

use aes::{
    Aes256,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding},
};
use cbc::{Decryptor, Encryptor};
use getrandom::SysRng;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use p256::{
    PublicKey,
    ecdh::EphemeralSecret,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    cbor::{CborError, CborValue, encode},
    credentials::CredentialStore,
};

type HmacSha256 = Hmac<sha2_client_pin::Sha256>;
type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;

pub const PIN_UV_AUTH_PROTOCOL: u8 = 1;
pub const PIN_UV_AUTH_PROTOCOL_TWO: u8 = 2;
pub const PIN_UV_AUTH_PARAMETER_SIZE: usize = 16;
pub const PIN_HASH_SIZE: usize = 16;
pub const PIN_ENCRYPTED_SIZE: usize = 64;
pub const PIN_MIN_CODEPOINTS: usize = 4;
pub const PIN_MAX_UTF8_BYTES: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinUvAuthProtocol {
    One,
    Two,
}

impl PinUvAuthProtocol {
    #[must_use]
    pub const fn from_id(id: u64) -> Option<Self> {
        match id {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            _ => None,
        }
    }

    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::One => PIN_UV_AUTH_PROTOCOL,
            Self::Two => PIN_UV_AUTH_PROTOCOL_TWO,
        }
    }

    #[must_use]
    pub const fn auth_parameter_size(self) -> usize {
        match self {
            Self::One => PIN_UV_AUTH_PARAMETER_SIZE,
            Self::Two => 32,
        }
    }

    #[must_use]
    pub fn authenticate_token(self, token: &[u8; 32], message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(token).expect("HMAC accepts a 32-byte key");
        mac.update(message);
        let full = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        match self {
            Self::One => full[..16].to_vec(),
            Self::Two => full.to_vec(),
        }
    }

    #[must_use]
    pub fn verify_token_authentication(
        self,
        token: &[u8; 32],
        message: &[u8],
        auth: &[u8],
    ) -> bool {
        auth.len() == self.auth_parameter_size()
            && self.authenticate_token(token, message).ct_eq(auth).into()
    }
}

/// Protocol-selected key material. Protocol 1 uses the first 32 bytes; Protocol 2
/// uses the first half for HMAC and the second half for AES.
#[derive(Clone)]
pub struct PinUvAuthSharedSecret {
    protocol: PinUvAuthProtocol,
    key: Zeroizing<[u8; 64]>,
}

impl PinUvAuthSharedSecret {
    #[must_use]
    pub const fn protocol(&self) -> PinUvAuthProtocol {
        self.protocol
    }

    #[must_use]
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        let hmac_key = &self.key[..32];
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts a 32-byte key");
        mac.update(message);
        let full = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        match self.protocol {
            PinUvAuthProtocol::One => full[..16].to_vec(),
            PinUvAuthProtocol::Two => full.to_vec(),
        }
    }

    #[must_use]
    pub fn verify(&self, message: &[u8], auth: &[u8]) -> bool {
        if auth.len() != self.protocol.auth_parameter_size() {
            return false;
        }
        self.authenticate(message).ct_eq(auth).into()
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, PinCryptoError> {
        if plaintext.is_empty() || plaintext.len() % 16 != 0 {
            return Err(PinCryptoError::InvalidCiphertext);
        }
        let (key, iv, prefix_iv) = match self.protocol {
            PinUvAuthProtocol::One => (&self.key[..32], [0_u8; 16], false),
            PinUvAuthProtocol::Two => {
                let mut iv = [0_u8; 16];
                getrandom::fill(&mut iv).map_err(|_| PinCryptoError::RandomGenerationFailed)?;
                (&self.key[32..], iv, true)
            }
        };
        let mut ciphertext = Zeroizing::new(Vec::with_capacity(
            plaintext.len() + if prefix_iv { iv.len() } else { 0 },
        ));
        if prefix_iv {
            ciphertext.extend_from_slice(&iv);
        }
        ciphertext.extend_from_slice(plaintext);
        let data = if prefix_iv {
            &mut ciphertext[16..]
        } else {
            ciphertext.as_mut_slice()
        };
        Encryptor::<Aes256>::new(key.into(), (&iv).into())
            .encrypt_padded_mut::<NoPadding>(data, plaintext.len())
            .map_err(|_| PinCryptoError::InvalidCiphertext)?;
        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, PinCryptoError> {
        let (key, iv, encrypted) = match self.protocol {
            PinUvAuthProtocol::One => {
                if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
                    return Err(PinCryptoError::InvalidCiphertext);
                }
                (&self.key[..32], [0_u8; 16], ciphertext)
            }
            PinUvAuthProtocol::Two => {
                if ciphertext.len() < 32 || (ciphertext.len() - 16) % 16 != 0 {
                    return Err(PinCryptoError::InvalidCiphertext);
                }
                let iv: [u8; 16] = ciphertext[..16]
                    .try_into()
                    .map_err(|_| PinCryptoError::InvalidCiphertext)?;
                (&self.key[32..], iv, &ciphertext[16..])
            }
        };
        let mut plaintext = Zeroizing::new(encrypted.to_vec());
        Decryptor::<Aes256>::new(key.into(), (&iv).into())
            .decrypt_padded_mut::<NoPadding>(&mut plaintext)
            .map_err(|_| PinCryptoError::InvalidCiphertext)?;
        Ok(plaintext)
    }
}

impl Zeroize for PinUvAuthSharedSecret {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinManagementError {
    ProtectedStorageRequired,
    CurrentPinRequired,
    PinNotSet,
    PinBlocked,
    InvalidPin,
    InvalidCurrentPin,
    Persistence,
}

/// Configures the authenticator PIN through the protected local credential store.
///
/// This is intended for the desktop settings surface. Protocol callers must continue
/// using CTAP ClientPIN so that their PIN is protected by the protocol key agreement.
pub fn configure_pin(
    store: &mut CredentialStore,
    current_pin: Option<&[u8]>,
    new_pin: &[u8],
) -> Result<(), PinManagementError> {
    if !store.has_protected_storage() {
        return Err(PinManagementError::ProtectedStorageRequired);
    }
    if store.pin_state().verifier().is_some() && store.pin_state().retries() == 0 {
        return Err(PinManagementError::PinBlocked);
    }
    validate_pin(new_pin).map_err(|_| PinManagementError::InvalidPin)?;

    if let Some(expected_verifier) = store.pin_state().verifier() {
        let expected_verifier = Zeroizing::new(*expected_verifier);
        let Some(current_pin) = current_pin else {
            return Err(PinManagementError::CurrentPinRequired);
        };
        let retries = store.pin_state().retries();
        let actual_verifier = pin_hash(current_pin);
        let correct = actual_verifier
            .as_slice()
            .ct_eq(expected_verifier.as_slice())
            .unwrap_u8()
            == 1;
        if !correct {
            let next_retries = retries.saturating_sub(1);
            store
                .set_pin_retries(next_retries)
                .map_err(|_| PinManagementError::Persistence)?;
            return Err(if next_retries == 0 {
                PinManagementError::PinBlocked
            } else {
                PinManagementError::InvalidCurrentPin
            });
        }
    } else if current_pin.is_some() {
        return Err(PinManagementError::PinNotSet);
    }

    let verifier = pin_hash(new_pin);
    // Persist a copy only in the credential store's protected payload; `verifier` is wiped on drop.
    let result = store
        .set_pin_verifier(Some(*verifier))
        .map_err(|_| PinManagementError::Persistence);
    result
}

/// An ephemeral P-256 key agreement for one ClientPIN command exchange.
pub struct PinKeyAgreement {
    secret: EphemeralSecret,
    public_key: PublicKey,
}

impl PinKeyAgreement {
    #[must_use]
    pub fn generate() -> Result<Self, PinCryptoError> {
        let secret = EphemeralSecret::try_generate_from_rng(&mut SysRng)
            .map_err(|_| PinCryptoError::RandomGenerationFailed)?;
        let public_key = PublicKey::from(&secret);
        Ok(Self { secret, public_key })
    }

    #[must_use]
    pub fn cose_public_key(&self) -> Result<Vec<u8>, CborError> {
        let point = self.public_key.to_sec1_point(false);
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
    ) -> Result<Zeroizing<[u8; 32]>, PinCryptoError> {
        let peer = parse_peer_key(peer_cose_key)?;
        let raw = self.secret.diffie_hellman(&peer);
        Ok(Zeroizing::new(
            Sha256::digest(raw.raw_secret_bytes()).into(),
        ))
    }

    pub fn derive_shared_secret_for_protocol(
        &self,
        peer_cose_key: &CborValue,
        protocol: PinUvAuthProtocol,
    ) -> Result<PinUvAuthSharedSecret, PinCryptoError> {
        let peer = parse_peer_key(peer_cose_key)?;
        let raw = self.secret.diffie_hellman(&peer);
        let mut key = Zeroizing::new([0_u8; 64]);
        match protocol {
            PinUvAuthProtocol::One => {
                key[..32].copy_from_slice(&Sha256::digest(raw.raw_secret_bytes()));
            }
            PinUvAuthProtocol::Two => {
                let salt = [0_u8; 32];
                HkdfSha256::new(Some(&salt), raw.raw_secret_bytes())
                    .expand(b"CTAP2 HMAC key", &mut key[..32])
                    .map_err(|_| PinCryptoError::InvalidPeerKey)?;
                HkdfSha256::new(Some(&salt), raw.raw_secret_bytes())
                    .expand(b"CTAP2 AES key", &mut key[32..])
                    .map_err(|_| PinCryptoError::InvalidPeerKey)?;
            }
        }
        Ok(PinUvAuthSharedSecret { protocol, key })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCryptoError {
    RandomGenerationFailed,
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
    let full = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    full[..16].try_into().expect("fixed HMAC truncation length")
}

#[must_use]
pub fn verify_authentication(shared_secret: &[u8; 32], message: &[u8], auth: &[u8]) -> bool {
    if auth.len() != PIN_UV_AUTH_PARAMETER_SIZE {
        return false;
    }
    authenticate(shared_secret, message).ct_eq(auth).into()
}

/// Decrypts the hmac-secret salt input, authenticates it, computes one result
/// per salt, and encrypts the packed output in place.
pub fn process_hmac_secret(
    shared_secret: &[u8; 32],
    encrypted_salts: &mut [u8],
    salt_auth: &[u8],
    credential_secret: &[u8; 32],
) -> Result<Vec<u8>, PinCryptoError> {
    let mut key = Zeroizing::new([0_u8; 64]);
    key[..32].copy_from_slice(shared_secret);
    process_hmac_secret_with_protocol(
        &PinUvAuthSharedSecret {
            protocol: PinUvAuthProtocol::One,
            key,
        },
        encrypted_salts,
        salt_auth,
        credential_secret,
    )
    .map(|output| output.to_vec())
}

pub fn process_hmac_secret_with_protocol(
    shared_secret: &PinUvAuthSharedSecret,
    encrypted_salts: &mut [u8],
    salt_auth: &[u8],
    credential_secret: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, PinCryptoError> {
    use hmac::Mac;
    let salts = decrypt_hmac_secret_salts(shared_secret, encrypted_salts, salt_auth)?;
    let mut output = Zeroizing::new(Vec::with_capacity(salts.len()));
    for salt in salts.chunks_exact(32) {
        let mut mac =
            HmacSha256::new_from_slice(credential_secret).expect("HMAC accepts a 32-byte key");
        mac.update(salt);
        let digest = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        output.extend_from_slice(&*digest);
    }
    shared_secret.encrypt(&output)
}

/// Authenticates and decrypts an hmac-secret request when no credential
/// secret is available to produce an extension output.
pub fn validate_hmac_secret_request_with_protocol(
    shared_secret: &PinUvAuthSharedSecret,
    encrypted_salts: &[u8],
    salt_auth: &[u8],
) -> Result<(), PinCryptoError> {
    decrypt_hmac_secret_salts(shared_secret, encrypted_salts, salt_auth).map(drop)
}

fn decrypt_hmac_secret_salts(
    shared_secret: &PinUvAuthSharedSecret,
    encrypted_salts: &[u8],
    salt_auth: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PinCryptoError> {
    if !matches!(encrypted_salts.len(), 32 | 48 | 64 | 80)
        || !shared_secret.verify(encrypted_salts, salt_auth)
    {
        return Err(PinCryptoError::InvalidCiphertext);
    }
    let salts = shared_secret.decrypt(encrypted_salts)?;
    if !matches!(salts.len(), 32 | 64) {
        return Err(PinCryptoError::InvalidCiphertext);
    }
    Ok(salts)
}

#[must_use]
pub fn pin_hash(pin: &[u8]) -> Zeroizing<[u8; PIN_HASH_SIZE]> {
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(pin)));
    let mut verifier = [0_u8; PIN_HASH_SIZE];
    verifier.copy_from_slice(&digest[..PIN_HASH_SIZE]);
    Zeroizing::new(verifier)
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
) -> Result<Zeroizing<Vec<u8>>, PinCryptoError> {
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
    let pin = Zeroizing::new(encrypted[..end].to_vec());
    encrypted.zeroize();
    if validate_pin(&pin).is_err() {
        return Err(PinCryptoError::InvalidPin);
    }
    Ok(pin)
}

pub fn decrypt_pin_with_protocol(
    shared_secret: &PinUvAuthSharedSecret,
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PinCryptoError> {
    let mut plaintext = shared_secret.decrypt(encrypted)?;
    if plaintext.len() != PIN_ENCRYPTED_SIZE {
        return Err(PinCryptoError::InvalidCiphertext);
    }
    let end = plaintext
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(plaintext.len());
    if plaintext[end..].iter().any(|byte| *byte != 0) {
        plaintext.zeroize();
        return Err(PinCryptoError::InvalidPin);
    }
    plaintext.truncate(end);
    if validate_pin(&plaintext).is_err() {
        plaintext.zeroize();
        return Err(PinCryptoError::InvalidPin);
    }
    Ok(plaintext)
}

fn parse_peer_key(value: &CborValue) -> Result<PublicKey, PinCryptoError> {
    let CborValue::Map(fields) = value else {
        return Err(PinCryptoError::InvalidPeerKey);
    };
    if fields
        .iter()
        .any(|(key, _)| matches!(key, CborValue::Unsigned(2 | 4 | 5)))
    {
        return Err(PinCryptoError::InvalidPeerKey);
    }
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
