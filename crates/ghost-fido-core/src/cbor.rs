//! Small, bounded CBOR decoder for CTAP2 request validation.

use core::fmt;
use zeroize::{Zeroize, Zeroizing};

/// CTAP2 limits nested CBOR maps and arrays to four levels.
pub const CTAP2_MAX_NESTING_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

impl Zeroize for CborValue {
    fn zeroize(&mut self) {
        match self {
            Self::Unsigned(value) => value.zeroize(),
            Self::Negative(value) => value.zeroize(),
            Self::Bytes(value) => value.zeroize(),
            Self::Text(value) => value.zeroize(),
            Self::Array(values) => values.iter_mut().for_each(Zeroize::zeroize),
            Self::Map(entries) => {
                for (key, value) in entries {
                    key.zeroize();
                    value.zeroize();
                }
            }
            Self::Bool(value) => value.zeroize(),
            Self::Null => {}
        }
        *self = Self::Null;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    Empty,
    IntegerOverflow,
    Truncated,
    IndefiniteLength,
    NonCanonicalEncoding,
    MapKeyOrder,
    DuplicateMapKey,
    UnsupportedType(u8),
    InvalidUtf8,
    DepthExceeded,
    ItemLimitExceeded,
    ByteLimitExceeded,
    TrailingData,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("CBOR input is empty"),
            Self::IntegerOverflow => f.write_str("CBOR negative integer is out of range"),
            Self::Truncated => f.write_str("CBOR input is truncated"),
            Self::IndefiniteLength => f.write_str("indefinite-length CBOR is not allowed"),
            Self::NonCanonicalEncoding => {
                f.write_str("CBOR integer or length is not minimally encoded")
            }
            Self::MapKeyOrder => f.write_str("CBOR map keys are not in CTAP2 canonical order"),
            Self::DuplicateMapKey => f.write_str("CBOR map contains a duplicate key"),
            Self::UnsupportedType(t) => write!(f, "unsupported CBOR type {t}"),
            Self::InvalidUtf8 => f.write_str("CBOR text is not valid UTF-8"),
            Self::DepthExceeded => f.write_str("CBOR nesting depth exceeded"),
            Self::ItemLimitExceeded => f.write_str("CBOR item limit exceeded"),
            Self::ByteLimitExceeded => f.write_str("CBOR byte limit exceeded"),
            Self::TrailingData => f.write_str("CBOR contains trailing data"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CborLimits {
    pub max_depth: usize,
    pub max_items: usize,
    pub max_bytes: usize,
}
impl Default for CborLimits {
    fn default() -> Self {
        Self {
            max_depth: CTAP2_MAX_NESTING_DEPTH,
            max_items: 128,
            max_bytes: 8192,
        }
    }
}

pub fn decode(input: &[u8]) -> Result<CborValue, CborError> {
    decode_with_limits(input, CborLimits::default())
}
pub fn decode_with_limits(input: &[u8], limits: CborLimits) -> Result<CborValue, CborError> {
    if input.is_empty() {
        return Err(CborError::Empty);
    }
    let (mut value, offset) = parse(input, 0, 0, limits)?;
    if offset != input.len() {
        value.zeroize();
        return Err(CborError::TrailingData);
    }
    Ok(value)
}

fn parse(
    input: &[u8],
    mut offset: usize,
    depth: usize,
    limits: CborLimits,
) -> Result<(CborValue, usize), CborError> {
    if offset >= input.len() {
        return Err(CborError::Truncated);
    }
    let initial = input[offset];
    offset += 1;
    let major = initial >> 5;
    let info = initial & 0x1f;
    if info == 31 {
        return Err(CborError::IndefiniteLength);
    }
    let (argument, next) = read_argument(input, offset, info)?;
    offset = next;
    match major {
        0 => Ok((CborValue::Unsigned(argument), offset)),
        1 => {
            let value = i64::try_from(argument).map_err(|_| CborError::IntegerOverflow)?;
            Ok((CborValue::Negative(-1 - value), offset))
        }
        2 => {
            let len = bounded_len(argument, limits.max_bytes, true)?;
            let end = offset.checked_add(len).ok_or(CborError::Truncated)?;
            if end > input.len() {
                return Err(CborError::Truncated);
            }
            Ok((CborValue::Bytes(input[offset..end].to_vec()), end))
        }
        3 => {
            let len = bounded_len(argument, limits.max_bytes, true)?;
            let end = offset.checked_add(len).ok_or(CborError::Truncated)?;
            if end > input.len() {
                return Err(CborError::Truncated);
            }
            let text = core::str::from_utf8(&input[offset..end])
                .map_err(|_| CborError::InvalidUtf8)?
                .to_owned();
            Ok((CborValue::Text(text), end))
        }
        4 | 5 => {
            if depth >= limits.max_depth {
                return Err(CborError::DepthExceeded);
            }
            let count = bounded_len(argument, limits.max_items, false)?;
            if major == 4 {
                let mut values = Zeroizing::new(CborValue::Array(Vec::with_capacity(count)));
                for _ in 0..count {
                    let (value, end) = parse(input, offset, depth + 1, limits)?;
                    offset = end;
                    let CborValue::Array(values) = &mut *values else {
                        unreachable!();
                    };
                    values.push(value);
                }
                Ok((std::mem::replace(&mut *values, CborValue::Null), offset))
            } else {
                let mut values = Zeroizing::new(CborValue::Map(Vec::with_capacity(count)));
                let mut previous_key: Option<Zeroizing<Vec<u8>>> = None;
                for _ in 0..count {
                    let key_start = offset;
                    let (key, key_end) = parse(input, offset, depth + 1, limits)?;
                    let mut key = Zeroizing::new(key);
                    let encoded_key = Zeroizing::new(input[key_start..key_end].to_vec());
                    if let Some(previous) = &previous_key {
                        match compare_map_keys(previous, &encoded_key) {
                            core::cmp::Ordering::Less => {}
                            core::cmp::Ordering::Equal => {
                                return Err(CborError::DuplicateMapKey);
                            }
                            core::cmp::Ordering::Greater => return Err(CborError::MapKeyOrder),
                        }
                    }
                    let (value, value_end) = parse(input, key_end, depth + 1, limits)?;
                    let mut value = Zeroizing::new(value);
                    offset = value_end;
                    let CborValue::Map(values) = &mut *values else {
                        unreachable!();
                    };
                    values.push((
                        std::mem::replace(&mut *key, CborValue::Null),
                        std::mem::replace(&mut *value, CborValue::Null),
                    ));
                    previous_key = Some(encoded_key);
                }
                Ok((std::mem::replace(&mut *values, CborValue::Null), offset))
            }
        }
        7 => match info {
            20 => Ok((CborValue::Bool(false), offset)),
            21 => Ok((CborValue::Bool(true), offset)),
            22 => Ok((CborValue::Null, offset)),
            _ => Err(CborError::UnsupportedType(info)),
        },
        _ => Err(CborError::UnsupportedType(major)),
    }
}

fn read_argument(input: &[u8], offset: usize, info: u8) -> Result<(u64, usize), CborError> {
    let width = match info {
        0..=23 => return Ok((info as u64, offset)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(CborError::UnsupportedType(info)),
    };
    let end = offset.checked_add(width).ok_or(CborError::Truncated)?;
    if end > input.len() {
        return Err(CborError::Truncated);
    }
    let mut value = 0u64;
    for byte in &input[offset..end] {
        value = (value << 8) | u64::from(*byte);
    }
    let minimum = match width {
        1 => 24,
        2 => 256,
        4 => 65_536,
        8 => 4_294_967_296,
        _ => unreachable!(),
    };
    if value < minimum {
        return Err(CborError::NonCanonicalEncoding);
    }
    Ok((value, end))
}

fn compare_map_keys(left: &[u8], right: &[u8]) -> core::cmp::Ordering {
    let left_major = left.first().map_or(0, |byte| byte >> 5);
    let right_major = right.first().map_or(0, |byte| byte >> 5);
    left_major
        .cmp(&right_major)
        .then_with(|| left.len().cmp(&right.len()))
        .then_with(|| left.cmp(right))
}
fn bounded_len(value: u64, limit: usize, bytes: bool) -> Result<usize, CborError> {
    let length = usize::try_from(value).map_err(|_| CborError::ByteLimitExceeded)?;
    if length > limit {
        Err(if bytes {
            CborError::ByteLimitExceeded
        } else {
            CborError::ItemLimitExceeded
        })
    } else {
        Ok(length)
    }
}

#[must_use]
pub fn encode(value: &CborValue) -> Result<Vec<u8>, CborError> {
    let mut output = Zeroizing::new(Vec::new());
    encode_into(value, &mut output, 0)?;
    Ok(std::mem::take(&mut *output))
}

fn encode_into(value: &CborValue, output: &mut Vec<u8>, depth: usize) -> Result<(), CborError> {
    match value {
        CborValue::Unsigned(value) => write_argument(output, 0, *value),
        CborValue::Negative(value) => {
            let argument = u64::try_from(-1 - *value).map_err(|_| CborError::IntegerOverflow)?;
            write_argument(output, 1, argument);
        }
        CborValue::Bytes(value) => {
            write_argument(output, 2, value.len() as u64);
            output.extend_from_slice(value);
        }
        CborValue::Text(value) => {
            write_argument(output, 3, value.len() as u64);
            output.extend_from_slice(value.as_bytes());
        }
        CborValue::Array(values) => {
            if depth >= CTAP2_MAX_NESTING_DEPTH {
                return Err(CborError::DepthExceeded);
            }
            write_argument(output, 4, values.len() as u64);
            for value in values {
                encode_into(value, output, depth + 1)?;
            }
        }
        CborValue::Map(values) => {
            if depth >= CTAP2_MAX_NESTING_DEPTH {
                return Err(CborError::DepthExceeded);
            }
            let mut entries = Vec::with_capacity(values.len());
            for (key, value) in values {
                let mut encoded_key = Zeroizing::new(Vec::new());
                encode_into(key, &mut encoded_key, depth + 1)?;
                entries.push((encoded_key, value));
            }
            entries.sort_by(|(left, _), (right, _)| compare_map_keys(left, right));
            if entries
                .windows(2)
                .any(|pair| compare_map_keys(&pair[0].0, &pair[1].0) == core::cmp::Ordering::Equal)
            {
                return Err(CborError::DuplicateMapKey);
            }
            write_argument(output, 5, values.len() as u64);
            for (encoded_key, value) in entries {
                output.extend_from_slice(&encoded_key);
                encode_into(value, output, depth + 1)?;
            }
        }
        CborValue::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        CborValue::Null => output.push(0xf6),
    }
    Ok(())
}

fn write_argument(output: &mut Vec<u8>, major: u8, value: u64) {
    let info = if value < 24 {
        value as u8
    } else if value <= u8::MAX as u64 {
        24
    } else if value <= u16::MAX as u64 {
        25
    } else if value <= u32::MAX as u64 {
        26
    } else {
        27
    };
    output.push((major << 5) | info);
    match info {
        24 => output.push(value as u8),
        25 => output.extend_from_slice(&(value as u16).to_be_bytes()),
        26 => output.extend_from_slice(&(value as u32).to_be_bytes()),
        27 => output.extend_from_slice(&value.to_be_bytes()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{CTAP2_MAX_NESTING_DEPTH, CborError, CborValue, decode, encode};

    fn nested_arrays(depth: usize) -> CborValue {
        (0..depth).fold(CborValue::Unsigned(0), |value, _| {
            CborValue::Array(vec![value])
        })
    }

    fn nested_maps(depth: usize) -> CborValue {
        (0..depth).fold(CborValue::Unsigned(0), |value, _| {
            CborValue::Map(vec![(CborValue::Text("a".into()), value)])
        })
    }

    fn nested_array_bytes(depth: usize) -> Vec<u8> {
        let mut bytes = vec![0x81; depth];
        bytes.push(0);
        bytes
    }

    fn nested_map_bytes(depth: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(depth * 3 + 1);
        for _ in 0..depth {
            bytes.extend_from_slice(&[0xa1, 0x61, b'a']);
        }
        bytes.push(0);
        bytes
    }

    #[test]
    fn decoder_accepts_four_nested_array_and_map_levels() {
        let arrays = nested_array_bytes(CTAP2_MAX_NESTING_DEPTH);
        assert_eq!(decode(&arrays), Ok(nested_arrays(CTAP2_MAX_NESTING_DEPTH)));

        let maps = encode(&nested_maps(CTAP2_MAX_NESTING_DEPTH)).unwrap();
        assert_eq!(decode(&maps), Ok(nested_maps(CTAP2_MAX_NESTING_DEPTH)));
    }

    #[test]
    fn decoder_rejects_five_nested_array_and_map_levels() {
        assert_eq!(
            decode(&nested_array_bytes(CTAP2_MAX_NESTING_DEPTH + 1)),
            Err(CborError::DepthExceeded)
        );
        assert_eq!(
            decode(&nested_map_bytes(CTAP2_MAX_NESTING_DEPTH + 1)),
            Err(CborError::DepthExceeded)
        );
    }

    #[test]
    fn encoder_accepts_four_nested_array_and_map_levels() {
        assert!(encode(&nested_arrays(CTAP2_MAX_NESTING_DEPTH)).is_ok());
        assert!(encode(&nested_maps(CTAP2_MAX_NESTING_DEPTH)).is_ok());
    }

    #[test]
    fn encoder_rejects_five_nested_array_and_map_levels() {
        assert_eq!(
            encode(&nested_arrays(CTAP2_MAX_NESTING_DEPTH + 1)),
            Err(CborError::DepthExceeded)
        );
        assert_eq!(
            encode(&nested_maps(CTAP2_MAX_NESTING_DEPTH + 1)),
            Err(CborError::DepthExceeded)
        );
    }
}
