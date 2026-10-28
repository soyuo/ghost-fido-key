//! Small, bounded CBOR decoder for CTAP2 request validation.

use core::fmt;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    Empty,
    IntegerOverflow,
    Truncated,
    IndefiniteLength,
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
            max_depth: 16,
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
    let (value, offset) = parse(input, 0, 0, limits)?;
    if offset != input.len() {
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
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    let (value, end) = parse(input, offset, depth + 1, limits)?;
                    offset = end;
                    values.push(value);
                }
                Ok((CborValue::Array(values), offset))
            } else {
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    let (key, key_end) = parse(input, offset, depth + 1, limits)?;
                    let (value, value_end) = parse(input, key_end, depth + 1, limits)?;
                    offset = value_end;
                    values.push((key, value));
                }
                Ok((CborValue::Map(values), offset))
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
    Ok((value, end))
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
