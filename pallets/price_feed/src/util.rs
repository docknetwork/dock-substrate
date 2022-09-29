// ethabi crate cannot be directly used as its not `no_std` compatible. Also tried ethers-core and web3 but same issue.
// Adaptions of https://github.com/rust-ethereum/ethabi/blob/master/ethabi/src/decoder.rs.
// Lot of the code is intentionally commented as the relevant contract data is only of types uint256, int256

use codec::{Decode, Encode};

use sp_core::{H160, U256};
use sp_std::prelude::Vec;

/// Ethabi errors
#[derive(Debug)]
pub enum Error {
    /// Invalid entity such as a bad function name.
    InvalidName,
    /// Invalid data.
    InvalidData,
}

/// ABI word.
pub type Word = [u8; 32];

/// ABI address.
pub type EthAddress = H160;

/*/// ABI fixed bytes.
pub type FixedBytes = Vec<u8>;

/// ABI bytes.
pub type Bytes = Vec<u8>;*/

/// ABI signed integer.
pub type Int = U256;

/// ABI unsigned integer.
pub type Uint = U256;

struct DecodeResult {
    token: Token,
    new_offset: usize,
}

/// Function and event param types.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ParamType {
    /// Address.
    Address,
    /*/// Bytes.
    Bytes,*/
    /// Signed integer. u16 is sufficient as largest EVM integer type is 256 bit
    Int(u16),
    /// Unsigned integer. u16 is sufficient as largest EVM integer type is 256 bit
    Uint(u16),
    /*/// Boolean.
    Bool,
    /// String.
    String,
    /// Array of unknown size.
    Array(Box<ParamType>),
    /// Vector of bytes with fixed size.
    FixedBytes(usize),
    /// Array with fixed size.
    FixedArray(Box<ParamType>, usize),
    /// Tuple containing different types
    Tuple(Vec<ParamType>),*/
}

impl ParamType {
    /// returns whether a zero length byte slice (`0x`) is
    /// a valid encoded form of this param type
    pub fn is_empty_bytes_valid_encoding(&self) -> bool {
        /*match self {
            ParamType::FixedBytes(len) => *len == 0,
            ParamType::FixedArray(_, len) => *len == 0,
            _ => false,
        }*/
        false
    }

    /// returns whether a ParamType is dynamic
    /// used to decide how the ParamType should be encoded
    pub fn is_dynamic(&self) -> bool {
        /*match self {
            ParamType::Bytes | ParamType::Array(_) => true,
            ParamType::FixedArray(elem_type, _) => elem_type.is_dynamic(),
            ParamType::Tuple(params) => params.iter().any(|param| param.is_dynamic()),
            _ => false,
        }*/
        true
    }
}

/// Ethereum ABI params.
#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    /// Address.
    ///
    /// solidity name: address
    /// Encoded to left padded [0u8; 32].
    Address(EthAddress),
    /*/// Vector of bytes with known size.
    ///
    /// solidity name eg.: bytes8, bytes32, bytes64, bytes1024
    /// Encoded to right padded [0u8; ((N + 31) / 32) * 32].
    FixedBytes(FixedBytes),
    /// Vector of bytes of unknown size.
    ///
    /// solidity name: bytes
    /// Encoded in two parts.
    /// Init part: offset of 'closing part`.
    /// Closing part: encoded length followed by encoded right padded bytes.
    Bytes(Bytes),*/
    /// Signed integer.
    ///
    /// solidity name: int
    Int(Int),
    /// Unsigned integer.
    ///
    /// solidity name: uint
    Uint(Uint),
    /*/// Boolean value.
    ///
    /// solidity name: bool
    /// Encoded as left padded [0u8; 32], where last bit represents boolean value.
    Bool(bool),
    /// String.
    ///
    /// solidity name: string
    /// Encoded in the same way as bytes. Must be utf8 compliant.
    String(String),
    /// Array with known size.
    ///
    /// solidity name eg.: int[3], bool[3], address[][8]
    /// Encoding of array is equal to encoding of consecutive elements of array.
    FixedArray(Vec<Token>),
    /// Array of params with unknown size.
    ///
    /// solidity name eg. int[], bool[], address[5][]
    Array(Vec<Token>),
    /// Tuple of params of variable types.
    ///
    /// solidity name: tuple
    Tuple(Vec<Token>),*/
}

impl Token {
    pub fn into_address(self) -> Option<EthAddress> {
        match self {
            Token::Address(address) => Some(address),
            _ => None,
        }
    }

    pub fn into_int(self) -> Option<Uint> {
        match self {
            Token::Int(int) => Some(int),
            _ => None,
        }
    }

    pub fn into_uint(self) -> Option<Uint> {
        match self {
            Token::Uint(uint) => Some(uint),
            _ => None,
        }
    }
}

/// Converts a vector of bytes with len equal n * 32, to a vector of slices.
pub fn slice_data(data: &[u8]) -> Result<Vec<Word>, Error> {
    if data.len() % 32 != 0 {
        return Err(Error::InvalidData);
    }

    let times = data.len() / 32;
    let mut result = Vec::with_capacity(times);
    for i in 0..times {
        let mut slice = [0u8; 32];
        let offset = 32 * i;
        slice.copy_from_slice(&data[offset..offset + 32]);
        result.push(slice);
    }
    Ok(result)
}

fn peek(slices: &[Word], position: usize) -> Result<&Word, Error> {
    slices.get(position).ok_or(Error::InvalidData)
}

/// Decodes ABI compliant vector of bytes into vector of tokens described by types param.
pub fn decode(types: &[ParamType], data: &[u8]) -> Result<Vec<Token>, Error> {
    let is_empty_bytes_valid_encoding = types.iter().all(|t| t.is_empty_bytes_valid_encoding());
    if !is_empty_bytes_valid_encoding && data.is_empty() {
        return Err(Error::InvalidName);
    }
    let slices = slice_data(data)?;
    let mut tokens = Vec::with_capacity(types.len());
    let mut offset = 0;
    for param in types {
        let res = decode_param(param, &slices, offset)?;
        offset = res.new_offset;
        tokens.push(res.token);
    }
    Ok(tokens)
}

fn decode_param(param: &ParamType, slices: &[Word], offset: usize) -> Result<DecodeResult, Error> {
    match *param {
        ParamType::Address => {
            let slice = peek(slices, offset)?;
            let mut address = [0u8; 20];
            address.copy_from_slice(&slice[12..]);

            let result = DecodeResult {
                token: Token::Address(address.into()),
                new_offset: offset + 1,
            };

            Ok(result)
        }
        ParamType::Int(_) => {
            let slice = peek(slices, offset)?;

            let result = DecodeResult {
                token: Token::Int(slice.clone().into()),
                new_offset: offset + 1,
            };

            Ok(result)
        }
        ParamType::Uint(_) => {
            let slice = peek(slices, offset)?;

            let result = DecodeResult {
                token: Token::Uint(slice.clone().into()),
                new_offset: offset + 1,
            };

            Ok(result)
        } /*ParamType::Bool => {
              let slice = peek(slices, offset)?;

              let b = as_bool(slice)?;

              let result = DecodeResult { token: Token::Bool(b), new_offset: offset + 1 };
              Ok(result)
          }
          ParamType::FixedBytes(len) => {
              // FixedBytes is anything from bytes1 to bytes32. These values
              // are padded with trailing zeros to fill 32 bytes.
              let taken = take_bytes(slices, offset, len)?;
              let result = DecodeResult { token: Token::FixedBytes(taken.bytes), new_offset: taken.new_offset };
              Ok(result)
          }
          ParamType::Bytes => {
              let offset_slice = peek(slices, offset)?;
              let len_offset = (as_u32(offset_slice)? / 32) as usize;

              let len_slice = peek(slices, len_offset)?;
              let len = as_u32(len_slice)? as usize;

              let taken = take_bytes(slices, len_offset + 1, len)?;

              let result = DecodeResult { token: Token::Bytes(taken.bytes), new_offset: offset + 1 };
              Ok(result)
          }
          ParamType::String => {
              let offset_slice = peek(slices, offset)?;
              let len_offset = (as_u32(offset_slice)? / 32) as usize;

              let len_slice = peek(slices, len_offset)?;
              let len = as_u32(len_slice)? as usize;

              let taken = take_bytes(slices, len_offset + 1, len)?;

              let result = DecodeResult { token: Token::String(String::from_utf8(taken.bytes)?), new_offset: offset + 1 };
              Ok(result)
          }
          ParamType::Array(ref t) => {
              let offset_slice = peek(slices, offset)?;
              let len_offset = (as_u32(offset_slice)? / 32) as usize;
              let len_slice = peek(slices, len_offset)?;
              let len = as_u32(len_slice)? as usize;

              let tail = &slices[len_offset + 1..];
              let mut tokens = Vec::with_capacity(len);
              let mut new_offset = 0;

              for _ in 0..len {
                  let res = decode_param(t, &tail, new_offset)?;
                  new_offset = res.new_offset;
                  tokens.push(res.token);
              }

              let result = DecodeResult { token: Token::Array(tokens), new_offset: offset + 1 };

              Ok(result)
          }
          ParamType::FixedArray(ref t, len) => {
              let mut tokens = Vec::with_capacity(len);
              let is_dynamic = param.is_dynamic();

              let (tail, mut new_offset) = if is_dynamic {
                  (&slices[(as_u32(peek(slices, offset)?)? as usize / 32)..], 0)
              } else {
                  (slices, offset)
              };

              for _ in 0..len {
                  let res = decode_param(t, &tail, new_offset)?;
                  new_offset = res.new_offset;
                  tokens.push(res.token);
              }

              let result = DecodeResult {
                  token: Token::FixedArray(tokens),
                  new_offset: if is_dynamic { offset + 1 } else { new_offset },
              };

              Ok(result)
          }
          ParamType::Tuple(ref t) => {
              let is_dynamic = param.is_dynamic();

              // The first element in a dynamic Tuple is an offset to the Tuple's data
              // For a static Tuple the data begins right away
              let (tail, mut new_offset) = if is_dynamic {
                  (&slices[(as_u32(peek(slices, offset)?)? as usize / 32)..], 0)
              } else {
                  (slices, offset)
              };

              let len = t.len();
              let mut tokens = Vec::with_capacity(len);
              for param in t {
                  let res = decode_param(param, &tail, new_offset)?;
                  new_offset = res.new_offset;
                  tokens.push(res.token);
              }

              // The returned new_offset depends on whether the Tuple is dynamic
              // dynamic Tuple -> follows the prefixed Tuple data offset element
              // static Tuple  -> follows the last data element
              let result = DecodeResult {
                  token: Token::Tuple(tokens),
                  new_offset: if is_dynamic { offset + 1 } else { new_offset },
              };

              Ok(result)
          }*/
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding() {
        let value = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 96, 52, 215, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 52, 215, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,
        ];
        let decoded = decode(
            &[
                ParamType::Uint(80),
                ParamType::Int(256),
                ParamType::Uint(256),
                ParamType::Uint(256),
                ParamType::Uint(80),
            ],
            &value,
        )
        .unwrap();
        assert_eq!(decoded[0].clone().into_uint().unwrap().low_u32(), 32);
        assert_eq!(decoded[1].clone().into_int().unwrap().low_u32(), 34);
    }
}
