#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

extern crate alloc;

pub mod common;
pub mod modules;
pub mod runtime_api;
pub mod util;

pub use modules::{
    accumulator, anchor, attest, blob, did, master, offchain_signatures, revoke,
    status_list_credential,
};

#[cfg(test)]
mod tests;
