#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

extern crate alloc;
extern crate core;

pub mod common;
mod modules;
pub mod runtime_api;
pub mod types;
pub mod util;

pub use modules::{
    accumulator, anchor, attest, blob, did, master, offchain_signatures, revoke,
    status_list_credential,
};

#[cfg(test)]
mod tests;
