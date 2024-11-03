#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

mod naive_approach_poseidon_chain;
mod naive_approach_sha_chain;
mod poseidon_chain;
mod sha_chain_offchain;
mod sha_chain_onchain;
mod utils;

#[cfg(feature = "experimental-frontends")]
mod keccak_chain;
