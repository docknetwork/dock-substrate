/*#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]*/

use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as ClientError, HeaderBackend};
use sp_session::SessionKeys;
use sc_rpc_api::DenyUnsafe;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use sp_core::Bytes;
use std::{marker::PhantomData, sync::Arc};

#[rpc]
pub trait PoAApi {
    // TODO: Don't need a Vec<u8> as seed is 32 bytes for both sr25519 and ed25519 which are sufficient
    // for Aura and Grandpa
    /// Set session key for PoA node which is running Aura+Grandpa. Accept a seed for generating
	/// Aura and Grandpa keys by using the same seed for both
    #[rpc(name = "poa_genSessionKeyUsingSeed")]
    fn gen_session_key_using_seed(&self, seed: Bytes) -> Result<Bytes>;
    // fn gen_session_key_using_seed(&self, seed: [u8; 32]);
}

pub struct PoA<Client, B> {
    /// Substrate client
    client: Arc<Client>,
    /// Whether to deny unsafe calls
    deny_unsafe: DenyUnsafe,
    _marker: PhantomData<B>,
}

impl<Client, B> PoA<Client, B> {
    /// Create new instance of PoA API.
    pub fn new(
        client: Arc<Client>,
        deny_unsafe: DenyUnsafe,
    ) -> Self {
        PoA {
            client,
            deny_unsafe,
            _marker: Default::default(),
        }
    }
}

impl<Client, Block> PoAApi for PoA<Client, Block>
    where
        Block: BlockT,
        Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + 'static,
        Client::Api: SessionKeys<Block, Error = ClientError>,
{
    fn gen_session_key_using_seed(&self, seed: Bytes) -> Result<Bytes> {
        self.deny_unsafe.check_if_safe()?;

        // Need to be byte array of the secret phrase taken as ascii
        /*if seed.0.len() != 32 {
            return Err(RpcError {
                code: ErrorCode::ServerError(1),
                message: "Seed must be of length 32".into(),
                data: Some(format!("{:?}", seed.0).into()),
            })
        }*/

        let best_block_hash = self.client.info().best_hash;
        println!("In gen_session_key_using_seed {:?}", &seed.0);
        self.client.runtime_api().generate_session_keys(
            &BlockId::Hash(best_block_hash),
            Some(seed.0),
        ).map(Into::into).map_err(|e| RpcError {
            code: ErrorCode::ServerError(2),
            message: "Error while generating session key using seed".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Decode;
    use sp_core::{
        testing::{ED25519, SR25519, KeyStore}, ed25519, sr25519,
        crypto::{CryptoTypePublicPair, Public}
    };
    use substrate_test_runtime_client::{self, DefaultTestClientBuilderExt, TestClientBuilderExt, runtime::SessionKeys};

    #[test]
    fn gen_session_key_using_seed() {
        let keystore = KeyStore::new();
        let client_builder = substrate_test_runtime_client::TestClientBuilder::new();
        let client = Arc::new(client_builder.set_keystore(keystore.clone()).build());
        let poa = PoA::new(client.clone(), DenyUnsafe::Yes);

        let seed_vec = vec![0; 32];
        let seed = Bytes(seed_vec);
        assert!(poa.gen_session_key_using_seed(seed.clone()).is_err());

        let poa_1 = PoA::new(client.clone(), DenyUnsafe::No);
        let small_seed = Bytes(vec![0; 31]);
        assert!(poa_1.gen_session_key_using_seed(small_seed).is_err());

        let poa_2 = PoA::new(client.clone(), DenyUnsafe::No);
        let large_seed = Bytes(vec![0; 33]);
        assert!(poa_2.gen_session_key_using_seed(large_seed).is_err());

        let poa_3 = PoA::new(client, DenyUnsafe::No);
        let new_public_keys = poa_3.gen_session_key_using_seed(seed).unwrap();

        let session_keys = SessionKeys::decode(&mut &new_public_keys[..]).unwrap();

        let ed25519_public_keys = keystore.read().keys(ED25519).unwrap();
        let sr25519_public_keys = keystore.read().keys(SR25519).unwrap();

        println!("{:?}", session_keys.ed25519.to_raw_vec());
        println!("111");
        println!("{:?}", session_keys.sr25519.to_raw_vec());

        assert!(ed25519_public_keys.contains(&CryptoTypePublicPair(ed25519::CRYPTO_ID, session_keys.ed25519.to_raw_vec())));
        assert!(sr25519_public_keys.contains(&CryptoTypePublicPair(sr25519::CRYPTO_ID, session_keys.sr25519.to_raw_vec())));
    }
}