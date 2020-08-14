use dock_testnet_runtime::{
    did::{self, Did, KeyDetail},
    master::Membership,
    opaque::SessionKeys,
    AuraConfig, Balance, BalancesConfig, DIDModuleConfig, GenesisConfig, GrandpaConfig,
    MasterConfig, PoAModuleConfig, SessionConfig, SudoConfig, SystemConfig, WASM_BINARY,
};
use hex_literal::hex;
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
};

fn session_keys(aura: AuraId, grandpa: GrandpaId) -> SessionKeys {
    SessionKeys { aura, grandpa }
}

type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// Helper function to generate a crypto pair from seed
fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <MultiSignature as Verify>::Signer;

/// Helper function to generate an account ID from seed
fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate an authority key for Aura and Grandpa
fn get_authority_keys_from_seed(s: &str) -> (AccountId, AuraId, GrandpaId) {
    (
        get_account_id_from_seed::<sr25519::Public>(s),
        get_from_seed::<AuraId>(s),
        get_from_seed::<GrandpaId>(s),
    )
}

/// Create a public key from an SS58 address
fn pubkey_from_ss58<T: Public>(ss58: &str) -> T {
    Ss58Codec::from_string(ss58).unwrap()
}

/// Create an account id from a SS58 address
fn account_id_from_ss58<T: Public>(ss58: &str) -> AccountId
where
    AccountPublic: From<T>,
{
    AccountPublic::from(pubkey_from_ss58::<T>(ss58)).into_account()
}

/// Create a non-secure development did with specified secret key
fn did_from_seed(did: &[u8; 32], seed: &[u8; 32]) -> (Did, KeyDetail) {
    let pk = sr25519::Pair::from_seed(seed).public().0;
    (
        *did,
        KeyDetail::new(*did, did::PublicKey::Sr25519(did::Bytes32 { value: pk })),
    )
}

pub fn development_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Development",
        "dev",
        ChainType::Development,
        || {
            GenesisBuilder {
                initial_authorities: vec![get_authority_keys_from_seed("Alice")],
                endowed_accounts: ["Alice", "Bob", "Alice//stash", "Bob//stash"]
                    .iter()
                    .cloned()
                    .map(get_account_id_from_seed::<sr25519::Public>)
                    .collect(),
                master: Membership {
                    members: [
                        b"Alice\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Bob\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Charlie\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ]
                    .iter()
                    .cloned()
                    .cloned()
                    .collect(),
                    vote_requirement: 2,
                },
                dids: [
                    (
                        b"Alice\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Alicesk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ),
                    (
                        b"Bob\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Bobsk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ),
                    (
                        b"Charlie\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Charliesk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ),
                ]
                .iter()
                .map(|(name, sk)| did_from_seed(name, sk))
                .collect(),
                sudo: get_account_id_from_seed::<sr25519::Public>("Alice"),
                min_epoch_length: 8,
                max_active_validators: 2,
                emission_status: true,
            }
            .build()
        },
        vec![],
        None,
        None,
        None,
        None,
    )
}

pub fn local_testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Local Poa Testnet",
        "local_poa_testnet",
        ChainType::Local,
        || {
            GenesisBuilder {
                initial_authorities: vec![
                    get_authority_keys_from_seed("Alice"),
                    get_authority_keys_from_seed("Bob"),
                ],
                endowed_accounts: [
                    "Alice",
                    "Bob",
                    "Charlie",
                    "Dave",
                    "Eve",
                    "Ferdie",
                    "Alice//stash",
                    "Bob//stash",
                    "Charlie//stash",
                    "Dave//stash",
                    "Eve//stash",
                    "Ferdie//stash",
                ]
                .iter()
                .cloned()
                .map(get_account_id_from_seed::<sr25519::Public>)
                .collect(),
                master: Membership {
                    members: [
                        b"Alice\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Bob\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Charlie\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ]
                    .iter()
                    .cloned()
                    .cloned()
                    .collect(),
                    vote_requirement: 2,
                },
                dids: [
                    (
                        b"Alice\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Alicesk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ),
                    (
                        b"Bob\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Bobsk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ),
                    (
                        b"Charlie\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"Charliesk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ),
                ]
                .iter()
                .map(|(name, sk)| did_from_seed(name, sk))
                .collect(),
                sudo: get_account_id_from_seed::<sr25519::Public>("Alice"),
                min_epoch_length: 16,
                max_active_validators: 4,
                emission_status: true,
            }
            .build()
        },
        vec![],
        None,
        None,
        None,
        None,
    )
}

pub fn testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Poa Testnet",
        "poa_testnet",
        ChainType::Live,
        || {
            GenesisBuilder {
                initial_authorities: vec![
                    (
                        account_id_from_ss58::<sr25519::Public>(
                            "5DjPH6m1x4QLc4YaaxtVX752nQWZzBHZzwNhn5TztyMDgz8t",
                        ),
                        pubkey_from_ss58::<AuraId>(
                            "5FkKCjCwd36ztkEKatp3cAbuUWjUECi4y5rQnpkoEeagTimD",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "5CemoFcouqEdmBgMYjQwkFjBFPzLRc5jcXyjD8dKvqBWwhfh",
                        ),
                    ),
                    (
                        account_id_from_ss58::<sr25519::Public>(
                            "5HR2ytqigzQdbthhWA2g5K9JQayczEPwhAfSqAwSyb8Etmqh",
                        ),
                        pubkey_from_ss58::<AuraId>(
                            "5DfRTtDzNyLuoCV77im5D6UyUx62HxmNYYvtkepaGaeMmoKu",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "5FJir6hEEWvVCt4PHJ95ygtw5MvgD2xoET9xqskTu4MZBC98",
                        ),
                    ),
                ],
                endowed_accounts: [
                    "5CUrmmBsA7oPP2uJ58yPTjZn7dUpFzD1MtRuwLdoPQyBnyWM",
                    "5DS9inxHmk3qLvTu1ZDWF9GrvkJRCR2xeWdCfa1k7dwwL1e2",
                    "5Fq9cARnUAWxKGU9w5UngNNMsfjcxenAAuBn8zYJwyidSnuU",
                    "5DcxJv1LRAiEmpR41xKUNbmefmutQ7WBEKEsS5xBxh8wQ99J",
                    "5E7BHnwo9LoKP6bAJseeqZgnWSbsFmiZxMAsEd7zGJfDoCCr",
                    "5DkS3AbP8mXWVUg8o9R7Y8czAPoi9JTYmS3FPzKx1z6735nd",
                    "5C89W6aJTdBBbXPhyLrefGSB97kXKWAo5NkqBvG8U9MKhEkP",
                    "5GpPMM3Mw1eAqniXQsRHdjd7dshmiudU46sELyRfGEbBoJu5",
                ]
                .iter()
                .cloned()
                .map(account_id_from_ss58::<sr25519::Public>)
                .collect(),
                master: Membership {
                    members: [
                        b"nm\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"nl\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        b"ec\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    ]
                    .iter()
                    .cloned()
                    .cloned()
                    .collect(),
                    vote_requirement: 2,
                },
                dids: [
                    (
                        b"nm\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        hex!("2a6f70c3dc8cd003075bbf14567c4251b512c5514dff069c293c14679f91913d"),
                    ),
                    (
                        b"nl\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        hex!("848001ef27f057719a31e0e457d4edd946c5792d03a8cb203bc025bdda825301"),
                    ),
                    (
                        b"ec\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        hex!("c85c62af598cb718ce4bd1b0b739605fa7a4252db508ceb23dbd3eb4ca523062"),
                    ),
                ]
                .iter()
                .cloned()
                .map(|(did, pk)| {
                    (
                        *did,
                        KeyDetail::new(*did, did::PublicKey::Sr25519(did::Bytes32 { value: pk })),
                    )
                })
                .collect(),
                // In mainnet, this will be a public key (0s) that no one knows private key for
                sudo: account_id_from_ss58::<sr25519::Public>(
                    "5CFfPovgr1iLJ4fekiTPmtGMyg7XGmLxUnTvd1Y4GigwPqzH",
                ),
                min_epoch_length: 100,
                max_active_validators: 8,
                emission_status: false,
            }
            .build()
        },
        vec!["/dns4/testnet-1.dock.io/tcp/30333/p2p/\
             12D3KooWSbaqC655sjBSk7bNMghWsKdy1deCKRL6aRf6xcmm9dwW"
            .parse()
            .unwrap()],
        None,
        None,
        None,
        None,
    )
}

struct GenesisBuilder {
    initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
    endowed_accounts: Vec<AccountId>,
    master: Membership,
    dids: Vec<(Did, KeyDetail)>,
    sudo: AccountId,
    min_epoch_length: u32,
    max_active_validators: u8,
    emission_status: bool,
}

impl GenesisBuilder {
    fn build(self) -> GenesisConfig {
        // 1 token is 25000000 gas
        let token_to_gas: Balance = 25_000_000;
        // 200M tokens
        let emission_supply: Balance = token_to_gas * 200_000_000;
        // TODO: This needs to be tweaked once we know all exchanges
        // 100M tokens
        let per_member_endowment: Balance = token_to_gas * 100_000_000;

        // Max emission per validator in an epoch
        // 30K tokens
        let max_emm_validator_epoch: Balance = token_to_gas * 15_000;

        // Percentage of rewards given to Treasury
        let treasury_reward_pc = 60;
        // Percentage of validator rewards that will be locked
        let validator_reward_lock_pc = 50;

        self.validate().unwrap();

        GenesisConfig {
            system: Some(SystemConfig {
                code: WASM_BINARY.unwrap().to_vec(),
                changes_trie_config: Default::default(),
            }),
            pallet_session: Some(SessionConfig {
                keys: self
                    .initial_authorities
                    .iter()
                    .map(|x| {
                        (
                            x.0.clone(),
                            x.0.clone(),
                            session_keys(x.1.clone(), x.2.clone()),
                        )
                    })
                    .collect::<Vec<_>>(),
            }),
            poa: Some(PoAModuleConfig {
                min_epoch_length: self.min_epoch_length,
                max_active_validators: self.max_active_validators,
                active_validators: self
                    .initial_authorities
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<_>>(),
                emission_supply,
                max_emm_validator_epoch,
                treasury_reward_pc,
                validator_reward_lock_pc,
                // TODO: This will be false on mainnet launch as there won't be any tokens.
                emission_status: self.emission_status,
            }),
            balances: Some(BalancesConfig {
                balances: self
                    .endowed_accounts
                    .iter()
                    .cloned()
                    .map(|k| (k, per_member_endowment))
                    .collect(),
            }),
            aura: Some(AuraConfig {
                authorities: vec![],
            }),
            grandpa: Some(GrandpaConfig {
                authorities: vec![],
            }),
            master: Some(MasterConfig {
                members: self.master,
            }),
            did: Some(DIDModuleConfig { dids: self.dids }),
            sudo: Some(SudoConfig { key: self.sudo }),
        }
    }

    fn validate(&self) -> Result<(), String> {
        // Every DID in master must be pre-declared
        for did in self.master.members.iter() {
            if !self.dids.iter().any(|(k, _v)| k == did) {
                return Err(format!(
                    "Master contains DID {:x?}.. that is not pre-declared",
                    did[0],
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn expected_did_from_seed() {
        let did = [1u8; 32];
        let pk = hex!("c02bab578b07e7e41997fcb03de683f4780e3ad383e573d817d2462f4a27c701");
        let sk = hex!("d2a75ce109331dde9b6f7782d56b0668ad2f7ad53d32aec4c1618292c2127e87");
        assert_eq!(
            did_from_seed(&did, &sk),
            (
                did,
                KeyDetail::new(did, did::PublicKey::Sr25519(did::Bytes32 { value: pk })),
            )
        );
    }
}
