use dock_runtime::{
    did::{self, Did, KeyDetail},
    master::Membership,
    opaque::SessionKeys,
    AuraConfig, Balance, BalancesConfig, DIDModuleConfig, GenesisConfig, GrandpaConfig,
    MasterConfig, PoAModuleConfig, SessionConfig, SudoConfig, SystemConfig, MILLISECS_PER_BLOCK,
    WASM_BINARY,
};
use hex_literal::hex;
use sc_service::{ChainType, Properties};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
};

use serde_json::map::Map;

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

fn get_common_properties_map() -> Properties {
    let mut properties = Map::new();
    properties.insert("tokenSymbol".into(), "DCK".into());
    properties.insert("tokenDecimals".into(), 6.into());
    properties
}

fn get_dev_properties() -> Properties {
    let mut properties = get_common_properties_map();
    properties.insert("ss58Format".into(), 42.into());
    properties
}

#[allow(dead_code)]
fn get_testnet_properties() -> Properties {
    let mut properties = get_common_properties_map();
    properties.insert("ss58Format".into(), 21.into());
    properties
}

fn get_mainnet_properties() -> Properties {
    let mut properties = get_common_properties_map();
    properties.insert("ss58Format".into(), 22.into());
    properties
}

pub fn development_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Development",
        "dev",
        ChainType::Development,
        || {
            GenesisBuilder {
                initial_authorities: vec![get_authority_keys_from_seed("Alice")],
                endowed_accounts: ["Alice", "Bob", "Alice//stash", "Bob//stash", "Charlie", "Dave", "Eve", "Ferdie",]
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
        Some(get_dev_properties()),
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
                max_active_validators: 5,
                emission_status: true,
            }
            .build()
        },
        vec![],
        None,
        None,
        Some(get_dev_properties()),
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
                min_epoch_length: 1000,
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
        // The chain is already deployed so can't use new prefix. If we ever choose to redeploy it, we
        // should use correct properties and update account addresses
        Some(get_dev_properties()),
        None,
    )
}

/// Configuration for the mainnet
pub fn mainnet_config() -> ChainSpec {
    // Epoch is of ~7 days, 604800000 ms in 7 days
    let min_epoch_length = (604800000 / MILLISECS_PER_BLOCK) as u32;
    let max_active_validators = 11;
    let emission_status = false;

    ChainSpec::from_genesis(
        "Dock Mainnet", // This will be used in the Telemetry so keeping the word "Dock" in there
        "dock_mainnet",
        ChainType::Live,
        move || {
            GenesisBuilder {
                initial_authorities: vec![
                    (
                        account_id_from_ss58::<sr25519::Public>(
                            "3Gb64wBURVBpAau5WVRRpAgNLPAnqsPR3CgoZPAK6diinaMp",
                        ),
                        pubkey_from_ss58::<AuraId>(
                            "3Gr7uEiA7jis4DdijeSTQnXoU4tc8DUZkjpy3mshhgyx3Hyw",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "3G4PHvp6EDBbmvfcDLEEkAQk1cRmvh3ZHp264pERRzcZzHwn",
                        ),
                    )
                ],
                endowed_accounts: [
                    "3EjNXTpMJieqEF5Fj5szwAqpvmmKFG3YtsY5eBazxaCkNtoz",
                    "3HmNvFfZey63mdUdKrQ2iTdbYB6ic5y9QaAZCQZ7aWMBnUu8",
                    "3CjsvaK2h1AkimGohPCZuykuykpp5SU5NvM2d8VLEmzt2Pd6",
                    "3FYRYvGLaatYrLMgU68frrptGbnMZCCakZaFQNDQy3WrEeAb",
                    "3J4zBr2jCttvBJrkks1U2Rquhmgk4pmSgEboNPPbmPp7fuSb",
                    "3D9gQig8SD3veR6n4Yjy8CeLAeVVrEN49UXia7Wztu4go4sF",
                    "3EQqc6uyguP1RsvJvQxzoz3stbvMuZoWA9vKX18u9su17Lu3",
                    "3HGY9pJWZfhXKhCzr8fYW989bf21Gk6PoWKcPSy9ewNKJXrJ",
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
                        hex!("628321c4c6c4e3ea9553b4c0762cd51dc05562c716cbd2b94ba6e87194474f48"),
                    ),
                    (
                        b"nl\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        hex!("ce63ce77519770026f67a500c9107d66f7570d5aab203ad739664e6b6aa1c201"),
                    ),
                    (
                        b"ec\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        hex!("082f15a97e4757100ead2cba1bad527def2a7602167ceea0a5854e03a27eed4a"),
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
                // Post mainnet launch, this will be changed into a public key (0s) that no one knows private key for
                sudo: account_id_from_ss58::<sr25519::Public>(
                    "3HqoTXW3HBQJoFpvRaAaJoNsWTBZs3CuGRqT9xxfv497k8fs",
                ),
                min_epoch_length,
                max_active_validators,
                emission_status,
            }
            .build()
        },
        vec!["/dns4/mainnet-node.dock.io/tcp/30333/p2p/\
             12D3KooWGTXSDietKtxC41fM5M8YmLVaQfnBnohkwaak3y5iqXMy"
            .parse()
            .unwrap()],
        None,
        None,
        Some(get_mainnet_properties()),
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
        let emission_supply: Balance = token_to_gas.checked_mul( 200_000_000).unwrap();
        // TODO: This needs to be tweaked once we know all exchanges
        // 100M tokens
        let per_member_endowment: Balance = token_to_gas.checked_mul(100_000_000).unwrap();

        // Max emission per validator in an epoch
        // 30K tokens
        let max_emm_validator_epoch: Balance = token_to_gas.checked_mul(15_000).unwrap();

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
