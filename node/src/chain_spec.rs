use dock_runtime::{
    did::{self, Did, KeyDetail},
    master::Membership,
    price_feed::{util::ParamType, ContractConfig},
    AccountId, AuthorityDiscoveryConfig, BabeConfig, Balance, BalancesConfig, DIDModuleConfig,
    EVMConfig, ElectionsConfig, EthereumConfig, GenesisConfig, GrandpaConfig, Hash, ImOnlineConfig,
    MasterConfig, PoAModuleConfig, PriceFeedModuleConfig, SessionConfig, SessionKeys, Signature,
    StakerStatus, StakingConfig, SudoConfig, SystemConfig, TechnicalCommitteeConfig,
    BABE_GENESIS_EPOCH_CONFIG, DOCK, MAX_ALLOWED_VALIDATORS, MILLISECS_PER_BLOCK, WASM_BINARY,
};
use hex_literal::hex;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_service::{ChainType, Properties};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair, Public, H160};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{IdentifyAccount, Verify};

use serde_json::map::Map;

use sp_runtime::Perbill;
use std::collections::BTreeMap;

fn session_keys(
    babe: BabeId,
    grandpa: GrandpaId,
    im_online: ImOnlineId,
    authority_discovery: AuthorityDiscoveryId,
) -> SessionKeys {
    SessionKeys {
        babe,
        grandpa,
        im_online,
        authority_discovery,
    }
}

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// Helper function to generate a crypto pair from seed
fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate an authority key for Babe, Grandpa, ImOnline and Authority discovery
fn get_authority_keys_from_seed(
    seed: &str,
) -> (
    AccountId,
    AccountId,
    BabeId,
    GrandpaId,
    ImOnlineId,
    AuthorityDiscoveryId,
) {
    (
        get_account_id_from_seed::<sr25519::Public>(&format!("{}//stash", seed)),
        get_account_id_from_seed::<sr25519::Public>(seed),
        get_from_seed::<BabeId>(seed),
        get_from_seed::<GrandpaId>(seed),
        get_from_seed::<ImOnlineId>(seed),
        get_from_seed::<AuthorityDiscoveryId>(seed),
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

fn get_seed_vector_to_account_vector(seeds: Vec<&str>) -> Vec<AccountId> {
    seeds
        .iter()
        .cloned()
        .map(get_account_id_from_seed::<sr25519::Public>)
        .collect()
}

fn get_dev_chain_price_feed_contract() -> ContractConfig {
    ContractConfig {
        address: H160::from([
            102, 119, 174, 46, 44, 201, 133, 68, 109, 66, 165, 189, 238, 24, 39, 2, 232, 94, 133,
            135,
        ]),
        query_aggregator_abi_encoded: vec![36, 90, 123, 252],
        query_price_abi_encoded: vec![254, 175, 150, 140],
        return_val_abi: vec![
            ParamType::Uint(80),
            ParamType::Int(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(80),
        ],
    }
}

pub fn development_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Development",
        "dev",
        ChainType::Development,
        || {
            GenesisBuilder {
                initial_authorities: vec![get_authority_keys_from_seed("Alice")],
                endowed_accounts: get_seed_vector_to_account_vector(vec![
                    "Alice",
                    "Bob",
                    "Alice//stash",
                    "Bob//stash",
                    "Charlie",
                    "Dave",
                    "Eve",
                    "Ferdie",
                ]),
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
                council_members: get_seed_vector_to_account_vector(
                    ["Alice//stash", "Bob//stash", "Charlie"].to_vec(),
                ),
                technical_committee_members: get_seed_vector_to_account_vector(
                    ["Charlie", "Dave", "Eve"].to_vec(),
                ),
                contract_config: get_dev_chain_price_feed_contract(),
                stash: 100 * DOCK,
                validator_count: 3,
                // TODO: Fix
                poa_last_block: Hash::repeat_byte(42),
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
                endowed_accounts: get_seed_vector_to_account_vector(vec![
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
                ]),
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
                council_members: get_seed_vector_to_account_vector(
                    ["Alice//stash", "Bob//stash", "Charlie"].to_vec(),
                ),
                technical_committee_members: get_seed_vector_to_account_vector(
                    ["Charlie", "Dave", "Eve"].to_vec(),
                ),
                contract_config: get_dev_chain_price_feed_contract(),
                stash: 100 * DOCK,
                validator_count: 20,
                // TODO: Fix
                poa_last_block: Hash::repeat_byte(42),
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

/// Configuration for the PoS testnet
pub fn pos_testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Dock Testnet",
        "dock_pos_testnet",
        ChainType::Live,
        || {
            GenesisBuilder {
                initial_authorities: vec![
                    (
                        // TODO: Keeping stash and controller same for now. Fix later.
                        account_id_from_ss58::<sr25519::Public>(
                            "5DjPH6m1x4QLc4YaaxtVX752nQWZzBHZzwNhn5TztyMDgz8t",
                        ),
                        account_id_from_ss58::<sr25519::Public>(
                            "39sz7eSJE2MfFT6345boRTKqdS6vh2Pq779TdpitMFRNi5Jr",
                        ),
                        pubkey_from_ss58::<BabeId>(
                            "3ADTmtqUYvjjcWjaZiLYgF1yuKjJ5MV91LDesUFUWh6SYtug",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "377vNRFLqisNUxBcXYwSpL9FgCzAGkroenLyHn81CshH2qQT",
                        ),
                        // TODO: Keeping same as BabeId. Fix later.
                        pubkey_from_ss58::<ImOnlineId>(
                            "5FkKCjCwd36ztkEKatp3cAbuUWjUECi4y5rQnpkoEeagTimD",
                        ),
                        pubkey_from_ss58::<AuthorityDiscoveryId>(
                            "5FkKCjCwd36ztkEKatp3cAbuUWjUECi4y5rQnpkoEeagTimD",
                        ),
                    ),
                    (
                        account_id_from_ss58::<sr25519::Public>(
                            "39o6FM6ZKZ2Jcz7N3HJ276Y6bkp4CoYZLPmwUAUPKsFoCAM5",
                        ),
                        account_id_from_ss58::<sr25519::Public>(
                            "5DjPH6m1x4QLc4YaaxtVX752nQWZzBHZzwNhn5TztyMDgz8t",
                        ),
                        pubkey_from_ss58::<BabeId>(
                            "388a33rXJryeWxzN6YHaHAu3um5r97YSaoJ8qJKFYdA7s5qK",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "39msRGKmAQZDveZeG7fb3mK1WAvW4BjsGhXCvXF9B6sKGVMi",
                        ),
                        // TODO: Keeping same as BabeId. Fix later.
                        pubkey_from_ss58::<ImOnlineId>(
                            "5DfRTtDzNyLuoCV77im5D6UyUx62HxmNYYvtkepaGaeMmoKu",
                        ),
                        pubkey_from_ss58::<AuthorityDiscoveryId>(
                            "5DfRTtDzNyLuoCV77im5D6UyUx62HxmNYYvtkepaGaeMmoKu",
                        ),
                    ),
                ],
                endowed_accounts: [
                    "36x1LvpQ61S86oQZ3xVtXoyrYSUe78z5Q8oA1z8UfTUwtRkL",
                    "37uJHxaphdga4gy9zNk1KDgwMZJF3Zp2gkzSkDWRPgThR4nN",
                    "3AJJBL4KQ49h32yQuu1HkSnSJUjSooZED9Z2De2zE2EPXxbN",
                    "3866t5dsM4LyVavJzmqySgBj6auiFGHFGZc7WjSsEjehVSpM",
                    "38aKrxaL5ES46s6RHhB9ue6rwFbh6vVdzbY7KGcfYMAytWNS",
                    "38DacLDv4fAFDFBPmxwccD34bCoXzTEcogQVUdpdJ2bs8RRo",
                    "36bJ5GCqPWovKHtxxAP9jLrFZvkMAews7d85GZkokBs5nTGy",
                    "3BHXvWftruGuZZDnPgwnhp3C4ghba4QY6MEURcvLYH6wtcwQ",
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
                    "36ioxyZDmuM51qAujXytqxgSQV7M7v82X2qAhf2jYmChV8oN",
                ),
                min_epoch_length: 1000,
                max_active_validators: 8,
                emission_status: false,
                council_members: vec![
                    account_id_from_ss58::<sr25519::Public>(
                        "3B2UdCG1V67DqqyukyKUkAHr9tzNHu4kkP3zMzhpQhJC4phU",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3Bbw94DwFtVPgUnFM1aWPiBNxY9Cu7wu6tVnY2Q28nRcp8ZY",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3B1Uzug8RUBQn7DHHv1TG5qxVqB6fpMP2WXoHV19Gt3pvETt",
                    ),
                ],
                technical_committee_members: vec![
                    account_id_from_ss58::<sr25519::Public>(
                        "39PMxQAnMXeFcF4arwoswqs7rfJ3h2QAFdDRB7s23may1G6v",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3C4thWXiNJP4U1rQ5GSUcHb6P6hxxBQur6MybepEbu26evDf",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "39FphaNUGfYMhiBnJXSyuTF9qKdm3JXNhLDJgDBjKdaKLJCe",
                    ),
                ],
                // TODO: Set this after deploying contract to testnet
                contract_config: get_dev_chain_price_feed_contract(),
                stash: 100 * DOCK,
                validator_count: 50,
                // TODO: Fix
                poa_last_block: Hash::repeat_byte(22),
            }
            .build()
        },
        vec!["/dns4/testnet-1.dock.io/tcp/30333/p2p/\
             12D3KooWSbaqC655sjBSk7bNMghWsKdy1deCKRL6aRf6xcmm9dwW"
            .parse()
            .unwrap()],
        None,
        None,
        Some(get_testnet_properties()),
        None,
    )
}

/// Configuration for the PoS mainnet
pub fn pos_mainnet_config() -> ChainSpec {
    // Epoch is of ~10 days, 864000000 ms in 10 days
    let min_epoch_length = (864000000 / MILLISECS_PER_BLOCK) as u32;
    let max_active_validators = 11;
    let emission_status = false;

    ChainSpec::from_genesis(
        "Dock Mainnet", // This will be used in the Telemetry so keeping the word "Dock" in there
        "dock_pos_mainnet",
        ChainType::Live,
        move || {
            GenesisBuilder {
                initial_authorities: vec![(
                    // TODO: Keeping stash and controller same for now. Fix later.
                    account_id_from_ss58::<sr25519::Public>(
                        "3Gb64wBURVBpAau5WVRRpAgNLPAnqsPR3CgoZPAK6diinaMp",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3Gb64wBURVBpAau5WVRRpAgNLPAnqsPR3CgoZPAK6diinaMp",
                    ),
                    pubkey_from_ss58::<BabeId>("3Gr7uEiA7jis4DdijeSTQnXoU4tc8DUZkjpy3mshhgyx3Hyw"),
                    pubkey_from_ss58::<GrandpaId>(
                        "3G4PHvp6EDBbmvfcDLEEkAQk1cRmvh3ZHp264pERRzcZzHwn",
                    ),
                    // TODO: Keeping same as BabeId. Fix later.
                    pubkey_from_ss58::<ImOnlineId>(
                        "3Gr7uEiA7jis4DdijeSTQnXoU4tc8DUZkjpy3mshhgyx3Hyw",
                    ),
                    pubkey_from_ss58::<AuthorityDiscoveryId>(
                        "3Gr7uEiA7jis4DdijeSTQnXoU4tc8DUZkjpy3mshhgyx3Hyw",
                    ),
                )],
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
                council_members: vec![
                    account_id_from_ss58::<sr25519::Public>(
                        "3EpgfUS2x744ZTFccNdkpRRSW1efbYyqNyw81x9eHqy7JuAS",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3EuDQ56g6hpZgdLNwkb4EzqhdGk6oPpd51KzHqSP8TXYuzeV",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3EBrJoDw8hbuCrww4mV8o1YzG8JtmWHh4MbHb5rKPYgAVA23",
                    ),
                ],
                technical_committee_members: vec![
                    account_id_from_ss58::<sr25519::Public>(
                        "3HPsdLzFNbffiQpgMxvztDPMfEixoyfbWioxzTSHg6Q1RKTr",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3H8WLyLk5LButFHsDJCN6CVP5bNWCKx3zcTpWEpMEpQwJgqd",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "3DMtxe6rnXAMnut5vtDEzPEV1JzsUTCrbq9R6t9xPNwZmit6",
                    ),
                ],
                // TODO: Set this after deploying contract to mainnet
                contract_config: get_dev_chain_price_feed_contract(),
                // TODO: Temporary value
                stash: 100 * DOCK,
                validator_count: MAX_ALLOWED_VALIDATORS,
                // TODO: Fix
                poa_last_block: Hash::repeat_byte(22),
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
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        BabeId,
        GrandpaId,
        ImOnlineId,
        AuthorityDiscoveryId,
    )>,
    endowed_accounts: Vec<AccountId>,
    master: Membership,
    dids: Vec<(Did, KeyDetail)>,
    sudo: AccountId,
    min_epoch_length: u32,
    max_active_validators: u8,
    emission_status: bool,
    council_members: Vec<AccountId>,
    technical_committee_members: Vec<AccountId>,
    contract_config: ContractConfig,
    /// Balance that would be locked for the initial authorities
    stash: Balance,
    /// Maximum allowed validators
    validator_count: u16,
    poa_last_block: Hash,
}

impl GenesisBuilder {
    fn build(self) -> GenesisConfig {
        // 200M tokens
        let emission_supply: Balance = DOCK.checked_mul(200_000_000).unwrap();
        // 100M tokens
        let per_member_endowment: Balance = DOCK.checked_mul(100_000_000).unwrap();

        // Max emission per validator in an epoch
        // 15K tokens
        let max_emm_validator_epoch: Balance = DOCK.checked_mul(15_000).unwrap();

        // Percentage of rewards given to Treasury
        let treasury_reward_pc = 60;
        // Percentage of validator rewards that will be locked
        let validator_reward_lock_pc = 50;

        self.validate().unwrap();

        let stash = self.stash;

        GenesisConfig {
            system: SystemConfig {
                code: WASM_BINARY.unwrap().to_vec(),
                changes_trie_config: Default::default(),
            },
            pallet_session: SessionConfig {
                keys: self
                    .initial_authorities
                    .iter()
                    .map(|x| {
                        (
                            x.0.clone(),
                            x.0.clone(),
                            session_keys(x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone()),
                        )
                    })
                    .collect::<Vec<_>>(),
            },
            poa: PoAModuleConfig {
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
                poa_last_block: self.poa_last_block,
            },
            balances: BalancesConfig {
                balances: self
                    .endowed_accounts
                    .iter()
                    .cloned()
                    .map(|k| (k, per_member_endowment))
                    .collect(),
            },
            grandpa: GrandpaConfig {
                authorities: vec![],
            },
            master: MasterConfig {
                members: self.master,
            },
            did: DIDModuleConfig { dids: self.dids },
            sudo: SudoConfig { key: self.sudo },
            pallet_collective_Instance1: Default::default(),
            pallet_collective_Instance2: TechnicalCommitteeConfig {
                members: self.technical_committee_members,
                phantom: Default::default(),
            },
            pallet_membership_Instance1: Default::default(),
            pallet_ethereum: EthereumConfig {},
            pallet_evm: EVMConfig {
                accounts: BTreeMap::new(),
            },
            price_feed: PriceFeedModuleConfig {
                contract_config: self.contract_config,
            },
            pallet_staking: StakingConfig {
                validator_count: self.validator_count as u32,
                minimum_validator_count: self.initial_authorities.len() as u32,
                stakers: self
                    .initial_authorities
                    .iter()
                    .map(|x| (x.0.clone(), x.1.clone(), stash, StakerStatus::Validator))
                    .collect(),
                invulnerables: self
                    .initial_authorities
                    .iter()
                    .map(|x| x.0.clone())
                    .collect(),
                // 10% of slashed amount goes as reward to the reporters of bad behavior.
                // TODO: Consider increasing it in the beginning
                slash_reward_fraction: Perbill::from_percent(10),
                ..Default::default()
            },
            pallet_babe: BabeConfig {
                authorities: vec![],
                epoch_config: Some(BABE_GENESIS_EPOCH_CONFIG),
            },
            pallet_im_online: ImOnlineConfig { keys: vec![] },
            pallet_authority_discovery: AuthorityDiscoveryConfig { keys: vec![] },
            pallet_treasury: Default::default(),
            pallet_elections_phragmen: ElectionsConfig {
                members: self
                    .council_members
                    .iter()
                    .cloned()
                    .map(|member| (member, stash))
                    .collect(),
            },
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
