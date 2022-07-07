use dock_runtime::{
    did::{Did, DidKey},
    keys_and_sigs::PublicKey,
    master::Membership,
    AccountId, AuthorityDiscoveryConfig, BabeConfig, Balance, BalancesConfig, DIDModuleConfig,
    EVMConfig, ElectionsConfig, EthereumConfig, GenesisConfig, GrandpaConfig, Hash, ImOnlineConfig,
    MasterConfig, PoAModuleConfig, SessionConfig, SessionKeys, Signature, StakerStatus,
    StakingConfig, SudoConfig, SystemConfig, TechnicalCommitteeConfig, BABE_GENESIS_EPOCH_CONFIG,
    DOCK, WASM_BINARY,
};
use hex_literal::hex;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_service::{ChainType, Properties};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::{AuthorityId as BabeId, BabeEpochConfiguration};
use sp_core::{crypto::Ss58Codec, sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{IdentifyAccount, Verify};

use serde_json::map::Map;

use sp_runtime::Perbill;
use std::{collections::BTreeMap, str::FromStr};

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
fn did_from_seed(did: &[u8; 32], seed: &[u8; 32]) -> (Did, DidKey) {
    let pk = sr25519::Pair::from_seed(seed).public().0;
    (
        Did(*did),
        DidKey::new_with_all_relationships(PublicKey::sr25519(pk)),
    )
}

fn get_common_properties_map() -> Properties {
    let mut properties = Map::new();
    properties.insert("tokenSymbol".into(), "DOCK".into());
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
                    .map(|d| Did(**d))
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
                council_members: get_seed_vector_to_account_vector(
                    ["Alice//stash", "Bob//stash", "Charlie"].to_vec(),
                ),
                technical_committee_members: get_seed_vector_to_account_vector(
                    ["Charlie", "Dave", "Eve"].to_vec(),
                ),
                stash: 100 * DOCK,
                validator_count: 3,
                // TODO: Fix
                poa_last_block: Hash::repeat_byte(42),
                babe_epoch_config: BABE_GENESIS_EPOCH_CONFIG,
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
        "Local Testnet",
        "local_testnet",
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
                    .map(|d| Did(**d))
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
                council_members: get_seed_vector_to_account_vector(
                    ["Alice//stash", "Bob//stash", "Charlie"].to_vec(),
                ),
                technical_committee_members: get_seed_vector_to_account_vector(
                    ["Charlie", "Dave", "Eve"].to_vec(),
                ),
                stash: 1000 * DOCK,
                validator_count: 10,
                // TODO: Fix
                poa_last_block: Hash::repeat_byte(42),
                babe_epoch_config: BABE_GENESIS_EPOCH_CONFIG,
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
        "Dock PoS Testnet",
        "dock_pos_testnet",
        ChainType::Live,
        || {
            GenesisBuilder {
                initial_authorities: vec![(
                    // Dock V1
                    account_id_from_ss58::<sr25519::Public>(
                        "39sz7eSJE2MfFT6345boRTKqdS6vh2Pq779TdpitMFRNi5Jr",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "38TGisDkCrzzkANAXVoFQwmAR7dNWs3E94axqn6nxKBcmGp4",
                    ),
                    pubkey_from_ss58::<BabeId>("3ADTmtqUYvjjcWjaZiLYgF1yuKjJ5MV91LDesUFUWh6SYtug"),
                    pubkey_from_ss58::<GrandpaId>(
                        "377vNRFLqisNUxBcXYwSpL9FgCzAGkroenLyHn81CshH2qQT",
                    ),
                    pubkey_from_ss58::<ImOnlineId>(
                        "3ADTmtqUYvjjcWjaZiLYgF1yuKjJ5MV91LDesUFUWh6SYtug",
                    ),
                    pubkey_from_ss58::<AuthorityDiscoveryId>(
                        "3ADTmtqUYvjjcWjaZiLYgF1yuKjJ5MV91LDesUFUWh6SYtug",
                    ),
                )],
                endowed_accounts: [
                    "39sz7eSJE2MfFT6345boRTKqdS6vh2Pq779TdpitMFRNi5Jr", // Dock V1
                    "36ioxyZDmuM51qAujXytqxgSQV7M7v82X2qAhf2jYmChV8oN", // Sudo
                    "36iNsCXukfGTmSJBBvWaakvJTqEPWEWQ1CGXZpK1BP1ZxJbF", // API
                    "37yrw7s12i6VtGHAA6XkKL6onUTpk4KXoeCAx6eiW9Xc1KjC", // Faucet
                    "3AJJBL4KQ49h32yQuu1HkSnSJUjSooZED9Z2De2zE2EPXxbN",
                    "3866t5dsM4LyVavJzmqySgBj6auiFGHFGZc7WjSsEjehVSpM",
                    "38aKrxaL5ES46s6RHhB9ue6rwFbh6vVdzbY7KGcfYMAytWNS",
                    "39o6FM6ZKZ2Jcz7N3HJ276Y6bkp4CoYZLPmwUAUPKsFoCAM5", // Council 2
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
                    .map(|d| Did(**d))
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
                        Did(*did),
                        DidKey::new_with_all_relationships(PublicKey::sr25519(pk)),
                    )
                })
                .collect(),
                // In mainnet, this will be a public key (0s) that no one knows private key for
                sudo: account_id_from_ss58::<sr25519::Public>(
                    "36ioxyZDmuM51qAujXytqxgSQV7M7v82X2qAhf2jYmChV8oN",
                ),
                council_members: vec![
                    account_id_from_ss58::<sr25519::Public>(
                        "39sz7eSJE2MfFT6345boRTKqdS6vh2Pq779TdpitMFRNi5Jr",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "39o6FM6ZKZ2Jcz7N3HJ276Y6bkp4CoYZLPmwUAUPKsFoCAM5",
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
                stash: 1_000 * DOCK,
                validator_count: 3,
                poa_last_block: Hash::from_str(
                    "0d84a546e4fdde4bf7c56c764a42457ee05b45bdc0c20e765903ab96465b8b3e",
                )
                .unwrap(),
                babe_epoch_config: BABE_GENESIS_EPOCH_CONFIG,
            }
            .build()
        },
        vec!["/dns4/knox-1.dock.io/tcp/30333/p2p/\
             12D3KooWFWhaZ8DxgwN7KJyFBPuQTL838amWqNKPTFtJJ8ZtZpPQ"
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
    ChainSpec::from_genesis(
        "Dock PoS Mainnet", // This will be used in the Telemetry so keeping the word "Dock" in there
        "dock_pos_mainnet",
        ChainType::Live,
        move || {
            GenesisBuilder {
                initial_authorities: vec![
                    (
                        // Dock
                        account_id_from_ss58::<sr25519::Public>(
                            "3Gb64wBURVBpAau5WVRRpAgNLPAnqsPR3CgoZPAK6diinaMp",
                        ),
                        account_id_from_ss58::<sr25519::Public>(
                            "3CtFE8uweavb7NLxT8M6XXrqmPAHwnZzLLjGFaZaUT3TsLFc",
                        ),
                        pubkey_from_ss58::<BabeId>(
                            "3Gr7uEiA7jis4DdijeSTQnXoU4tc8DUZkjpy3mshhgyx3Hyw",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "3G4PHvp6EDBbmvfcDLEEkAQk1cRmvh3ZHp264pERRzcZzHwn",
                        ),
                        pubkey_from_ss58::<ImOnlineId>(
                            "3Gr7uEiA7jis4DdijeSTQnXoU4tc8DUZkjpy3mshhgyx3Hyw",
                        ),
                        pubkey_from_ss58::<AuthorityDiscoveryId>(
                            "3Gr7uEiA7jis4DdijeSTQnXoU4tc8DUZkjpy3mshhgyx3Hyw",
                        ),
                    ),
                    (
                        // Sebastian
                        account_id_from_ss58::<sr25519::Public>(
                            "3EnG2iod8ThS7dhh9wygvi7qMjBPKBgfvA1ksQmy7Kh8q3Jn",
                        ),
                        account_id_from_ss58::<sr25519::Public>(
                            "3Gu97k8voXQgXSfyyLmveiyzaSTgRbNrmZaESgbsAeteLRob",
                        ),
                        pubkey_from_ss58::<BabeId>(
                            "3Gg76YYbXVfPTkNF2UttthHohfZbAt7FhyRDZDdHCpWia2zU",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "3GohMRgRysfkJYjTktKNYjbXkN4CXwyCE1wxWT1zU5GcCW9h",
                        ),
                        pubkey_from_ss58::<ImOnlineId>(
                            "3D71ST82aNxJMXQEiX4xvwZJRDRViLtsoGjXowU8LHmsWA4w",
                        ),
                        pubkey_from_ss58::<AuthorityDiscoveryId>(
                            "3D3tZb7UMwyysLJK2ib4LzYUXrZWziZnX2JsipZKaTNzH3HQ",
                        ),
                    ),
                    (
                        // Ryabina
                        account_id_from_ss58::<sr25519::Public>(
                            "3GfPebPXY4DrgmcxmkbKgCTc3gQDLffGNAbGJL4QGegWDFvr",
                        ),
                        account_id_from_ss58::<sr25519::Public>(
                            "3DMxY4BAXVKQyPzD2ptVTtWBFPYetuUzxZNnhxwGDxEU4hVr",
                        ),
                        pubkey_from_ss58::<BabeId>(
                            "3DZRiAxXrRQvyPMWusAaCSdUhHrg8mvSURuWsYfuKvym5enV",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "3D7myE1PhvgRZifaepPiAoKHxtJKvtTw8YDdUiQSWmT3Nkcm",
                        ),
                        pubkey_from_ss58::<ImOnlineId>(
                            "3Gcgfe7v3d2vkFgUMvc81UeRnZ3jbJRsNr9cuZyrkwuHN47X",
                        ),
                        pubkey_from_ss58::<AuthorityDiscoveryId>(
                            "3G3FC3MzqqtUcG8mt37ivYYpWAHMfEhoq2sWJgMdENhJevuH",
                        ),
                    ),
                    (
                        // Pathrock
                        account_id_from_ss58::<sr25519::Public>(
                            "3Fx3GPCR6F3Wc8EyoJY7fxEJv2ch1bHXCy8AKUCEKfQRbifD",
                        ),
                        account_id_from_ss58::<sr25519::Public>(
                            "3HJXQkYFoqeoYLba4PiQDLARY9Fk8Hj7y2mrYShPLhgUFpYp",
                        ),
                        pubkey_from_ss58::<BabeId>(
                            "3Fr7kyamDqAmi9VbejgSZzkMnCjeHHiabKNKAEVzMYJB5X58",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "3FLqrfaGUzyPT7m3hvZztzBHKsTK9N5ged941zYuyB7QficR",
                        ),
                        pubkey_from_ss58::<ImOnlineId>(
                            "3FSnbCYv6J3ayjo4gF7gFqEwiaF3w8Sit1kGj2G78b2L8fQF",
                        ),
                        pubkey_from_ss58::<AuthorityDiscoveryId>(
                            "3GiiWVL2DMPc9UoMv8ryoogY4RnHvKVHr4jaC8maPRbwmpch",
                        ),
                    ),
                    (
                        // Ovrhd
                        account_id_from_ss58::<sr25519::Public>(
                            "3GXbRJNihSi4wogCVGLjCVZQtpzcuPGW5WnyDpx3orNh4UyW",
                        ),
                        account_id_from_ss58::<sr25519::Public>(
                            "3GifWRvo5dhuzxtH81r1kiTkZzy7PMgnhN6pfKNxPEjdQMkD",
                        ),
                        pubkey_from_ss58::<BabeId>(
                            "3ETxxJtV6ip69sBftRvsB4wiv7x1MPHgiGyv6mM7woaGsxgu",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "3GosAKwfLsdCPETtMyWobMU29v6XMTuhhryYnk5xfXhgqMra",
                        ),
                        pubkey_from_ss58::<ImOnlineId>(
                            "3FGZUCKy14c8DG99GgScHNJgvLJEqoDLMSfJ55hTxipxSASS",
                        ),
                        pubkey_from_ss58::<AuthorityDiscoveryId>(
                            "3Cs7TsVMhbmVuKp43mrSvJTScE8VCgtpUa1hthyUdYBDkyQy",
                        ),
                    ),
                ],
                endowed_accounts: [
                    "3Gb64wBURVBpAau5WVRRpAgNLPAnqsPR3CgoZPAK6diinaMp",
                    "3EnG2iod8ThS7dhh9wygvi7qMjBPKBgfvA1ksQmy7Kh8q3Jn",
                    "3GfPebPXY4DrgmcxmkbKgCTc3gQDLffGNAbGJL4QGegWDFvr",
                    "3Fx3GPCR6F3Wc8EyoJY7fxEJv2ch1bHXCy8AKUCEKfQRbifD",
                    "3GXbRJNihSi4wogCVGLjCVZQtpzcuPGW5WnyDpx3orNh4UyW",
                    "3EpgfUS2x744ZTFccNdkpRRSW1efbYyqNyw81x9eHqy7JuAS",
                    "3EuDQ56g6hpZgdLNwkb4EzqhdGk6oPpd51KzHqSP8TXYuzeV",
                    "3EBrJoDw8hbuCrww4mV8o1YzG8JtmWHh4MbHb5rKPYgAVA23",
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
                    .map(|d| Did(**d))
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
                        Did(*did),
                        DidKey::new_with_all_relationships(PublicKey::sr25519(pk)),
                    )
                })
                .collect(),
                // Post mainnet launch, this will be changed into a public key (0s) that no one knows private key for
                sudo: account_id_from_ss58::<sr25519::Public>(
                    "3HqoTXW3HBQJoFpvRaAaJoNsWTBZs3CuGRqT9xxfv497k8fs",
                ),
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
                // Initial stakers/validators should have at least this amount as balance
                stash: 1_000 * DOCK,
                validator_count: 7,
                // TODO: Fix
                poa_last_block: Hash::from_str(
                    "16e8d1eec1f20b755bf850dd584bb516ff2a5e4d95e0bff61eb99efd8cb2d1ce",
                )
                .unwrap(),
                babe_epoch_config: BABE_GENESIS_EPOCH_CONFIG,
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
    dids: Vec<(Did, DidKey)>,
    sudo: AccountId,
    council_members: Vec<AccountId>,
    technical_committee_members: Vec<AccountId>,
    /// Balance that would be locked for the initial authorities
    stash: Balance,
    /// Maximum allowed validators
    validator_count: u16,
    /// Hash of the last block of PoA chain
    poa_last_block: Hash,
    babe_epoch_config: BabeEpochConfiguration,
}

impl GenesisBuilder {
    fn build(self) -> GenesisConfig {
        // 200M tokens
        let emission_supply: Balance = DOCK.checked_mul(200_000_000).unwrap();
        // 100M tokens
        let per_member_endowment: Balance = DOCK.checked_mul(100_000_000).unwrap();

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
                emission_supply,
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
                slash_reward_fraction: Perbill::from_percent(20),
                ..Default::default()
            },
            pallet_babe: BabeConfig {
                authorities: vec![],
                epoch_config: Some(self.babe_epoch_config),
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
                    did,
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
                Did(did),
                DidKey::new_with_all_relationships(PublicKey::sr25519(pk)),
            )
        );
    }
}
