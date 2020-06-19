use dock_testnet_runtime::{
    AuraConfig, BalancesConfig, GenesisConfig, GrandpaConfig, SudoConfig, SystemConfig, WASM_BINARY,
    SessionConfig, opaque::SessionKeys, PoAModuleConfig
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair, Public, ecdsa};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
    print
};

fn session_keys(
    aura: AuraId,
    grandpa: GrandpaId,
) -> SessionKeys {
    SessionKeys { aura, grandpa }
}


/// THIS IS ONLY USED FOR GENESIS
/// THIS MUST BE SAME AS WHATS DEFINED IN runtime/lib.rs
const MinEpochLength: u32 = 5;

type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;

// Note this is the URL for the telemetry server
//const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <MultiSignature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate an authority key for Aura and Grandpa
pub fn get_authority_keys_from_seed(s: &str) -> (AccountId, AuraId, GrandpaId) {
    (get_account_id_from_seed::<sr25519::Public>(s), get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

/// Helper function to generate an account id and authority key for Aura and Grandpa
pub fn get_poa_authority_keys_from_seed(s: &str) -> (AccountId, AuraId, GrandpaId) {
    (get_account_id_from_seed::<sr25519::Public>(s), get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
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

pub fn development_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Development",
        "dev",
        ChainType::Development,
        || {
            testnet_genesis(
                vec![get_authority_keys_from_seed("Alice")],
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                vec![
                    get_account_id_from_seed::<sr25519::Public>("Alice"),
                    get_account_id_from_seed::<sr25519::Public>("Bob"),
                    get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                ],
                true,
            )
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
        "Local Testnet",
        "local_testnet",
        ChainType::Local,
        || {
            testnet_genesis(
                vec![
                    get_authority_keys_from_seed("Alice"),
                    get_authority_keys_from_seed("Bob"),
                ],
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                vec![
                    get_account_id_from_seed::<sr25519::Public>("Alice"),
                    get_account_id_from_seed::<sr25519::Public>("Bob"),
                    get_account_id_from_seed::<sr25519::Public>("Charlie"),
                    get_account_id_from_seed::<sr25519::Public>("Dave"),
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                    get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
                ],
                true,
            )
        },
        vec![],
        None,
        None,
        None,
        None,
    )
}

pub fn remote_testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "RemoteDevelopment",
        "remdev",
        ChainType::Live,
        || {
            testnet_genesis(
                vec![
                    (
                        account_id_from_ss58::<ecdsa::Public>(
                            "5DjPH6m1x4QLc4YaaxtVX752nQWZzBHZzwNhn5TztyMDgz8t"
                        ),
                        pubkey_from_ss58::<AuraId>(
                            "5FkKCjCwd36ztkEKatp3cAbuUWjUECi4y5rQnpkoEeagTimD",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "5CemoFcouqEdmBgMYjQwkFjBFPzLRc5jcXyjD8dKvqBWwhfh",
                        ),
                    ),
                    (
                        account_id_from_ss58::<ecdsa::Public>(
                            "5HR2ytqigzQdbthhWA2g5K9JQayczEPwhAfSqAwSyb8Etmqh"
                        ),
                        pubkey_from_ss58::<AuraId>(
                            "5DfRTtDzNyLuoCV77im5D6UyUx62HxmNYYvtkepaGaeMmoKu",
                        ),
                        pubkey_from_ss58::<GrandpaId>(
                            "5FJir6hEEWvVCt4PHJ95ygtw5MvgD2xoET9xqskTu4MZBC98",
                        ),
                    ),
                ],
                account_id_from_ss58::<sr25519::Public>(
                    "5CFfPovgr1iLJ4fekiTPmtGMyg7XGmLxUnTvd1Y4GigwPqzH",
                ),
                vec![
                    account_id_from_ss58::<sr25519::Public>(
                        "5CUrmmBsA7oPP2uJ58yPTjZn7dUpFzD1MtRuwLdoPQyBnyWM",
                    ),
                    account_id_from_ss58::<sr25519::Public>(
                        "5DS9inxHmk3qLvTu1ZDWF9GrvkJRCR2xeWdCfa1k7dwwL1e2",
                    ),
                ],
                true,
            )
        },
        vec![
            "/dns4/testnet-bootstrap1.dock.io/tcp/30333/p2p/\
                     QmaWVer8pXKR8AM6u2B8r9gXivTW9vTitb6gjLM6FYQcXS"
                .parse()
                .unwrap(),
            "/dns4/testnet-bootstrap2.dock.io/tcp/30333/p2p/\
                     QmPSP1yGiECdm5wVXVDF9stGfvVPSY8QUT4PhYB4Gnk77Q"
                .parse()
                .unwrap(),
        ],
        None,
        None,
        None,
        None,
    )
}

pub fn local_poa_testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Local PoA Testnet",
        "local_poa_testnet",
        ChainType::Local,
        || {
            testnet_genesis(
                vec![
                    get_authority_keys_from_seed("Alice"),
                    get_authority_keys_from_seed("Bob"),
                ],
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                vec![
                    get_account_id_from_seed::<sr25519::Public>("Alice"),
                    get_account_id_from_seed::<sr25519::Public>("Bob"),
                    get_account_id_from_seed::<sr25519::Public>("Charlie"),
                    get_account_id_from_seed::<sr25519::Public>("Dave"),
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                    get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
                    get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
                ],
                true,
            )
        },
        vec![],
        None,
        None,
        None,
        None,
    )
}

/*fn testnet_genesis(
    initial_authorities: Vec<(AuraId, GrandpaId)>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
    _enable_println: bool,
) -> GenesisConfig {
    GenesisConfig {
        system: Some(SystemConfig {
            code: WASM_BINARY.to_vec(),
            changes_trie_config: Default::default(),
        }),
        balances: Some(BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1 << 60))
                .collect(),
        }),
        sudo: Some(SudoConfig { key: root_key }),
        aura: Some(AuraConfig {
            authorities: initial_authorities.iter().map(|x| (x.0.clone())).collect(),
        }),
        grandpa: Some(GrandpaConfig {
            authorities: initial_authorities
                .iter()
                .map(|x| (x.1.clone(), 1))
                .collect(),
        }),
    }
}*/

fn testnet_genesis(
    initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
    _enable_println: bool,
) -> GenesisConfig {
    let num_auth = initial_authorities.len() as u32;
    let rem = MinEpochLength % num_auth;
    let epoch_len = if rem == 0 {
        MinEpochLength
    } else {
        MinEpochLength + num_auth - rem
    };
    print("epoch_len is---");
    print(epoch_len);
    println!("epoch_len is {}", epoch_len);
    // Customize
    GenesisConfig {
        system: Some(SystemConfig {
            code: WASM_BINARY.to_vec(),
            changes_trie_config: Default::default(),
        }),
        pallet_session: Some(SessionConfig {
            keys: initial_authorities.iter().map(|x| {
                (x.0.clone(), x.0.clone(), session_keys(x.1.clone(), x.2.clone()))
            }).collect::<Vec<_>>(),
        }),
        poa: Some(PoAModuleConfig {
            active_validators: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
            next_epoch_begins_after: epoch_len + 1,    // +1 as first block is genesis and not produced by anyone
            force_session_change: false,
        }),
        balances: Some(BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1 << 60))
                .collect(),
        }),
        sudo: Some(SudoConfig { key: root_key }),
        aura: Some(AuraConfig {
            //authorities: initial_authorities.iter().map(|x| (x.1.clone())).collect(),
            authorities:  vec![],
        }),
        grandpa: Some(GrandpaConfig {
            // authorities: initial_authorities
            //     .iter()
            //     .map(|x| (x.2.clone(), 1))
            //     .collect(),
            authorities: vec![]
        }),
    }
}
