use dock_testnet_runtime::{
    opaque::SessionKeys, AuraConfig, BalancesConfig, GenesisConfig, GrandpaConfig, PoAModuleConfig,
    SessionConfig, SudoConfig, SystemConfig, WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::crypto::Ss58Codec;
use sp_core::{ecdsa, sr25519, Pair, Public};
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
                        account_id_from_ss58::<ecdsa::Public>(
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
                ],
            )
        },
        vec![],
        None,
        None,
        None,
        None,
    )
}

fn testnet_genesis(
    initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
) -> GenesisConfig {
    // 1 token is 25000000 gas
    let token_to_gas: u128 = 25_000_000;
    // 200M tokens
    let emission_supply: u128 = token_to_gas * 200_000_000;
    // TODO: This needs to be tweaked once we know all exchanges
    // 100M tokens
    let per_member_endowment: u128 = token_to_gas * 100_000_000;

    // Max emission per validator in an epoch
    // 30K tokens
    let max_emm_validator_epoch: u128 = token_to_gas * 15_000;

    GenesisConfig {
        system: Some(SystemConfig {
            code: WASM_BINARY.to_vec(),
            changes_trie_config: Default::default(),
        }),
        pallet_session: Some(SessionConfig {
            keys: initial_authorities
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
            min_epoch_length: 16,
            max_active_validators: 4,
            active_validators: initial_authorities
                .iter()
                .map(|x| x.0.clone())
                .collect::<Vec<_>>(),
            emission_supply,
            max_emm_validator_epoch,
            treasury_reward_pc: 60,
            validator_reward_lock_pc: 50,
            // TODO: This will be false on mainnet launch as there won't be any tokens.
            emission_status: true,
        }),
        balances: Some(BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, per_member_endowment))
                .collect(),
        }),
        sudo: Some(SudoConfig { key: root_key }),
        aura: Some(AuraConfig {
            authorities: vec![],
        }),
        grandpa: Some(GrandpaConfig {
            authorities: vec![],
        }),
    }
}
