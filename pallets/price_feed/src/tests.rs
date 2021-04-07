use crate::{mock::*, ContractConfig, Error, ParamType, DUMMY_SOURCE, GAS_LIMIT, ZERO_VALUE};
use common::traits::PriceProvider;
use frame_support::{assert_err, StorageValue};
use pallet_evm::Runner;
use sp_core::{H160, U256};

const AGGREGATOR_QUERY_ABI: [u8; 4] = [36, 90, 123, 252];
const PRICE_QUERY_ABI: [u8; 4] = [254, 175, 150, 140];

/// Deploy aggregator and proxy contracts and set contract config in this pallet
fn setup_contracts() -> (H160, H160) {
    let evm_config = <Test as pallet_evm::Config>::config();

    // Aggregator constructor call with arguments `10, 15, 1200, 1200, 10`
    let aggregator_deploy_code = hex::decode("608060405234801561001057600080fd5b506040516102e73803806102e7833981810160405260a081101561003357600080fd5b5080516020820151604083015160608401516080909401519293919290919061006885858585856001600160e01b0361007216565b50505050506100af565b600080546001600160501b039687166001600160501b03199182161790915560019490945560029290925560035560048054919093169116179055565b610229806100be6000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c80638cd221c91161005b5780638cd221c9146100e8578063c22c24991461010c578063f21f537d14610114578063feaf968c1461011c5761007d565b80636444bd16146100825780637519ab50146100c657806385bb7d69146100e0575b600080fd5b6100c4600480360360a081101561009857600080fd5b506001600160501b03813581169160208101359160408201359160608101359160809091013516610160565b005b6100ce6101a0565b60408051918252519081900360200190f35b6100ce6101a6565b6100f06101ac565b604080516001600160501b039092168252519081900360200190f35b6100f06101bb565b6100ce6101ca565b6101246101d0565b604080516001600160501b0396871681526020810195909552848101939093526060840191909152909216608082015290519081900360a00190f35b600080546001600160501b0396871669ffffffffffffffffffff199182161790915560019490945560029290925560035560048054919093169116179055565b60035481565b60015481565b6000546001600160501b031681565b6004546001600160501b031681565b60025481565b6000546001546002546003546004546001600160501b039485169416909192939456fea2646970667358221220739aa4f0c3ea9e475a476da24e7b66931c23a245f6542d41d7b936cd62e75e1264736f6c63430006050033000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000000004b000000000000000000000000000000000000000000000000000000000000004b0000000000000000000000000000000000000000000000000000000000000000a").expect("Decoding failed");
    let info = <Test as pallet_evm::Config>::Runner::create(
        DUMMY_SOURCE,
        aggregator_deploy_code,
        ZERO_VALUE,
        GAS_LIMIT,
        None,
        Some(U256::zero()),
        evm_config,
    )
    .unwrap();
    let aggregator_address = info.value;

    // Proxy contract constructor needs the aggregator contract address so its ABI encoding is appended to contract byte code
    let mut proxy_deploy_code = hex::decode("608060405234801561001057600080fd5b506040516101493803806101498339818101604052602081101561003357600080fd5b5051600080546001600160a01b039092166001600160a01b031990921691909117905560e5806100646000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c8063245a7bfc146037578063f9120af6146059575b600080fd5b603d607e565b604080516001600160a01b039092168252519081900360200190f35b607c60048036036020811015606d57600080fd5b50356001600160a01b0316608d565b005b6000546001600160a01b031690565b600080546001600160a01b0319166001600160a01b039290921691909117905556fea2646970667358221220e6ea90ae509c1e97b506e2a0f0a3696b49e7b564a2723832159db0e2ec54c73564736f6c63430006050033").unwrap();
    // ABI encoding of address is of 32 bytes
    proxy_deploy_code.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // 12 bytes of padding
    proxy_deploy_code.extend_from_slice(aggregator_address.as_bytes()); // 20 bytes of address

    // Proxy contract deploy
    let info = <Test as pallet_evm::Config>::Runner::create(
        DUMMY_SOURCE,
        proxy_deploy_code,
        ZERO_VALUE,
        GAS_LIMIT,
        None,
        Some(U256::one()), // Nonce increases by 1
        evm_config,
    )
    .unwrap();
    let proxy_address = info.value;

    let return_val_abi = vec![
        ParamType::Uint(80),
        ParamType::Int(256),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(80),
    ];
    let contract_config = ContractConfig {
        address: proxy_address,
        query_aggregator_abi_encoded: AGGREGATOR_QUERY_ABI.to_vec(),
        query_price_abi_encoded: PRICE_QUERY_ABI.to_vec(),
        return_val_abi,
    };

    PriceFeedModule::set_contract_config(Origin::root(), contract_config.clone()).unwrap();

    (aggregator_address, proxy_address)
}

#[test]
fn set_contract_config() {
    new_test_ext().execute_with(|| {
        let config = ContractConfig::default();

        assert!(PriceFeedModule::contract_config().is_none());

        // Non root cannot set config
        assert!(PriceFeedModule::set_contract_config(Origin::signed(10), config.clone()).is_err());
        assert!(PriceFeedModule::set_contract_config(Origin::signed(1), config.clone()).is_err());
        assert!(PriceFeedModule::set_contract_config(Origin::signed(500), config.clone()).is_err());

        PriceFeedModule::set_contract_config(Origin::root(), config.clone()).unwrap();
        assert!(PriceFeedModule::contract_config().is_some());
    })
}

#[test]
fn set_update_frequency() {
    new_test_ext().execute_with(|| {
        let freq = 135;

        assert!(PriceFeedModule::price_update_freq().is_none());

        // Non root cannot set frequency
        assert!(PriceFeedModule::set_update_frequency(Origin::signed(2), freq).is_err());
        assert!(PriceFeedModule::set_update_frequency(Origin::signed(39), freq).is_err());
        assert!(PriceFeedModule::set_update_frequency(Origin::signed(1025), freq).is_err());

        PriceFeedModule::set_update_frequency(Origin::root(), freq).unwrap();
        assert!(PriceFeedModule::price_update_freq().is_some());
    })
}

#[test]
fn price_stale() {
    new_test_ext().execute_with(|| {
        assert!(PriceFeedModule::price_update_freq().is_none());
        assert!(PriceFeedModule::last_price_update_at().is_none());

        // Price stale check should return false until both update frequency and last updated at are set
        assert!(!PriceFeedModule::is_price_stale(1).0);
        PriceFeedModule::set_update_frequency(Origin::root(), 5).unwrap();
        assert!(!PriceFeedModule::is_price_stale(1).0);

        crate::LastPriceUpdateAt::<Test>::put(10);
        assert!(!PriceFeedModule::is_price_stale(10).0);
        assert!(!PriceFeedModule::is_price_stale(11).0);
        assert!(!PriceFeedModule::is_price_stale(12).0);
        assert!(!PriceFeedModule::is_price_stale(14).0);

        assert!(PriceFeedModule::is_price_stale(15).0);

        // Note: More checks on weight could be done here
    })
}

#[test]
fn get_aggregator_address_from_proxy() {
    new_test_ext().execute_with(|| {
        let (aggregator, proxy) = setup_contracts();

        let (fetched_aggregator_address, _) = PriceFeedModule::get_aggregator_address_from_proxy(
            proxy,
            AGGREGATOR_QUERY_ABI.to_vec(),
        )
        .unwrap();

        assert_eq!(fetched_aggregator_address, aggregator);
    })
}

#[test]
fn get_price_from_contract() {
    new_test_ext().execute_with(|| {
        // Bytecodes used in this test are taken from Readme which contains the contract as well

        // Contract isn't deployed on EVM yet
        assert!(PriceFeedModule::get_price_from_contract().is_err());
        assert!(PriceFeedModule::price().is_none());

        let (contract_address, _) = setup_contracts();

        let (price, _) = PriceFeedModule::get_price_from_contract().unwrap();
        assert_eq!(price, 15);
        // Price is not updated in this pallet's storage
        assert!(PriceFeedModule::price().is_none());

        let evm_config = <Test as pallet_evm::Config>::config();

        // call `setData(11, 25, 1300, 1300, 10)`
        let set_call_1 = hex::decode("6444bd16000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000001900000000000000000000000000000000000000000000000000000000000005140000000000000000000000000000000000000000000000000000000000000514000000000000000000000000000000000000000000000000000000000000000a").unwrap();
        <Test as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_address,
            set_call_1,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            evm_config,
        ).unwrap();

        let (price, _) = PriceFeedModule::get_price_from_contract().unwrap();
        assert_eq!(price, 25);
        assert!(PriceFeedModule::price().is_none());

        // call `setData(12, 30, 1400, 1400, 11)`
        let set_call_2 = hex::decode("6444bd16000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000005780000000000000000000000000000000000000000000000000000000000000578000000000000000000000000000000000000000000000000000000000000000b").unwrap();
        <Test as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_address,
            set_call_2,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            evm_config,
        ).unwrap();

        let (price, _) = PriceFeedModule::get_price_from_contract().unwrap();
        assert_eq!(price, 30);
        assert!(PriceFeedModule::price().is_none());

        // call `setData(13, 40, 1410, 1400, 13)`
        let set_call_3 = hex::decode("6444bd16000000000000000000000000000000000000000000000000000000000000000d000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000005820000000000000000000000000000000000000000000000000000000000000578000000000000000000000000000000000000000000000000000000000000000d").unwrap();
        <Test as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_address,
            set_call_3,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            evm_config,
        ).unwrap();

        let (price, _) = PriceFeedModule::get_price_from_contract().unwrap();
        assert_eq!(price, 40);

        // Fetching from contract does not update the price storage of this pallet
        assert!(PriceFeedModule::price().is_none());
    })
}

#[test]
fn storage_price_update() {
    new_test_ext().execute_with(|| {
        // Contract isn't deployed on EVM yet
        assert!(PriceFeedModule::update_price_from_contract().is_err());
        assert!(PriceFeedModule::price().is_none());

        let (contract_address, _) = setup_contracts();

        PriceFeedModule::set_update_frequency(Origin::root(), 10).unwrap();
        System::set_block_number(10);

        // Update pallet's stored price from contract. This is the first run of the update price and `LastPriceUpdateAt` isn't set
        assert!(PriceFeedModule::last_price_update_at().is_none());
        PriceFeedModule::update_price_if_stale(10).unwrap();

        // Pallet's storage is updated
        assert_eq!(PriceFeedModule::price().unwrap(), 15);
        assert_eq!(PriceFeedModule::last_price_update_at().unwrap(), 10);

        System::set_block_number(14);

        let evm_config = <Test as pallet_evm::Config>::config();

        // call `setData(13, 40, 1410, 1400, 13)`
        let set_call = hex::decode("6444bd16000000000000000000000000000000000000000000000000000000000000000d000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000005820000000000000000000000000000000000000000000000000000000000000578000000000000000000000000000000000000000000000000000000000000000d").unwrap();
        <Test as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_address,
            set_call,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            evm_config,
        ).unwrap();

        // Price stored in this pallet unchanged when contract updated
        assert_eq!(PriceFeedModule::price().unwrap(), 15);

        // Price unchanged when it isn't stale
        PriceFeedModule::update_price_if_stale(14).unwrap();
        assert_eq!(PriceFeedModule::price().unwrap(), 15);

        System::set_block_number(21);

        // Price changed when its stale
        PriceFeedModule::update_price_if_stale(21).unwrap();
        assert_eq!(PriceFeedModule::price().unwrap(), 40);
    })
}

#[test]
fn decoding_emv_resp() {
    new_test_ext().execute_with(|| {
        let ret_params = [
            ParamType::Uint(80),
            ParamType::Int(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(80),
        ];
        let ret_value = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 96, 52, 215, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 52, 215, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,
        ];

        let price = PriceFeedModule::decode_evm_response_to_price(&ret_params, &ret_value).unwrap();
        assert_eq!(price, 34);

        let ret_value_1 = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 96, 52, 215, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 52, 215, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,
        ];
        assert_err!(
            PriceFeedModule::decode_evm_response_to_price(&ret_params, &ret_value_1),
            Error::<Test>::PriceIsZero
        );

        let ret_value_2 = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32,
        ];
        assert_err!(
            PriceFeedModule::decode_evm_response_to_price(&ret_params, &ret_value_2),
            Error::<Test>::ResponseParsingFailed
        );
    });
}

#[test]
fn price_provider_api() {
    new_test_ext().execute_with(|| {
        assert!(PriceFeedModule::optimized_get_dock_usd_price().is_none());

        let (contract_address, _) = setup_contracts();

        assert!(PriceFeedModule::optimized_get_dock_usd_price().is_none());

        PriceFeedModule::update_price_from_contract().unwrap();

        let (price_optmz, _) = PriceFeedModule::optimized_get_dock_usd_price().unwrap();
        let (price, _) = PriceFeedModule::get_dock_usd_price().unwrap();
        assert_eq!(PriceFeedModule::price().unwrap(), 15);
        assert_eq!(price_optmz, 15);
        assert_eq!(price, 15);

        // Update the price in contract
        let evm_config = <Test as pallet_evm::Config>::config();
        // call `setData(13, 40, 1410, 1400, 13)`
        let set_call = hex::decode("6444bd16000000000000000000000000000000000000000000000000000000000000000d000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000005820000000000000000000000000000000000000000000000000000000000000578000000000000000000000000000000000000000000000000000000000000000d").unwrap();
        <Test as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_address,
            set_call,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            evm_config,
        ).unwrap();

        let (price_optmz, _) = PriceFeedModule::optimized_get_dock_usd_price().unwrap();
        let (price, _) = PriceFeedModule::get_dock_usd_price().unwrap();
        assert_eq!(PriceFeedModule::price().unwrap(), 15);
        // Optimized get call still fetches the price from storage
        assert_eq!(price_optmz, 15);
        // Non-optimized get fetches from contract
        let (price_ctr, _) = PriceFeedModule::get_price_from_contract().unwrap();
        assert_eq!(price_ctr, 40);
        assert_eq!(price, 40);
    })
}
