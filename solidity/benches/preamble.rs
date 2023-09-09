use ark_bn254::{Bn254, G1Projective as G};

use ark_ec::ProjectiveCurve;
use ark_ff::{biginteger::BigInteger, PrimeField};
use ethabi::Token;
use num_integer::Integer;
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};
use sha3::Keccak256;

use num_bigint::Sign;
use std::{
    ops::Deref,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use auction_house::{
    auction::AuctionParams,
    house::{AccountPrivateState, AuctionHouse, HouseAuctionParams, HouseParams},
};
use range_proofs::bulletproofs::{Bulletproofs, Params as BulletproofsParams};
use rsa::{
    bigint::{nat_to_f, BigInt},
    hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::PoEParams,
};
use solidity::{
    encode_bulletproof, encode_new_auction, encode_tc_comm, encode_tc_opening, encode_tc_partial,
    get_bigint_library_src, get_bn254_deploy_src, get_bn254_library_src,
    get_bulletproofs_verifier_contract_src, get_filename_src, get_fkps_src,
    get_pedersen_deploy_src, get_pedersen_library_src, get_rsa_library_src,
};
use solidity_test_utils::{
    address::Address, contract::Contract, encode_field_element, evm::Evm, to_be_bytes,
};
use timed_commitments::{basic_tc::TimeParams, lazy_tc::LazyTC, PedersenComm, PedersenParams};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRsaParams;
impl RsaGroupParams for TestRsaParams {
    const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
    const M: Lazy<BigInt> = Lazy::new(|| {
        BigInt::from_str("220221485961027482895807132690296630677486844071857248828102639779900826037\
                          522817575171387188561253238223028895754955597267595588137098207226627715313\
                          686049237996261509248457831215460282155642105163463527516323185300916088248\
                          789771290659167975569920900762065967420098972398211591577160443790408101308\
                          817972103247443575027202837913668619892210165571903754903981604693359583977\
                          802099079979976465322630291407337945531372576140316723612803378607350692963\
                          974127646284411621516308667435495842780676101093520710501949914086065977327\
                          554104291784758074296814223591834286965337274202669433267036319135962442072\
                          33293683841131181").unwrap()
    });
}

pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;

pub const MOD_BITS: usize = 2048;
pub const TIME_PARAM: u64 = 100; 
pub const NUM_BID_BITS: u64 = 32;
pub const LOG_NUM_BID_BITS: u64 = 5;

pub const REWARD_SELF_OPEN: u32 = 5;
pub const REWARD_FORCE_OPEN: u32 = 5;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPoEParams;

impl PoEParams for TestPoEParams {
    const HASH_TO_PRIME_ENTROPY: usize = 256;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPocklingtonParams;
impl PocklingtonCertParams for TestPocklingtonParams {
    const NONCE_SIZE: usize = 16;
    const MAX_STEPS: usize = 5;
    const INCLUDE_SOLIDITY_WITNESSES: bool = true;
}

pub type TC = LazyTC<
    G,
    TestPoEParams,
    TestRsaParams,
    Keccak256,
    PocklingtonHash<TestPocklingtonParams, Keccak256>,
>;

pub type Account = AccountPrivateState<
    G,
    TestPoEParams,
    TestRsaParams,
    Keccak256,
    PocklingtonHash<TestPocklingtonParams, Keccak256>,
>;

pub type TestAuctionHouse = AuctionHouse<
    G,
    TestPoEParams,
    TestRsaParams,
    Keccak256,
    PocklingtonHash<TestPocklingtonParams, Keccak256>,
>;

pub fn deploy_bulletproofs(
    evm: &mut Evm,
    deployer: &Address,
    ped_pp: &PedersenParams<G>,
    bulletproofs_pp: &BulletproofsParams<G>,
) -> (Contract, Address) {
    let bn254_src = get_bn254_library_src();
    let pedersen_lib_src = get_pedersen_library_src(ped_pp, false);
    let bulletproofs_src = get_bulletproofs_verifier_contract_src(
        bulletproofs_pp,
        ped_pp,
        NUM_BID_BITS,
        LOG_NUM_BID_BITS,
        false,
    );

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" }
                },
                "settings": {
                    "optimizer": { "enabled": <%opt%> },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object", "abi"
                            ],
                        "": [ "*" ] } }
                }
            }"#
    .replace("<%opt%>", &true.to_string())
    .replace("<%bn254_src%>", &bn254_src)
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%src%>", &bulletproofs_src);

    let bulletproofs_contract =
        Contract::compile_from_config(&solc_config, "BulletproofsVerifier").unwrap();
    let create_result = evm
        .deploy(
            bulletproofs_contract
                .encode_create_contract_bytes(&[])
                .unwrap(),
            &deployer,
        )
        .unwrap();
    let contract_addr = create_result.addr.clone();
    // println!(
    //   "Bulletproofs contract deployed at address: {:?}",
    //   contract_addr
    // );
    (bulletproofs_contract, contract_addr)
}

pub fn deploy_tc(
    evm: &mut Evm,
    deployer: &Address,
    ped_pp: &PedersenParams<G>,
    time_pp: &TimeParams<TestRsaParams>,
) -> (Contract, Address) {
    let bn254_src = get_bn254_library_src();
    let bigint_src = get_bigint_library_src();
    let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
    let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
    let poe_src = get_filename_src("PoEVerifier.sol", false);
    let fkps_src = get_fkps_src(&time_pp.x.n, &time_pp.y.n, MOD_BITS, TIME_PARAM, false);
    let tc_src = get_filename_src("TC.sol", false);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
                    "PoEVerifier.sol": { "content": "<%poe_lib_src%>" },
                    "FKPS.sol": { "content": "<%fkps_lib_src%>" }
                },
                "settings": {
                    "optimizer": { "enabled": <%opt%> },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object", "abi"
                            ],
                        "": [ "*" ] } }
                }
            }"#
    .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
    .replace("<%bn254_src%>", &bn254_src)
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%bigint_src%>", &bigint_src)
    .replace("<%rsa_lib_src%>", &rsa_src)
    .replace("<%poe_lib_src%>", &poe_src)
    .replace("<%fkps_lib_src%>", &fkps_src)
    .replace("<%src%>", &tc_src);

    let contract = Contract::compile_from_config(&solc_config, "TC").unwrap();
    let create_result = evm
        .deploy(
            contract.encode_create_contract_bytes(&[]).unwrap(),
            &deployer,
        )
        .unwrap();
    let contract_addr = create_result.addr.clone();

    (contract, contract_addr)
}

pub fn deploy_erc721(evm: &mut Evm, deployer: &Address) -> (Contract, Address) {
    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "IERC721.sol": { "content": "<%erc721_src%>" }
                },
                "settings": {
                    "optimizer": { "enabled": <%opt%> },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object", "abi"
                            ],
                        "": [ "*" ] } }
                }
            }"#
    .replace("<%opt%>", &true.to_string())
    .replace("<%erc721_src%>", &get_filename_src("IERC721.sol", false))
    .replace("<%src%>", &get_filename_src("TestERC721.sol", true));

    let erc721_contract = Contract::compile_from_config(&solc_config, "TestERC721").unwrap();

    // Deploy ERC-721 contract
    let create_result = evm
        .deploy(
            erc721_contract
                .encode_create_contract_bytes(&[
                    Token::String("TestERC721".to_string()),
                    Token::String("NFT".to_string()),
                ])
                .unwrap(),
            &deployer,
        )
        .unwrap();
    let erc721_contract_addr = create_result.addr.clone();

    (erc721_contract, erc721_contract_addr)
}


pub fn deploy_ah_coin(
    evm: &mut Evm,
    deployer: &Address,
) -> Contract {
    let auction_house_coin_src = get_filename_src("AuctionHouseCoin.sol", true);
    let erc20_src = get_filename_src("IERC20.sol", false);
    let erc721_src = get_filename_src("IERC721.sol", false);

    let solc_config = r#"
          {
              "language": "Solidity",
              "sources": {
                  "input.sol": { "content": "<%src%>" },
                  "IERC20.sol": { "content": "<%erc20_src%>" },
                  "IERC721.sol": { "content": "<%erc721_src%>" }
              },
              "settings": {
                  "optimizer": { "enabled": <%opt%> },
                  "outputSelection": {
                      "*": {
                          "*": [
                              "evm.bytecode.object", "abi"
                          ],
                      "": [ "*" ] } }
              }
          }"#
    .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
    .replace("<%erc20_src%>", &erc20_src)
    .replace("<%erc721_src%>", &erc721_src)
    .replace("<%src%>", &auction_house_coin_src);

    let contract = Contract::compile_from_config(&solc_config, "AuctionHouseCoin").unwrap();
    // let create_result = evm
    //   .deploy(
    //     contract.encode_create_contract_bytes(&[]).unwrap(),
    //     &deployer,
    //   )
    //   .unwrap();
    // let contract_addr = create_result.addr.clone();
    // println!("AH Coin contract deployed at address: {:?}", contract_addr);
    contract
}


// pub fn deploy_ah_coin(
//     evm: &mut Evm,
//     deployer: &Address,
//     ped_pp: &PedersenParams<G>,
//     bulletproofs_pp: &BulletproofsParams<G>,
//     bulletproofs_contract_addr: &Address,
// ) -> Contract {
//     let auction_house_coin_src = get_filename_src("AuctionHouseCoin.sol", true);
//     let bn254_src = get_bn254_library_src();
//     let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
//     let bulletproofs_src = get_bulletproofs_verifier_contract_src(
//         &bulletproofs_pp,
//         &ped_pp,
//         NUM_BID_BITS,
//         LOG_NUM_BID_BITS,
//         false,
//     );
//     let erc20_src = get_filename_src("IERC20.sol", false);
//     let erc721_src = get_filename_src("IERC721.sol", false);

//     let solc_config = r#"
//           {
//               "language": "Solidity",
//               "sources": {
//                   "input.sol": { "content": "<%src%>" },
//                   "BN254.sol": { "content": "<%bn254_src%>" },
//                   "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
//                   "BulletproofsVerifier.sol": { "content": "<%bulletproofs_lib_src%>" },
//                   "IERC20.sol": { "content": "<%erc20_src%>" },
//                   "IERC721.sol": { "content": "<%erc721_src%>" }
//               },
//               "settings": {
//                   "optimizer": { "enabled": <%opt%> },
//                   "outputSelection": {
//                       "*": {
//                           "*": [
//                               "evm.bytecode.object", "abi"
//                           ],
//                       "": [ "*" ] } },
//                   "libraries": {
//                       "BulletproofsVerifier.sol": {
//                           "BulletproofsVerifier": "<%bulletproofs_lib_addr%>"
//                       }
//                   }
//               }
//           }"#
//     .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
//     .replace("<%bn254_src%>", &bn254_src)
//     .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
//     .replace("<%bulletproofs_lib_src%>", &bulletproofs_src)
//     .replace(
//         "<%bulletproofs_lib_addr%>",
//         &bulletproofs_contract_addr.to_string(),
//     )
//     .replace("<%erc20_src%>", &erc20_src)
//     .replace("<%erc721_src%>", &erc721_src)
//     .replace("<%src%>", &auction_house_coin_src);

//     let contract = Contract::compile_from_config(&solc_config, "AuctionHouseCoin").unwrap();
//     // let create_result = evm
//     //   .deploy(
//     //     contract.encode_create_contract_bytes(&[]).unwrap(),
//     //     &deployer,
//     //   )
//     //   .unwrap();
//     // let contract_addr = create_result.addr.clone();
//     // println!("AH Coin contract deployed at address: {:?}", contract_addr);
//     contract
// }

pub fn deploy_ahc_factory(
    evm: &mut Evm,
    deployer: &Address,
    // ped_pp: &PedersenParams<G>,
    // bulletproofs_pp: &BulletproofsParams<G>,
    // bulletproofs_contract_addr: &Address,
) -> (Contract, Address) {
    let ahc_factory_src = get_filename_src("AuctionHouseCoinFactory.sol", true);
    // let bn254_src = get_bn254_library_src();
    // let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
    // let bulletproofs_src = get_bulletproofs_verifier_contract_src(
    //     &bulletproofs_pp,
    //     &ped_pp,
    //     NUM_BID_BITS,
    //     LOG_NUM_BID_BITS,
    //     false,
    // );
    let erc20_src = get_filename_src("IERC20.sol", false);
    let erc721_src = get_filename_src("IERC721.sol", false);
    let ah_coin_src = get_filename_src("AuctionHouseCoin.sol", false);

    // let solc_config = r#"
    //         {
    //             "language": "Solidity",
    //             "sources": {
    //                 "input.sol": { "content": "<%src%>" },
    //                 "BN254.sol": { "content": "<%bn254_src%>" },
    //                 "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
    //                 "BulletproofsVerifier.sol": { "content": "<%bulletproofs_lib_src%>" },
    //                 "IERC20.sol": { "content": "<%erc20_src%>" },
    //                 "IERC721.sol": { "content": "<%erc721_src%>" },
    //                 "AuctionHouseCoin.sol": { "content": "<%ah_coin_src%>" }

    //             },
    //             "settings": {
    //                 "optimizer": { "enabled": <%opt%> },
    //                 "outputSelection": {
    //                     "*": {
    //                         "*": [
    //                             "evm.bytecode.object", "abi"
    //                         ],
    //                     "": [ "*" ] } },
    //                 "libraries": {
    //                     "BulletproofsVerifier.sol": {
    //                         "BulletproofsVerifier": "<%bulletproofs_lib_addr%>"
    //                     }
    //                 }
    //             }
    //         }"#
    let solc_config = r#"
    {
        "language": "Solidity",
        "sources": {
            "input.sol": { "content": "<%src%>" },
            "IERC20.sol": { "content": "<%erc20_src%>" },
            "IERC721.sol": { "content": "<%erc721_src%>" },
            "AuctionHouseCoin.sol": { "content": "<%ah_coin_src%>" }

        },
        "settings": {
            "optimizer": { "enabled": <%opt%> },
            "outputSelection": {
                "*": {
                    "*": [
                        "evm.bytecode.object", "abi"
                    ],
                "": [ "*" ] } }
        }
    }"#
    .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
    // .replace("<%bn254_src%>", &bn254_src)
    // .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    // .replace("<%bulletproofs_lib_src%>", &bulletproofs_src)
    // .replace(
    //     "<%bulletproofs_lib_addr%>",
    //     &bulletproofs_contract_addr.to_string(),
    // )
    .replace("<%erc20_src%>", &erc20_src)
    .replace("<%erc721_src%>", &erc721_src)
    .replace("<%ah_coin_src%>", &ah_coin_src)
    .replace("<%src%>", &ahc_factory_src);

    let contract = Contract::compile_from_config(&solc_config, "AuctionHouseCoinFactory").unwrap();
    let create_result = evm
        .deploy(
            contract.encode_create_contract_bytes(&[]).unwrap(),
            &deployer,
        )
        .unwrap();
    let contract_addr = create_result.addr.clone();
    // println!(
    //   "AHC Factory contract deployed at address: {:?}",
    //   contract_addr
    // );
    (contract, contract_addr)
}

pub fn deploy_ah(
    evm: &mut Evm,
    deployer: &Address,
    ped_pp: &PedersenParams<G>,
    time_pp: &TimeParams<TestRsaParams>,
    bulletproofs_pp: &BulletproofsParams<G>,
    bulletproofs_contract_addr: &Address,
    tc_contract_addr: &Address,
    ahc_factory_contract_addr: &Address,
) -> Contract {
    // Compile auction house contract from template
    // println!("Compiling auction house contract...");
    let auction_house_src = get_filename_src("AuctionHouse.sol", true);
    let bn254_src = get_bn254_library_src();
    let bigint_src = get_bigint_library_src();
    let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
    let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
    let poe_src = get_filename_src("PoEVerifier.sol", false);
    let fkps_src = get_fkps_src(&time_pp.x.n, &time_pp.y.n, MOD_BITS, TIME_PARAM, false);
    let tc_src = get_filename_src("TC.sol", false);
    let bulletproofs_src = get_bulletproofs_verifier_contract_src(
        &bulletproofs_pp,
        &ped_pp,
        NUM_BID_BITS,
        LOG_NUM_BID_BITS,
        false,
    );
    let erc20_src = get_filename_src("IERC20.sol", false);
    let erc721_src = get_filename_src("IERC721.sol", false);
    let ahc_factory_src = get_filename_src("AuctionHouseCoinFactory.sol", false);
    let ah_coin_src = get_filename_src("AuctionHouseCoin.sol", false);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
                    "PoEVerifier.sol": { "content": "<%poe_lib_src%>" },
                    "FKPS.sol": { "content": "<%fkps_lib_src%>" },
                    "TC.sol": { "content": "<%tc_lib_src%>" },
                    "BulletproofsVerifier.sol": { "content": "<%bulletproofs_lib_src%>" },
                    "IERC20.sol": { "content": "<%erc20_src%>" },
                    "IERC721.sol": { "content": "<%erc721_src%>" },
                    "AuctionHouseCoinFactory.sol": { "content": "<%ahc_factory_src%>" },
                    "AuctionHouseCoin.sol": { "content": "<%ah_coin_src%>" }
                },
                "settings": {
                    "optimizer": { "enabled": <%opt%> },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object", "abi"
                            ],
                        "": [ "*" ] } },
                    "libraries": {
                        "TC.sol": {
                            "TC": "<%tc_lib_addr%>"
                        },
                        "BulletproofsVerifier.sol": {
                            "BulletproofsVerifier": "<%bulletproofs_lib_addr%>"
                        }
                    }
                }
            }"#
    .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
    .replace("<%bn254_src%>", &bn254_src)
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%bigint_src%>", &bigint_src)
    .replace("<%rsa_lib_src%>", &rsa_src)
    .replace("<%poe_lib_src%>", &poe_src)
    .replace("<%fkps_lib_src%>", &fkps_src)
    .replace("<%tc_lib_src%>", &tc_src)
    .replace("<%tc_lib_addr%>", &tc_contract_addr.to_string())
    .replace("<%bulletproofs_lib_src%>", &bulletproofs_src)
    .replace(
        "<%bulletproofs_lib_addr%>",
        &bulletproofs_contract_addr.to_string(),
    )
    .replace("<%erc20_src%>", &erc20_src)
    .replace("<%erc721_src%>", &erc721_src)
    .replace("<%ahc_factory_src%>", &ahc_factory_src)
    .replace("<%ah_coin_src%>", &ah_coin_src)
    .replace("<%src%>", &auction_house_src);

    let contract = Contract::compile_from_config(&solc_config, "AuctionHouse").unwrap();

    // // Deploy auction house contract
    // let contract_constructor_input = vec![
    //     ahc_factory_contract_addr.as_token(),
    //     // Token::Uint(U256::from(20)),
    //     // Token::Uint(U256::from(10)),
    //     // Token::Uint(U256::from(REWARD_SELF_OPEN)),
    //     // Token::Uint(U256::from(REWARD_FORCE_OPEN)),
    // ];
    // let create_result = evm
    //     .deploy(
    //         contract
    //             .encode_create_contract_bytes(&contract_constructor_input)
    //             .unwrap(),
    //         &deployer,
    //     )
    //     .unwrap();
    // let contract_addr = create_result.addr.clone();
    contract
}

pub fn setup_bidders(
    evm: &mut Evm,
    n_bidders: usize,
    auction_house: &mut AuctionHouse<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >,
    house_pp: &HouseParams<G>,
    ah_coin_contract: &Contract,
    ah_coin_contract_addr: &Address,
) -> Vec<(
    AccountPrivateState<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >,
    Address,
)> {
    let mut rng = StdRng::seed_from_u64(1u64);
    let mut bidders = Vec::new();

    let big_balance = (n_bidders as u32) * 100;
    for i in 0..n_bidders {
        let bidder_addr = Address::random(&mut rng);
        evm.create_account(&bidder_addr, big_balance);

        let (uid, _) = auction_house.new_account(&house_pp);
        assert_eq!(uid, i as u32);
        auction_house
            .account_deposit(&house_pp, uid, big_balance)
            .unwrap();

        let _ = evm
            .call_payable(
                ah_coin_contract
                    .encode_call_contract_bytes("exchangeAHCFromEther", &[])
                    .unwrap(),
                &ah_coin_contract_addr,
                &bidder_addr,
                U256::from(big_balance),
            )
            .unwrap();
        // println!("Bidder {} exchanged ether for AHC: gas: {}", i, result.gas);

        let _ = evm
            .call(
                ah_coin_contract
                    .encode_call_contract_bytes(
                        "approve",
                        &[
                            ah_coin_contract_addr.as_token(),
                            Token::Uint(U256::from(big_balance)),
                        ],
                    )
                    .unwrap(),
                &ah_coin_contract_addr,
                &bidder_addr,
            )
            .unwrap();
        // println!(
        //   "Bidder {} approved auction house to transfer AHC: gas: {}",
        //   i, result.gas
        // );

        let _ = evm
            .call(
                ah_coin_contract
                    .encode_call_contract_bytes("deposit", &[Token::Uint(U256::from(big_balance))])
                    .unwrap(),
                &ah_coin_contract_addr,
                &bidder_addr,
            )
            .unwrap();
        // println!(
        //   "Bidder {} deposited AHC into auction house balance: gas: {}",
        //   i, result.gas
        // );

        let mut bidder = Account::new();
        bidder.confirm_deposit(house_pp, big_balance).unwrap();

        bidders.push((bidder, bidder_addr));
    }
    bidders
}

pub fn collect_bids(
    evm: &mut Evm,
    bidders: &mut Vec<(
        AccountPrivateState<
            G,
            TestPoEParams,
            TestRsaParams,
            Keccak256,
            PocklingtonHash<TestPocklingtonParams, Keccak256>,
        >,
        Address,
    )>,
    house_pp: &HouseParams<G>,
    auction_pp: &HouseAuctionParams<G, TestRsaParams>,
    auction_house: &mut AuctionHouse<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >,
    ah_contract: &Contract,
    ah_contract_addr: &Address,
) -> (u64, Vec<u64>, Vec<u64>) {
    let mut place_bid_gas: u64 = 0;
    let mut place_bid_client_vec: Vec<u64> = Vec::new();
    let mut place_bid_server_vec: Vec<u64> = Vec::new();

    let mut rng = StdRng::seed_from_u64(1u64);
    for i in 0..bidders.len() {
        let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
        let mut start = Instant::now();
        let (bid_proposal, opening) = bidder
            .propose_bid(&mut rng, &house_pp, &auction_pp, (i as u32 + 1) * 20)
            .unwrap();
        let mut end = start.elapsed().as_nanos();
        place_bid_client_vec.push(end as u64);

        let result = evm
            .call(
                ah_contract
                    .encode_call_contract_bytes(
                        "bidAuction",
                        &[
                            Token::Uint(U256::from(0)),
                            encode_tc_comm::<Bn254, _>(&bid_proposal.comm_bid),
                            encode_bulletproof::<Bn254>(&bid_proposal.range_proof_bid),
                            encode_bulletproof::<Bn254>(&bid_proposal.range_proof_balance),
                        ],
                    )
                    .unwrap(),
                &ah_contract_addr,
                &bidder_addr,
            )
            .unwrap();

        // println!("Bidder {} placed bid: gas: {}", i, result.gas);

        if i == 0 {
            place_bid_gas = result.gas;
        }

        bidder
            .confirm_bid(
                &house_pp,
                &auction_pp,
                0,
                (i as u32 + 1) * 20,
                &bid_proposal,
                &opening,
            )
            .unwrap();

        start = Instant::now();
        let bidret = auction_house
            .account_bid(&house_pp, &auction_pp, 0, i as u32, &bid_proposal)
            .unwrap();
        end = start.elapsed().as_nanos();
        place_bid_server_vec.push(end as u64);
    }

    (place_bid_gas, place_bid_client_vec, place_bid_server_vec)
}
