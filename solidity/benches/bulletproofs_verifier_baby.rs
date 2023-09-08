use ark_bn254::Bn254;
use ark_ec::short_weierstrass_jacobian::GroupProjective;
use ark_ed_on_bn254::{constraints::EdwardsVar as GV, EdwardsProjective as G};

use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};

use solidity_test_utils::{
    address::Address, contract::Contract, encode_group_element, encode_group_element_pc, evm::Evm,
    to_be_bytes,
};

use range_proofs::bulletproofs::{Bulletproofs, PedersenComm};
use rsa::bigint::BigInt;
use solidity::{
    encode_bulletproof, encode_bulletproof_2, get_bn254_library_src,
    get_bulletproofs_verifier_contract_src, get_bulletproofs_verifier_contract_src_2,
    get_filename_src, get_pedersen_library_src, get_pedersen_library_src2,
};

const NUM_BITS: u64 = 64;
const LOG_NUM_BITS: u64 = 6;

fn main() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
    let pp = Bulletproofs::<G, sha3::Keccak256>::gen_params(&mut rng, NUM_BITS);

    let v = BigInt::from(1000);
    let (comm, opening) = PedersenComm::<G>::commit(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();
    let proof = Bulletproofs::<G, sha3::Keccak256>::prove_range(
        &mut rng, &pp, &ped_pp, &comm, &v, &opening, NUM_BITS,
    )
    .unwrap();
    assert!(Bulletproofs::<G, sha3::Keccak256>::verify_range(
        &pp, &ped_pp, &comm, NUM_BITS, &proof
    )
    .unwrap());

    // Compile contract from template
    let babyjubjub_src = get_filename_src("BabyJubjub.sol", false);
    let pedersen_lib_src = get_pedersen_library_src2::<G>(&ped_pp, false);
    let bulletproofs_src =
        get_bulletproofs_verifier_contract_src_2(&pp, &ped_pp, NUM_BITS, LOG_NUM_BITS, true);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "PedersenBaby.sol": { "content": "<%pedersen_lib_src%>" },
                    "BabyJubjub.sol": { "content": "<%babyjubjub_src%>" }
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
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%babyjubjub_src%>", &babyjubjub_src)
    .replace("<%src%>", &bulletproofs_src);

    let contract = Contract::compile_from_config(&solc_config, "BulletproofsVerifier").unwrap();

    // Setup EVM
    let mut evm = Evm::new();
    let deployer = Address::random(&mut rng);
    evm.create_account(&deployer, 0);

    // Deploy contract
    let create_result = evm
        .deploy(
            contract.encode_create_contract_bytes(&[]).unwrap(),
            &deployer,
        )
        .unwrap();
    let contract_addr = create_result.addr.clone();
    println!("Contract deploy gas cost: {}", create_result.gas);

    // Call verify function on contract
    let input = vec![
        encode_group_element_pc::<G>(&comm),
        encode_bulletproof_2::<G>(&proof),
    ];
    let result = evm
        .call(
            contract
                .encode_call_contract_bytes("verify", &input)
                .unwrap(),
            &contract_addr,
            &deployer,
        )
        .unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    println!("{:?}", result);
}
