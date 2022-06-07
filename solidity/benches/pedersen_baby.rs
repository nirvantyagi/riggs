use ark_bn254::{Bn254};
use ark_ec::short_weierstrass_jacobian::GroupProjective;
use ark_ed_on_bn254::{constraints::EdwardsVar as GV, EdwardsProjective as G};

use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};

use solidity_test_utils::{
    address::Address, contract::Contract, encode_field_element, encode_group_element, 
    encode_group_element_pc, encode_field_element_pc, evm::Evm,
    to_be_bytes, 
};

// use range_proofs::bulletproofs::PedersenComm;
use timed_commitments::{PedersenComm, PedersenParams};
use rsa::bigint::BigInt;
use solidity::{encode_ped_pp_pc, encode_ped_pp, get_bn254_library_src, get_pedersen_library_src, get_pedersen_library_src2, get_filename_src};

fn main() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);

    let v = BigInt::from(10000);
    let (comm, v_f, opening) =
        PedersenComm::<G>::commit2(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();

    assert!(PedersenComm::<G>::ver_open(&ped_pp, &comm, &v.to_bytes_le().1, &opening).unwrap());


    println!("{}", &ped_pp.g.x);
    println!("{}", &ped_pp.g.y);
    println!("{}", &ped_pp.h.x);
    println!("{}", &ped_pp.h.y);


    // Compile contract from template
    // let bn254_src = get_bn254_library_src();
    let babyjubjub_src = get_filename_src("BabyJubjub.sol", false);
    let pedersen_src = get_pedersen_library_src2::<G>(&ped_pp, true);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
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
    .replace("<%babyjubjub_src%>", &babyjubjub_src)
    .replace("<%src%>", &pedersen_src);
    //.replace("<%src%>", &pedersen_test_src);

    let contract = Contract::compile_from_config(&solc_config, "PedersenBaby").unwrap();

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
        encode_field_element_pc::<G>(&v_f),
        encode_field_element_pc::<G>(&opening),
        encode_ped_pp_pc::<G>(&ped_pp),
    ];

    println!("HELLO\n");
    
    let result = evm
        .call(
            contract
                .encode_call_contract_bytes("verify", &input)
                .unwrap(),
            &contract_addr,
            &deployer,
        )
        .unwrap();

    println!("Pedersen BabyJubjub verification cost {:?} gas", result.gas);
    assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
}