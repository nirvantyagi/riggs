use ark_ec::{ProjectiveCurve, PairingEngine};
use ark_bn254::{
    Bn254,
    G1Projective as G,
};

use rand::{rngs::StdRng, SeedableRng};
use ethabi::Token;
use primitive_types::{U256};

use solidity_test_utils::{contract::Contract, evm::Evm, address::Address, parse_g1_to_solidity_string, to_be_bytes, parse_g1, parse_field};

use rsa::{
    bigint::BigInt,
    poe::hash_to_prime::hash_to_variable_output_length,
};
use range_proofs::bulletproofs::{
    Bulletproofs, Proof, Params, PedersenComm, PedersenParams,
    serialize_group_elem,
};

use std::{fs::File, io::Read};

fn encode_group_element<E: PairingEngine>(g: &E::G1Projective) -> Token {
    let (x, y) = parse_g1::<E>(&g.into_affine());
    Token::Tuple(vec![Token::Uint(U256::from_big_endian(&x)), Token::Uint(U256::from_big_endian(&y))])
}

fn encode_field_element<E: PairingEngine>(f: &E::Fr) -> Token {
    Token::Uint(U256::from_big_endian(&parse_field::<E>(f)))
}

fn encode_proof<E: PairingEngine>(proof: &Proof<E::G1Projective>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&proof.comm_bits));
    tokens.push(encode_group_element::<E>(&proof.comm_blind));
    tokens.push(encode_group_element::<E>(&proof.comm_lc1));
    tokens.push(encode_group_element::<E>(&proof.comm_lc2));
    tokens.push(encode_field_element::<E>(&proof.t_x));
    tokens.push(encode_field_element::<E>(&proof.r_t_x));
    tokens.push(encode_field_element::<E>(&proof.r_ab));
    tokens.push(Token::Array(proof.comm_ipa.iter().map(|(cl, _)| encode_group_element::<E>(cl)).collect::<Vec<_>>()));
    tokens.push(Token::Array(proof.comm_ipa.iter().map(|(_, cr)| encode_group_element::<E>(cr)).collect::<Vec<_>>()));
    tokens.push(encode_field_element::<E>(&proof.base_a));
    tokens.push(encode_field_element::<E>(&proof.base_b));
    Token::Tuple(tokens)
}

//fn encode_params<E: PairingEngine>(pp_hash: &[u8], ped_pp: &PedersenParams<E::G1Projective>, pp: &Params<E::G1Projective>) -> Token {
//    let mut tokens = Vec::new();
//    tokens.push(Token::FixedBytes(pp_hash.to_vec()));
//    tokens.push(encode_group_element::<E>(&ped_pp.g));
//    tokens.push(encode_group_element::<E>(&ped_pp.h));
//    tokens.push(Token::Array(pp.g.iter().map(|g| encode_group_element::<E>(g)).collect::<Vec<_>>()));
//    tokens.push(Token::Array(pp.h.iter().map(|h| encode_group_element::<E>(h)).collect::<Vec<_>>()));
//    tokens.push(encode_group_element::<E>(&pp.u));
//    Token::Tuple(tokens)
//}

const NUM_BITS: u64 = 32;
const LOG_NUM_BITS: u64 = 5;

fn main() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
    let pp = Bulletproofs::<G, sha3::Keccak256>::gen_params(&mut rng, NUM_BITS);

    let pp_hash = {
        let mut hash_input = Vec::<u8>::new();
        hash_input.append(&mut serialize_group_elem(&ped_pp.g));
        hash_input.append(&mut serialize_group_elem(&ped_pp.h));
        for g in pp.g.iter() {
            hash_input.append(&mut serialize_group_elem(g));
        }
        for h in pp.h.iter() {
            hash_input.append(&mut serialize_group_elem(h));
        }
        hash_input.append(&mut serialize_group_elem(&pp.u));
        hash_to_variable_output_length::<sha3::Keccak256>(&hash_input, 32)
    };


    let v = BigInt::from(1000);
    let (comm, opening) =
        PedersenComm::<G>::commit(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();
    let proof = Bulletproofs::<G, sha3::Keccak256>::prove_range(
        &mut rng, &pp, &ped_pp, &comm, &v, &opening, NUM_BITS,
    )
        .unwrap();
    assert!(Bulletproofs::<G, sha3::Keccak256>::verify_range(&pp, &ped_pp, &comm, NUM_BITS, &proof).unwrap());

    // Compile contract from template
    let contract_path = format!(
        "{}/contracts/BulletproofsVerifier.sol",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"");

    let src = src
        .replace("<%pp_hash%>", &format!("0x{}", hex::encode(&pp_hash)))
        .replace("<%ped_pp_g%>", &parse_g1_to_solidity_string::<Bn254>(&ped_pp.g.into_affine()))
        .replace("<%ped_pp_h%>", &parse_g1_to_solidity_string::<Bn254>(&ped_pp.h.into_affine()))
        .replace("<%ipa_pp_u%>", &parse_g1_to_solidity_string::<Bn254>(&pp.u.into_affine()))
        .replace("<%ipa_pp_len%>", &NUM_BITS.to_string())
        .replace("<%ipa_log_len%>", &LOG_NUM_BITS.to_string())
        .replace("<%ipa_pp_vecs%>", &{
            let mut populate_ipa_pp_vec = String::new();
            for (i, (g, h)) in pp.g.iter().zip(pp.h.iter()).enumerate() {
                populate_ipa_pp_vec.push_str(&format!("pp.ipaG[{}] = BN254.G1Point({});", i, &parse_g1_to_solidity_string::<Bn254>(&g.into_affine())));
                populate_ipa_pp_vec.push_str("\n        ");
                populate_ipa_pp_vec.push_str(&format!("pp.ipaH[{}] = BN254.G1Point({});", i, &parse_g1_to_solidity_string::<Bn254>(&h.into_affine())));
                if i < pp.g.len() - 1 {
                    populate_ipa_pp_vec.push_str("\n        ");
                }
            }
            populate_ipa_pp_vec
        });


    //println!("{}", src);
    let contract = Contract::compile_from_src_string(&src, "BulletproofsVerifier", true).unwrap();

    // Setup EVM
    let mut evm = Evm::new();
    let deployer = Address::random(&mut rng);
    evm.create_account(&deployer, 0);

    // Deploy contract
    let create_result = evm.deploy(contract.encode_create_contract_bytes(&[]).unwrap(), &deployer).unwrap();
    let contract_addr = create_result.addr.clone();
    println!("Contract deploy gas cost: {}", create_result.gas);

    // Call verify function on contract
    let input = vec![
        encode_group_element::<Bn254>(&comm),
        encode_proof::<Bn254>(&proof)
    ];
    let result = evm.call(contract.encode_call_contract_bytes("verify", &input).unwrap(), &contract_addr, &deployer).unwrap();
    //assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    println!("{:?}", result);




}