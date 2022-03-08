use ark_bn254::{Bn254, G1Projective as G};
use ark_ec::{PairingEngine, ProjectiveCurve};

use ethabi::Token;
use range_proofs::bulletproofs::{serialize_group_elem, Params, PedersenParams, Proof};
use rsa::bigint::BigInt;
use rsa::hash_to_prime::hash_to_variable_output_length;
use solidity_test_utils::{
    encode_field_element, encode_group_element, parse_g1_to_solidity_string,
};
use std::{fs::File, io::Read};

pub fn get_bn254_library_src() -> String {
    let contract_path = format!("{}/contracts/BN254.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"");
    src
}

pub fn get_bulletproofs_verifier_contract_src(
    pp: &Params<G>,
    ped_pp: &PedersenParams<G>,
    n: u64,
    lg_n: u64,
) -> String {
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

    let contract_path = format!(
        "{}/contracts/BulletproofsVerifier.sol",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace("<%pp_hash%>", &format!("0x{}", hex::encode(&pp_hash)))
        .replace(
            "<%ped_pp_g%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.g.into_affine()),
        )
        .replace(
            "<%ped_pp_h%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.h.into_affine()),
        )
        .replace(
            "<%ipa_pp_u%>",
            &parse_g1_to_solidity_string::<Bn254>(&pp.u.into_affine()),
        )
        .replace("<%ipa_pp_len%>", &n.to_string())
        .replace("<%ipa_log_len%>", &lg_n.to_string())
        .replace(
            "<%ipa_final_check_len%>",
            &(2 * n + 2 * lg_n + 8).to_string(),
        )
        .replace("<%ipa_pp_vecs%>", &{
            let mut populate_ipa_pp_vec = String::new();
            for (i, (g, h)) in pp.g.iter().zip(pp.h.iter()).enumerate() {
                populate_ipa_pp_vec.push_str(&format!(
                    "pp.ipaG[{}] = BN254.G1Point({});",
                    i,
                    &parse_g1_to_solidity_string::<Bn254>(&g.into_affine())
                ));
                populate_ipa_pp_vec.push_str("\n        ");
                populate_ipa_pp_vec.push_str(&format!(
                    "pp.ipaH[{}] = BN254.G1Point({});",
                    i,
                    &parse_g1_to_solidity_string::<Bn254>(&h.into_affine())
                ));
                if i < pp.g.len() - 1 {
                    populate_ipa_pp_vec.push_str("\n        ");
                }
            }
            populate_ipa_pp_vec
        });
    src
}

pub fn get_bigint_library_src() -> String {
    let contract_path = format!("{}/contracts/BigInt.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"");
    src
}

pub fn get_rsa_library_src(m: &BigInt, m_len: usize) -> String {
    let contract_path = format!("{}/contracts/RSA2048.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace("<%pp_m_len%>", &format!("{}", m_len / 256))
        .replace("<%pp_m_populate%>", &{
            let mut populate_m = String::new();
            for (i, u256digit) in m.to_u64_digits().1.chunks(4).rev().enumerate() {
                populate_m.push_str(&format!(
                    "m_u256_digits[{}] = 0x{}{}{}{};",
                    i,
                    hex::encode(&u256digit[3].to_be_bytes()),
                    hex::encode(&u256digit[2].to_be_bytes()),
                    hex::encode(&u256digit[1].to_be_bytes()),
                    hex::encode(&u256digit[0].to_be_bytes()),
                ));
                if i < m.to_u64_digits().1.len() / 4 - 1 {
                    populate_m.push_str("\n        ");
                }
            }
            populate_m
        });
    src
}

pub fn get_poe_library_src() -> String {
    let contract_path = format!("{}/contracts/PoEVerifier.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"");
    src
}

// pub fn get_pedersen_library_src(ped_pp: &PedersenParams<G>) -> String {
//     let contract_path = format!(
//         "{}/contracts/Pedersen.sol",
//         env!("CARGO_MANIFEST_DIR")
//     );

//     let mut src_file = File::open(contract_path).unwrap();
//     let mut src = String::new();
//     src_file.read_to_string(&mut src).unwrap();
//     src = src.replace("\"", "\\\"")
//         .replace("<%ped_pp_g%>", &parse_g1_to_solidity_string::<Bn254>(&ped_pp.g.into_affine()))
//         .replace("<%ped_pp_h%>", &parse_g1_to_solidity_string::<Bn254>(&ped_pp.h.into_affine()));
//     src
// }

pub fn get_pedersen_test_src(ped_pp: &PedersenParams<G>) -> String {
    let contract_path = format!("{}/contracts/PedersenTest.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%ped_pp_g%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.g.into_affine()),
        )
        .replace(
            "<%ped_pp_h%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.h.into_affine()),
        );
    src
}

pub fn get_filename_src(filename: &str) -> String {
    let contract_path = format!("{}/contracts/", env!("CARGO_MANIFEST_DIR"));
    let full_path: String = contract_path + filename;

    let mut src_file = File::open(full_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"");
    src
}

pub fn encode_bulletproof<E: PairingEngine>(proof: &Proof<E::G1Projective>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&proof.comm_bits));
    tokens.push(encode_group_element::<E>(&proof.comm_blind));
    tokens.push(encode_group_element::<E>(&proof.comm_lc1));
    tokens.push(encode_group_element::<E>(&proof.comm_lc2));
    tokens.push(encode_field_element::<E>(&proof.t_x));
    tokens.push(encode_field_element::<E>(&proof.r_t_x));
    tokens.push(encode_field_element::<E>(&proof.r_ab));
    tokens.push(Token::Array(
        proof
            .comm_ipa
            .iter()
            .map(|(cl, _)| encode_group_element::<E>(cl))
            .collect::<Vec<_>>(),
    ));
    tokens.push(Token::Array(
        proof
            .comm_ipa
            .iter()
            .map(|(_, cr)| encode_group_element::<E>(cr))
            .collect::<Vec<_>>(),
    ));
    tokens.push(encode_field_element::<E>(&proof.base_a));
    tokens.push(encode_field_element::<E>(&proof.base_b));
    Token::Tuple(tokens)
}
