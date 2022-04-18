use ark_bn254::{Bn254, G1Projective as G};
use ark_ec::{PairingEngine, ProjectiveCurve};

use digest::Digest;
use ethabi::Token;
use num_traits::Signed;
use primitive_types::U256;
use sha3::digest;
use std::{
    fs::File, io::Read,
    str::FromStr,
};

use range_proofs::bulletproofs::{serialize_group_elem, Params, PedersenParams, Proof};
use rsa::{
    bigint::BigInt,
    hash_to_prime::{
        hash_to_variable_output_length,
        pocklington::{PocklingtonCert, PocklingtonCertParams, PocklingtonHash, StepCert},
    },
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::Proof as PoEProof,
};
use timed_commitments::{basic_tc, lazy_tc};
use solidity_test_utils::{
    encode_field_element, encode_group_element, encode_int_from_bytes,
    parse_g1_to_solidity_string,
};

use once_cell::sync::Lazy;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRsaParams;

impl RsaGroupParams for TestRsaParams {
    const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
    const M: Lazy<BigInt> = Lazy::new(|| {
        BigInt::from_str("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357").unwrap()
    });
}

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
    as_contract: bool,
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
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        .replace("<%pp_hash%>", &format!("0x{}", hex::encode(&pp_hash)))
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

pub fn get_fkps_src(h: &BigInt, z: &BigInt, m_len: usize, t: u32, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/FKPS.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        //.replace("<%pp_time%>", &format!("{}", t))
        .replace("<%pp_time%>", &format!("{}", t))
        .replace("<%pp_m_len%>", &format!("{}", m_len / 256))
        .replace("<%pp_h_populate%>", &{
            let mut populate_h = String::new();
            for (i, u256digit) in h.to_u64_digits().1.chunks(4).rev().enumerate() {
                populate_h.push_str(&format!(
                    "h_u256_digits[{}] = 0x{}{}{}{};",
                    i,
                    hex::encode(&u256digit[3].to_be_bytes()),
                    hex::encode(&u256digit[2].to_be_bytes()),
                    hex::encode(&u256digit[1].to_be_bytes()),
                    hex::encode(&u256digit[0].to_be_bytes()),
                ));
                if i < h.to_u64_digits().1.len() / 4 - 1 {
                    populate_h.push_str("\n        ");
                }
            }
            populate_h
        })
        .replace("<%pp_z_populate%>", &{
            let mut populate_z = String::new();
            for (i, u256digit) in z.to_u64_digits().1.chunks(4).rev().enumerate() {
                populate_z.push_str(&format!(
                    "z_u256_digits[{}] = 0x{}{}{}{};",
                    i,
                    hex::encode(&u256digit[3].to_be_bytes()),
                    hex::encode(&u256digit[2].to_be_bytes()),
                    hex::encode(&u256digit[1].to_be_bytes()),
                    hex::encode(&u256digit[0].to_be_bytes()),
                ));
                if i < h.to_u64_digits().1.len() / 4 - 1 {
                    populate_z.push_str("\n        ");
                }
            }
            populate_z
        });
    src
}

pub fn get_rsa_library_src(m: &BigInt, m_len: usize, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/RSA2048.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
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

pub fn get_pedersen_library_src(ped_pp: &PedersenParams<G>, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/Pedersen.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
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

pub fn get_filename_src(filename: &str, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/", env!("CARGO_MANIFEST_DIR"));
    let full_path: String = contract_path + filename;

    let mut src_file = File::open(full_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        );
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

pub fn encode_bigint(n: &BigInt) -> Token {
    Token::Tuple(vec![
        Token::Bytes(pad_to_32_byte_offset(n.to_bytes_be().1)),
        Token::Bool(n.is_negative()),
    ])
}

pub fn encode_rsa_element<P: RsaGroupParams>(elmt: &RsaHiddenOrderGroup<P>) -> Token {
    Token::Tuple(vec![encode_bigint(&elmt.n)])
}

pub fn encode_pocklington_step_certificate(cert: &StepCert) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_bigint(&cert.f));
    tokens.push(Token::Uint(U256::from(cert.n)));
    tokens.push(Token::Uint(U256::from(cert.n2)));
    tokens.push(encode_bigint(&cert.a));
    tokens.push(encode_bigint(&cert.bu));
    tokens.push(encode_bigint(&cert.bv));
    tokens.push(encode_bigint(&cert.v.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.s.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.expr_sqrt.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.p_less_one_div_f.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.p_less_one_div_two.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_f1.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_f2.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_two1.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_two2.as_ref().unwrap()));
    Token::Tuple(tokens)
}

pub fn encode_pocklington_certificate(cert: &PocklingtonCert) -> Token {
    let step_certs = Token::Array(
        cert.step_certificates
            .iter()
            .map(|c| encode_pocklington_step_certificate(c))
            .collect::<Vec<_>>(),
    );
    Token::Tuple(vec![step_certs, Token::Uint(U256::from(cert.nonce))])
}

pub fn encode_poe_proof<P: RsaGroupParams, HP: PocklingtonCertParams, D: Digest>(
    proof: &PoEProof<P, PocklingtonHash<HP, D>>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_element(&proof.q));
    tokens.push(encode_pocklington_certificate(&proof.cert));
    Token::Tuple(tokens)
}

// Commitments

pub fn encode_fkps_comm<P: RsaGroupParams>(comm: &basic_tc::Comm<P>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_element(&comm.x));
    tokens.push(Token::Bytes(comm.ct.clone().to_vec()));
    Token::Tuple(tokens)
}

pub fn encode_tc_comm<E: PairingEngine, P: RsaGroupParams>(
    comm: &lazy_tc::Comm<E::G1Projective, P>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&comm.ped_comm));
    tokens.push(encode_fkps_comm(&comm.tc_comm));
    Token::Tuple(tokens)
}

// Openings

pub fn encode_fkps_opening<P: RsaGroupParams, HP: PocklingtonCertParams, D: Digest>(
    opening: &basic_tc::Opening<P, PocklingtonHash<HP, D>>,
    m: &Option<Vec<u8>>,
) -> Token {
    let mut tokens = Vec::new();

    match &opening {
        basic_tc::Opening::SELF(alpha) => {
            tokens.push(encode_int_from_bytes(&alpha.to_bytes_be().1));
        }
        basic_tc::Opening::FORCE(y, poe_proof) => {
            tokens.push(encode_rsa_element(&y));
            tokens.push(encode_poe_proof::<P, HP, D>(poe_proof));
        }
    };
    if m.is_none() {
        tokens.push(Token::Bytes([].to_vec()));
    } else {
        tokens.push(Token::Bytes(m.as_ref().unwrap().to_vec()));
    }
    Token::Tuple(tokens)
}

pub fn encode_tc_opening<P: RsaGroupParams, HP: PocklingtonCertParams, D: Digest>(
    opening: &lazy_tc::Opening<G, P, PocklingtonHash<HP, D>>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_fkps_opening(
        &opening.tc_opening,
        &opening.tc_m,
        // &opening.tc_m.as_ref().get_or_insert(&[].to_vec()),
    ));
    Token::Tuple(tokens)
}

// Public Params

pub fn encode_ped_pp<E: PairingEngine>(ped_pp: &PedersenParams<E::G1Projective>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&ped_pp.g));
    tokens.push(encode_group_element::<E>(&ped_pp.h));
    Token::Tuple(tokens)
}

pub fn encode_rsa_pp<P: RsaGroupParams>(m: &BigInt) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_element::<P>(&RsaHiddenOrderGroup::from_nat(
        BigInt::from(2),
    )));
    tokens.push(encode_bigint(&m));
    Token::Tuple(tokens)
}

pub fn encode_fkps_pp<P: RsaGroupParams>(m: &BigInt, fkps_pp: &basic_tc::TimeParams<P>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_pp::<P>(&m)); // needed in solidity code
    tokens.push(encode_rsa_element(&fkps_pp.x));
    tokens.push(encode_rsa_element(&fkps_pp.y));
    tokens.push(Token::Uint(U256::from(fkps_pp.t)));
    Token::Tuple(tokens)
}

pub fn encode_tc_pp<E: PairingEngine, P: RsaGroupParams>(
    m: &BigInt,
    fkps_pp: &basic_tc::TimeParams<P>,
    ped_pp: &PedersenParams<E::G1Projective>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_ped_pp::<E>(&ped_pp));
    tokens.push(encode_fkps_pp(&m, &fkps_pp));
    Token::Tuple(tokens)
}

fn pad_to_32_byte_offset(mut bytes: Vec<u8>) -> Vec<u8> {
    let pad_len = 32 * ((bytes.len() - 1) / 32 + 1);
    bytes.reverse();
    bytes.resize(pad_len, 0);
    debug_assert_eq!(bytes.len() % 32, 0);
    bytes.reverse();
    bytes
}
