#![allow(non_camel_case_types)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use num_bigint::BigInt;
use num_traits::{One, Zero};

use libc::c_char;
use std::{
    str::FromStr,
    ffi::CStr,
};

pub fn factor(n: &BigInt) -> Vec<(BigInt, u32)> {
    unsafe { pari_init(1000000, 0) };
    let gen = bn_to_gen(n);
    let factor_gen = unsafe { factorint(gen, 0) };
    parse_factor_output_gen(factor_gen)
}

fn bn_to_gen(bn: &BigInt) -> GEN {
    let neg1 = if bn < &BigInt::zero() { -1 } else { 1 };
    let neg_bn: BigInt = if bn < &BigInt::zero() {
        -BigInt::one()
    } else {
        BigInt::one()
    };
    let bn: BigInt = bn * &neg_bn;

    let bn_len = bn.bits() as usize;
    let num_int_bound: usize;
    if bn_len % 8 == 0 {
        num_int_bound = bn_len / 8;
    } else {
        num_int_bound = bn_len / 8 + 1;
    }
    let size_int = 32;
    let two_bn = BigInt::from(2);
    let all_ones_32bits = two_bn.pow(size_int as u32) - BigInt::one();
    let mut array = [0u8; 4];
    let ints_vec = (0..num_int_bound)
        .map(|i| {
            let masked_valued_bn = (&bn & &all_ones_32bits << (i * size_int)) >> (i * size_int);

            let mut masked_value_bytes = BigInt::to_bytes_be(&masked_valued_bn).1;
            // padding if int has leading zero bytes
            let mut template = vec![0; 4 - masked_value_bytes.len()];
            template.extend_from_slice(&masked_value_bytes);
            masked_value_bytes = template;

            array.copy_from_slice(&masked_value_bytes[..]);

            u32::from_be_bytes(array) as i64
        })
        .collect::<Vec<i64>>();

    let mut i = 0;
    let mut gen = unsafe { mkintn(1i64, 0i64) };
    unsafe {
        while i < num_int_bound {
            let elem1 = mkintn(1i64, ints_vec[num_int_bound - i - 1]);
            let elem2 = shifti(gen, (size_int) as i64);
            gen = gadd(elem1, elem2);
            i += 1
        }

        if neg1 == -1 {
            gen = gneg(gen);
        }
        gen
    }
}

fn gen_to_string(gen: GEN) -> String {
    let char_ptr: *const c_char = unsafe { GENtostr(gen) };
    let c_str: &CStr = unsafe { CStr::from_ptr(char_ptr) };
    c_str.to_str().unwrap().to_string()
}

fn parse_vec_gen(gen: GEN) -> Vec<String> {
    let vec_string = gen_to_string(gen);
    vec_string.trim_start_matches("[").trim_end_matches("]~").split(", ").map(|s| s.to_string()).collect()
}

fn parse_factor_output_gen(gen: GEN) -> Vec<(BigInt, u32)> {
    let factors_gen = unsafe { compo(gen, 1) };
    let multiplicities_gen = unsafe { compo(gen, 2) };
    parse_vec_gen(factors_gen).into_iter().map(|f| BigInt::from_str(&f).unwrap())
        .zip(parse_vec_gen(multiplicities_gen).into_iter().map(|n| u32::from_str(&n).unwrap()))
        .collect()
}

#[cfg(test)]
mod tests {
    use num_traits::Num;
    use super::*;

    #[test]
    fn bn_to_gen_to_bn_test() {
        unsafe {
            pari_init(1000000, 0);
        }
        let p = BigInt::from_str("1137386464826123894369328775958409418403355215727442139").unwrap();
        let gen = bn_to_gen(&p);
        let str = gen_to_string(gen);
        let p_recover = BigInt::from_str_radix(&str, 10).unwrap();

        println!("{}", p_recover.to_string());
        assert_eq!(p, p_recover);
    }

    #[test]
    fn factor_bn_test() {
        unsafe {
            pari_init(1000000, 0);
        }
        let p = BigInt::from_str("1137386464826123894369328775958409418403355215727442139").unwrap();
        let factors = factor(&(&p - BigInt::one()));
        let expected_factors = vec![
            (BigInt::from(2), 1),
            (BigInt::from(7), 2),
            (BigInt::from(11), 1),
            (BigInt::from_str("3839724103").unwrap(), 1),
            (BigInt::from_str("2605867251918143").unwrap(), 1),
            (BigInt::from_str("105447669733200262947593999").unwrap(), 1)
        ];
        println!("{:?}", factors);
        assert_eq!(factors, expected_factors);

        let composite = factors.into_iter().map(|(f, n)| f.pow(n)).product();
        assert_eq!(p - BigInt::one(), composite);
    }
}
