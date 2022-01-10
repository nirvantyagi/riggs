use num_bigint::{BigInt as NumBigInt};

use std::{
    borrow::Borrow,
    fmt::{self, Debug},
    error::Error as ErrorTrait,
};

use crate::Error;

//pub mod constraints;
pub type BigInt = NumBigInt;


#[derive(Debug)]
pub enum BigIntError {
    Conversion(usize, usize),
}

impl ErrorTrait for BigIntError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for BigIntError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            BigIntError::Conversion(n_limbs, limb_width) => format!("Integer does not fit in {} limbs of width {}", n_limbs, limb_width),
        };
        write!(f, "{}", msg)
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
