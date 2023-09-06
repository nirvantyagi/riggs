use std::error::Error as ErrorTrait;

pub mod bigint;
pub mod hash_to_prime;
pub mod hog;
pub mod poe;

pub type Error = Box<dyn ErrorTrait>;
