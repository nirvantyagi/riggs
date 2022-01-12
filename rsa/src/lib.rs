use std::error::Error as ErrorTrait;

pub mod bigint;
pub mod hog;
pub mod poe;

pub type Error = Box<dyn ErrorTrait>;