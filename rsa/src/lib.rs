use std::error::Error as ErrorTrait;

pub mod bigint;
pub mod hog;

pub type Error = Box<dyn ErrorTrait>;