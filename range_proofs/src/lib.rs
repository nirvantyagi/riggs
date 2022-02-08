use std::error::Error as ErrorTrait;

pub mod bulletproofs;

pub type Error = Box<dyn ErrorTrait>;
