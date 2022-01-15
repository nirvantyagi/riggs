use std::error::Error as ErrorTrait;

pub mod lazy_tc;

pub type Error = Box<dyn ErrorTrait>;
