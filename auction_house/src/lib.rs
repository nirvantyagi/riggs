use std::{
    error::Error as ErrorTrait,
    fmt::{self, Debug},
};

pub mod auction;

pub type Error = Box<dyn ErrorTrait>;

#[derive(Debug)]
pub enum AuctionError {
    InvalidPhase,
    InvalidBid,
}

impl ErrorTrait for AuctionError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for AuctionError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            AuctionError::InvalidBid => format!("invalid bid"),
            AuctionError::InvalidPhase => format!("invalid phase"),
        };
        write!(f, "{}", msg)
    }
}
