use std::{
    error::Error as ErrorTrait,
    fmt::{self, Debug},
};

pub mod auction;
pub mod baseline_auction;
pub mod baseline_house;
pub mod house;
pub mod rp_auction;
pub mod rp_house;
pub mod snark_auction;
pub mod snark_house;

pub type Error = Box<dyn ErrorTrait>;

#[derive(Debug)]
pub enum AuctionError {
    InvalidPhase,
    InvalidBid,
    InvalidID,
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
            AuctionError::InvalidID => format!("invalid id"),
        };
        write!(f, "{}", msg)
    }
}
