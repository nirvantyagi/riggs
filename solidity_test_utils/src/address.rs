use ethabi::token::Token;
use primitive_types::H160;
use rand::Rng;
use std::string::ToString;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address(pub H160);

impl Address {
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Self(H160(rng.gen()))
    }

    pub fn as_token(&self) -> Token {
        Token::Address(self.0)
    }
}

impl AsRef<H160> for Address {
    fn as_ref(&self) -> &H160 {
        &self.0
    }
}

impl From<H160> for Address {
    fn from(hash: H160) -> Self {
        Self(hash)
    }
}

impl Into<Token> for Address {
    fn into(self) -> Token {
        self.as_token()
    }
}

impl ToString for Address {
    fn to_string(&self) -> String {
        format!("{:?}", self.as_ref())
    }
}