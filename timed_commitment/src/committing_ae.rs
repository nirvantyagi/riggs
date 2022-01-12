use crate::Error;
use aes_gcm::{AeadInPlace, Aes128Gcm, NewAead, Nonce};
use rand::{CryptoRng, Rng};
use std::{
    error::Error as ErrorTrait,
    fmt::{self, Debug},
};

pub struct KeyCommittingAE;

impl KeyCommittingAE {
    pub fn encrypt<R: CryptoRng + Rng>(
        rng: &mut R,
        key: &[u8],
        ad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let ae = Aes128Gcm::new_from_slice(key)
            .or(Err(Box::new(KeyCommittingAEError::InvalidKeyFormat)))?;
        let mut nonce = [0u8; 12]; // 96-bit nonce
        rng.fill(&mut nonce);

        // Build up plaintext to encrypt in place
        let mut ct = Vec::new();
        // Prepend 128-bit zero block for key committing
        // - https://eprint.iacr.org/2020/1491.pdf
        // - https://www.usenix.org/system/files/sec22summer_albertini.pdf
        ct.extend_from_slice(&[0u8; 16]);
        ct.extend_from_slice(pt);
        ae.encrypt_in_place(&nonce.into(), ad, &mut ct)
            .map_err(|_| Box::new(KeyCommittingAEError::EncryptionFailed))?;

        // Append nonce to end
        ct.extend_from_slice(&nonce);
        Ok(ct)
    }

    // TODO: Fix timing side channel of decryption error
    pub fn decrypt(key: &[u8], ad: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
        let ae = Aes128Gcm::new_from_slice(key)
            .or(Err(Box::new(KeyCommittingAEError::InvalidKeyFormat)))?;
        let mut pt_zero_preprend = ct.to_vec();
        // Parse nonce from end
        let nonce = pt_zero_preprend.split_off(pt_zero_preprend.len() - 12);
        ae.decrypt_in_place(Nonce::from_slice(&nonce), ad, &mut pt_zero_preprend)
            .map_err(|_| Box::new(KeyCommittingAEError::DecryptionFailed))?;

        // Verify key-committing 0-block
        let pt = pt_zero_preprend.split_off(16);
        if (pt_zero_preprend.len() != 16) || (pt_zero_preprend.iter().any(|b| *b != 0)) {
            Err(Box::new(KeyCommittingAEError::DecryptionFailed))
        } else {
            Ok(pt)
        }
    }
}

#[derive(Debug)]
pub enum KeyCommittingAEError {
    InvalidKeyFormat,
    EncryptionFailed,
    DecryptionFailed,
}

impl ErrorTrait for KeyCommittingAEError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for KeyCommittingAEError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            KeyCommittingAEError::InvalidKeyFormat => format!("invalid key format"),
            KeyCommittingAEError::EncryptionFailed => format!("encryption failed"),
            KeyCommittingAEError::DecryptionFailed => format!("decryption failed"),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn key_committing_ae_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut pt = [1u8; 32];
        rng.fill(&mut pt);
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        let mut ad = [0u8; 32];
        rng.fill(&mut ad);

        let ct = KeyCommittingAE::encrypt(&mut rng, &key, &ad, &pt).unwrap();
        let dec_ct = KeyCommittingAE::decrypt(&key, &ad, &ct).unwrap();
        assert!(pt.iter().eq(dec_ct.iter()));

        let mut key_bad = key.to_vec();
        key_bad[0] = key_bad[0] + 1u8;
        assert!(KeyCommittingAE::decrypt(&key_bad, &ad, &ct).is_err());

        let mut ad_bad = ad.to_vec();
        ad_bad[0] = ad_bad[0] + 1u8;
        assert!(KeyCommittingAE::decrypt(&key, &ad_bad, &ct).is_err());

        let mut nonce_bad = ct.to_vec();
        let l = nonce_bad.len();
        nonce_bad[l - 1] = nonce_bad[l - 1] + 1u8;
        assert!(KeyCommittingAE::decrypt(&key, &ad, &nonce_bad).is_err());
    }
}
