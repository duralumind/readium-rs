use thiserror::Error;

/// Errors that can occur during cipher operations.
#[derive(Debug, Error)]
pub enum CipherError {
    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

pub mod aes_cbc256 {
    use super::CipherError;
    use aes::{
        cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit},
        Aes256,
    };
    use block_padding::Pkcs7;
    use cbc::{Decryptor, Encryptor};
    use rand::{rngs::OsRng, TryRngCore};

    type Aes256CbcEnc = Encryptor<Aes256>;
    type Aes256CbcDec = Decryptor<Aes256>;

    /// Encrypts with a randomly generated iv.
    /// The iv is prepended to the ciphertext and returned.
    pub fn encrypt_aes_256_cbc_with_random_iv(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
        // Generate a random iv
        let mut iv = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut iv)
            .expect("Failed to generate randomness");
        let mut encrypted = encrypt_aes_256_cbc(plaintext, key, &iv);
        let mut ciphertex = iv.to_vec();
        ciphertex.append(&mut encrypted);
        ciphertex
    }

    pub fn encrypt_aes_256_cbc(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
        let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
        encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    pub fn decrypt_aes_256_cbc(
        ciphertext: &[u8],
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, CipherError> {
        let decryptor = Aes256CbcDec::new(key.into(), iv.into());

        let mut buf = ciphertext.to_vec();
        let decrypted_data = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| CipherError::DecryptionFailed(format!("{:?}", e)))?;

        Ok(decrypted_data.to_vec())
    }

    pub fn decrypt_aes_256_cbc_with_prepended_iv(
        ciphertext: &[u8],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, CipherError> {
        let mut ciphertext = ciphertext.to_vec();
        // iv is the first 16 bytes
        let mut iv = [0; 16];
        iv.copy_from_slice(&ciphertext[0..16]);

        let decryptor = Aes256CbcDec::new(key.into(), &iv.into());

        let decrypted_data = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext[16..])
            .map_err(|e| CipherError::DecryptionFailed(format!("{:?}", e)))?;

        Ok(decrypted_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::aes_cbc256::*;

    const KEY: &[u8; 32] = &[42; 32];
    const IV: &[u8; 16] = &[41; 16];
    const PLAINTEXT: &[u8] = b"quickwhitefoxjumpsoverthelazydog";

    #[test]
    fn test_roundtrip() {
        let ciphertext = encrypt_aes_256_cbc(PLAINTEXT, KEY, IV);
        let decrypted = decrypt_aes_256_cbc(&ciphertext, KEY, IV).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_roundtrip_random_iv() {
        let ciphertext = encrypt_aes_256_cbc_with_random_iv(PLAINTEXT, KEY);
        let decrypted = decrypt_aes_256_cbc_with_prepended_iv(&ciphertext, KEY).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_incorrect_key() {
        let ciphertext = encrypt_aes_256_cbc(PLAINTEXT, KEY, IV);

        let wrong_key: &[u8; 32] = &[40; 32];
        // Decryption with the wrong key errors with bad padding
        assert!(decrypt_aes_256_cbc(&ciphertext, wrong_key, IV).is_err());
    }

    #[test]
    fn test_incorrect_iv() {
        let ciphertext = encrypt_aes_256_cbc(PLAINTEXT, KEY, IV);

        let wrong_iv: &[u8; 16] = &[40; 16];
        // Decryption with the wrong iv produces incorrect result
        let decrypted = decrypt_aes_256_cbc(&ciphertext, KEY, wrong_iv).unwrap();
        assert_ne!(decrypted, PLAINTEXT);
    }
}
