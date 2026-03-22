use super::cipher;
use base64::{Engine as _, engine::general_purpose};
use rand::{TryRngCore, rngs::OsRng};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::Transform;

/// The password chosen by the user to encrypt/decrypt the publication.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct UserPassphrase(pub String);

/// The hash algorithm for hashing the passphrase to a user key before [`Transform`].
#[derive(Debug)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    pub fn hash_message(&self, data: impl AsRef<[u8]>) -> [u8; 32] {
        match self {
            Self::Sha256 => Sha256::digest(data).into(),
        }
    }
}

/// The user's encryption key. This represents the key after applying the
/// secret [`Transform`].
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct UserEncryptionKey {
    key: [u8; 32],
}

impl UserEncryptionKey {
    pub fn new(
        passphrase: UserPassphrase,
        algorithm: HashAlgorithm,
        transform: impl Transform,
    ) -> Self {
        Self {
            key: transform.transform(algorithm.hash_message(passphrase.0.as_bytes())),
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// The content key that is used as a key for the encryption algorithm for actually
/// encrypting the contents of the publication.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ContentKey([u8; 32]);

impl ContentKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .expect("Failed to generate randomness");
        Self(key)
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decrypt the original content key using the user passphrase and the key transform.
    pub fn decrypt_content_key(
        encrypted_key: &EncryptedContentKey,
        user_key: &UserEncryptionKey,
    ) -> Result<Self, String> {
        let decrypted = cipher::aes_cbc256::decrypt_aes_256_cbc(
            encrypted_key.key(),
            user_key.key(),
            encrypted_key.iv(),
        )?;
        let mut content_key = [0; 32];
        content_key.copy_from_slice(&decrypted);
        Ok(ContentKey(content_key))
    }
}

/// Represents a [`ContentKey`] that has been encrypted using the [`UserEncryptionKey`].
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EncryptedContentKey {
    /// The key size here is 48 bytes because of additional padding with the PKCS7 padding scheme
    /// for aes cbc.
    key: [u8; 48],
    /// The associated initialization vector for the aes encryption.
    iv: [u8; 16],
}

impl EncryptedContentKey {
    /// Create an [`EncryptedContentKey`] by decoding raw bytes.
    pub fn new_from_raw_bytes(base64_encrypted_key: &str) -> Result<Self, String> {
        let encrypted_key_bytes = general_purpose::STANDARD
            .decode(base64_encrypted_key)
            .map_err(|e| format!("Base64 decode of content key failed, err: {:?}", e))?;

        if encrypted_key_bytes.len() != 64 {
            return Err(format!(
                "Expected 64 bytes for encrypted content key, got {}",
                encrypted_key_bytes.len()
            ));
        }
        let (iv_slice, key_slice) = encrypted_key_bytes.split_at(16);
        let key = key_slice
            .try_into()
            .map_err(|_| "Failed to extract key bytes".to_string())?;
        let iv = iv_slice
            .try_into()
            .map_err(|_| "Failed to extract iv bytes".to_string())?;

        Ok(Self { key, iv })
    }
    /// Create an [`EncryptedContentKey`] by encrypting the [`ContentKey`] with a
    /// [`UserPassphrase`].
    ///
    /// The encryption algorithm used is aes cbc with pkc7 padding.
    /// The resulting `EncryptedContentKey` length is 48 bytes (16 bytes additional padding)
    /// and the iv length is 16 bytes.
    pub fn new(
        content_key: ContentKey,
        passphrase: UserPassphrase,
        transform: impl Transform,
    ) -> Self {
        let user_key = UserEncryptionKey::new(passphrase, HashAlgorithm::Sha256, transform);
        // Generate a random iv
        let mut iv = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut iv)
            .expect("Failed to generate randomness");
        let mut key = [0u8; 48];
        // Vec gets dropped right after the scope ends
        {
            let encrypted =
                cipher::aes_cbc256::encrypt_aes_256_cbc(content_key.key(), &user_key.key, &iv);

            key.copy_from_slice(&encrypted);
        }
        Self { key, iv }
    }

    pub fn key(&self) -> &[u8; 48] {
        &self.key
    }

    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Decrypt the original content key using the user passphrase and the key transform.
    pub fn decrypt_content_key(
        &self,
        passphrase: UserPassphrase,
        transform: impl Transform,
    ) -> Result<ContentKey, String> {
        let user_key = UserEncryptionKey::new(passphrase, HashAlgorithm::Sha256, transform);
        let decrypted =
            cipher::aes_cbc256::decrypt_aes_256_cbc(&self.key, user_key.key(), &self.iv)?;
        let mut content_key = [0; 32];
        content_key.copy_from_slice(&decrypted);
        Ok(ContentKey(content_key))
    }

    /// Encodes the encrypted content key in base64 format (IV || ciphertext)
    pub fn to_base64(&self) -> String {
        // Concatenate IV + encrypted key (LCP format)
        let mut data = Vec::with_capacity(16 + self.key.len());
        data.extend_from_slice(&self.iv);
        data.extend_from_slice(&self.key);

        general_purpose::STANDARD.encode(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_no_transform() {
        struct IdentityTransform;

        impl Transform for IdentityTransform {
            fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
                user_key
            }
        }
        let content_key = ContentKey::generate();

        let encrypted_content_key = EncryptedContentKey::new(
            content_key.clone(),
            UserPassphrase("password123".to_string()),
            IdentityTransform,
        );

        let decrypted_content_key = encrypted_content_key
            .decrypt_content_key(UserPassphrase("password123".to_string()), IdentityTransform)
            .unwrap();
        assert_eq!(decrypted_content_key.key(), content_key.key());
    }

    #[test]
    fn roundtrip_with_transform() {
        // hash the hash
        struct ShaTransform;

        impl Transform for ShaTransform {
            fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
                Sha256::digest(user_key).into()
            }
        }
        let content_key = ContentKey::generate();

        let encrypted_content_key = EncryptedContentKey::new(
            content_key.clone(),
            UserPassphrase("password123".to_string()),
            ShaTransform,
        );

        let decrypted_content_key = encrypted_content_key
            .decrypt_content_key(UserPassphrase("password123".to_string()), ShaTransform)
            .unwrap();
        assert_eq!(decrypted_content_key.key(), content_key.key());
    }
}
