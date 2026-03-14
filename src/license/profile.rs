use clap::ValueEnum;

use crate::crypto::transform::Transform;

/// Encryption profiles supported by LCP
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EncryptionProfile {
    /// Basic LCP profile (http://readium.org/lcp/basic-profile)
    Basic,
}

impl Transform for EncryptionProfile {
    /// The transform for the basic profile is the identity function.
    ///
    /// Basically, the user's encryption key is simply the hash of their passphrase
    /// with no additional transform.
    fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
        match self {
            Self::Basic => user_key,
        }
    }
}
