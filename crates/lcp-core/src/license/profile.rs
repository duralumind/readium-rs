use crate::crypto::transform::Transform;

/// Encryption profiles supported by LCP
#[derive(Debug, Clone, Copy)]
pub enum EncryptionProfile {
    /// Basic LCP profile (http://readium.org/lcp/basic-profile)
    Basic,
}

impl std::fmt::Display for EncryptionProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
        }
    }
}

impl std::str::FromStr for EncryptionProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "basic" => Ok(Self::Basic),
            _ => Err(format!("Unknown encryption profile: {}", s)),
        }
    }
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
