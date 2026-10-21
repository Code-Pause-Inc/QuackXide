//! A secret string: zeroized on drop, redacted in `Debug`.

use serde::Deserialize;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Credentials and tokens held in memory: zeroized on drop (including each
/// clone), redacted in `Debug`, and read only through [`SecretString::expose`].
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

// `Zeroizing` clears the string when it drops.
impl ZeroizeOnDrop for SecretString {}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretString>();
    }

    #[test]
    fn secret_string_is_redacted_in_debug() {
        let secret = SecretString::new("hunter2".into());
        let debugged = format!("{secret:?} {:?}", secret.clone());
        assert!(!debugged.contains("hunter2"));
        assert!(debugged.contains("<redacted>"));
        assert_eq!(secret.expose(), "hunter2");
    }
}
