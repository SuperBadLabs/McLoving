//! Shared domain vocabulary. Runtime behavior begins in later tickets.

/// Stable product name used by foundation binaries.
pub const PRODUCT_NAME: &str = "McLoving";

#[cfg(test)]
mod tests {
    use super::PRODUCT_NAME;

    #[test]
    fn product_name_is_stable() {
        assert_eq!(PRODUCT_NAME, "McLoving");
    }
}
