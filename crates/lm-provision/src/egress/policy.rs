//! Host allowlist for the sh.exec egress pin (spec 05 §L3, sh_egress).
//!
//! Shares its host-matching rules with [`crate::exec::policy::HttpPolicy`]
//! — both call into [`super::host_match::matches`] on the authority
//! half, so a declared host string means the same thing whether the
//! profile carries it in `sh_egress` or in `http_allowlist`. A pattern
//! is a literal host, or a single leading `*.` wildcard confined to
//! labels (`*.hf.co` matches `cdn-lfs.hf.co` and the bare `hf.co`,
//! never `evilhf.co`). An empty allowlist denies every host, the same
//! empty-list-denies-all rule the other L3 policies carry.

/// A declaration-derived host allowlist.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    patterns: Vec<String>,
}

impl EgressPolicy {
    /// Build from the profile's declared `sh_egress` host patterns.
    pub fn new(patterns: impl IntoIterator<Item = String>) -> Self {
        Self {
            patterns: patterns.into_iter().collect(),
        }
    }

    /// Whether any pattern is declared. An egress pin with zero patterns is a
    /// real answer (deny everything); "no pin at all" is the caller's concern
    /// (a `None` policy), not an empty one.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// A host is allowed iff it matches one declared pattern.
    ///
    /// Delegates to the shared [`super::host_match::matches`] so this
    /// answers the same as [`crate::exec::policy::HttpPolicy`] on the
    /// same authority: case-insensitive, trailing dot ignored, `*.X`
    /// matches the bare `X` and any label prefixed onto it, a literal
    /// pattern matches only itself.
    ///
    /// **Port**: the caller passes the CONNECT **host** here, with the
    /// port already stripped (the proxy's `connect_host`), so a declared
    /// host admits any port on it. That is the one place this policy
    /// differs from `http_allowlist`, which pins the port too; see
    /// [`super::host_match`] §Port handling and spec 05 §L3.
    pub fn allows(&self, host: &str) -> bool {
        self.patterns
            .iter()
            .any(|p| super::host_match::matches(p, host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_denies_every_host() {
        let p = EgressPolicy::new(Vec::<String>::new());
        assert!(p.is_empty());
        assert!(!p.allows("huggingface.co"));
    }

    #[test]
    fn literal_matches_only_itself() {
        let p = EgressPolicy::new(["huggingface.co".to_string()]);
        assert!(p.allows("huggingface.co"));
        assert!(!p.allows("cdn.huggingface.co"));
        assert!(!p.allows("evilhuggingface.co"));
    }

    #[test]
    fn wildcard_matches_subdomain_and_bare_suffix_but_not_a_glued_label() {
        let p = EgressPolicy::new(["*.hf.co".to_string()]);
        assert!(p.allows("cdn-lfs.hf.co"));
        assert!(p.allows("hf.co"));
        assert!(!p.allows("evilhf.co"));
        assert!(!p.allows("hf.co.evil.com"));
    }

    #[test]
    fn matching_is_case_insensitive_and_ignores_a_trailing_dot() {
        let p = EgressPolicy::new(["huggingface.co".to_string()]);
        assert!(p.allows("HuggingFace.CO"));
        assert!(p.allows("huggingface.co."));
    }
}
