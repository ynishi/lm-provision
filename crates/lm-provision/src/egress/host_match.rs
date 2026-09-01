//! One host-pattern matcher, shared by the two L3 allowlists that
//! carry authority-scoped wildcards ([`super::policy::EgressPolicy`] on
//! the `sh_egress` host list, [`crate::exec::policy::HttpPolicy`] on
//! the `http_allowlist` URL list).
//!
//! Before this module the two sides carried divergent host semantics
//! for the same profile-facing concept — case sensitivity, trailing-dot
//! trim, and whether `*.hf.co` accepted the bare suffix `hf.co` — with
//! only one side's tests pinning any of them. That is a footgun: a
//! profile author has one mental model of "declared host" and expects
//! two consumer paths to answer the same way. Unifying here makes them
//! do so.
//!
//! # Semantics
//!
//! Both `host` and `pattern` are normalised the DNS way before the
//! match runs:
//!
//! - **Case-insensitive** (RFC 1035 §2.3.3: DNS names compare
//!   case-insensitively; `HuggingFace.CO` is the same name as
//!   `huggingface.co`).
//! - **Trailing dot trimmed** (RFC 1035 §3.1 / §4.1.1: a trailing dot
//!   marks a fully-qualified name; presence/absence does not change
//!   identity).
//!
//! Then, on the normalised pair:
//!
//! - A pattern with no `*` matches only itself.
//! - A pattern with a single `*` splits into prefix and suffix; the
//!   host matches when it starts with the prefix, ends with the suffix,
//!   and is at least as long as the two halves combined. The wildcard
//!   never matches into the path (this module operates on the authority
//!   half only — the URL side splits before calling in).
//! - A pattern spelled as `*.X` additionally matches the bare `X` — the
//!   "zero labels ahead of the suffix" case. This is the one asymmetric
//!   rule the module carries, mirroring the DNS convention that
//!   `*.example.com` covers the apex `example.com` too, and it is the
//!   [`EgressPolicy`]'s tested behaviour (`*.hf.co` matches `hf.co`).
//!
//! # Why not `regex` / a full DNS library
//!
//! Every pattern this crate handles comes from the profile author's own
//! declaration list. The matcher's whole job is deciding whether one
//! authority string satisfies one declared pattern — a byte-level
//! comparison over the normalised pair. A regex engine would be more
//! machinery than the problem needs, and its own escape / anchor rules
//! would become a second surface for the same footgun this module
//! removes.

/// Whether `host` satisfies `pattern` under the unified rules above.
///
/// Both sides are trimmed of a trailing `.` and lowercased before the
/// match runs. `pattern` may carry at most one `*`; a second one is
/// treated literally (no pattern in the profiles the crate ships uses
/// more than one, so guaranteeing "single wildcard" is a spec concern,
/// not a matcher one).
pub fn matches(pattern: &str, host: &str) -> bool {
    let pattern = normalise(pattern);
    let host = normalise(host);
    match pattern.find('*') {
        None => host == pattern,
        Some(star_idx) => {
            let prefix = &pattern[..star_idx];
            let suffix = &pattern[star_idx + 1..];
            // General star: prefix + <anything> + suffix.
            let general_match = host.len() >= prefix.len() + suffix.len()
                && host.starts_with(prefix)
                && host.ends_with(suffix);
            if general_match {
                return true;
            }
            // The bare-suffix case: `*.X` also matches the apex `X`,
            // which the general-star length guard rejects because the
            // leading `.` in the suffix means "at least one label
            // ahead" (RFC 1034 label conventions carried over into DNS
            // wildcard practice). Egress test:
            // `*.hf.co` accepts `hf.co`.
            if prefix.is_empty() {
                if let Some(bare) = suffix.strip_prefix('.') {
                    return host == bare;
                }
            }
            false
        }
    }
}

fn normalise(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_pattern_matches_only_itself() {
        assert!(matches("huggingface.co", "huggingface.co"));
        assert!(!matches("huggingface.co", "cdn.huggingface.co"));
        assert!(!matches("huggingface.co", "evilhuggingface.co"));
    }

    #[test]
    fn matching_is_case_insensitive_on_both_sides() {
        assert!(matches("HuggingFace.CO", "huggingface.co"));
        assert!(matches("huggingface.co", "HUGGINGFACE.CO"));
    }

    #[test]
    fn matching_ignores_a_trailing_dot_on_either_side() {
        assert!(matches("huggingface.co.", "huggingface.co"));
        assert!(matches("huggingface.co", "huggingface.co."));
        assert!(matches("*.hf.co.", "cdn.hf.co"));
    }

    #[test]
    fn star_prefix_matches_a_subdomain_and_the_bare_suffix_but_not_a_glued_label() {
        assert!(matches("*.hf.co", "cdn-lfs.hf.co"));
        assert!(matches("*.hf.co", "hf.co"));
        assert!(!matches("*.hf.co", "evilhf.co"));
        assert!(!matches("*.hf.co", "hf.co.evil.com"));
    }

    #[test]
    fn star_inside_the_authority_carries_the_general_prefix_suffix_rule() {
        // The `HttpPolicy` shape: a `*` not at the label boundary. The
        // matcher does not require `*.` — it accepts a general prefix +
        // wildcard + suffix, which is what the http side's original rule
        // let profiles author.
        assert!(matches("f*.b2.backblazeb2.com", "f001.b2.backblazeb2.com"));
        assert!(matches("f*.b2.backblazeb2.com", "f.b2.backblazeb2.com"));
        assert!(!matches("f*.b2.backblazeb2.com", "x.b2.backblazeb2.com"));
    }

    #[test]
    fn empty_host_never_matches_a_non_empty_pattern() {
        assert!(!matches("hf.co", ""));
        assert!(!matches("*.hf.co", ""));
    }
}
