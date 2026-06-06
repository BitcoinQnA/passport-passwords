// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Strict origin: scheme + host + port. Byte-for-byte equality after
//! normalisation.
//!
//! Normalisation rules:
//!   - scheme is lowercased (HTTP equals http)
//!   - host is lowercased and IDN-converted to ASCII (punycode); `url`
//!     does this for us
//!   - default ports are dropped (`:80` for http, `:443` for https)
//!   - userinfo is rejected entirely (no `https://user:pass@host`)
//!   - path / query / fragment are discarded
//!
//! Stored origins are byte-equal — `https://github.com` and
//! `https://www.github.com` are different `Origin`s. Public release fill,
//! save, probe, and upsert paths all keep exact-origin semantics. The
//! [`origin_match_key`] helper remains available for future opt-in
//! subdomain policies, but it is not the default release path.

use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OriginError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("scheme must be http or https, got {0}")]
    UnsupportedScheme(String),
    #[error("url is missing a host")]
    MissingHost,
    #[error("url contains userinfo, which is forbidden")]
    UserInfoNotAllowed,
}

impl Origin {
    /// Parse a URL and extract its strict origin.
    pub fn parse(input: &str) -> Result<Self, OriginError> {
        let url = Url::parse(input).map_err(|e| OriginError::InvalidUrl(e.to_string()))?;
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(OriginError::UnsupportedScheme(scheme.to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(OriginError::UserInfoNotAllowed);
        }
        let host = url.host_str().ok_or(OriginError::MissingHost)?;
        let mut s = format!("{}://{}", scheme, host.to_ascii_lowercase());
        if let Some(port) = url.port() {
            s.push_str(&format!(":{}", port));
        }
        Ok(Origin(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Curated list of multi-label public suffixes. Without this `example.co.uk`
/// would be reduced to `co.uk` and a record on `example.co.uk` would also
/// match `attacker.co.uk` — the safety floor on fuzzy match. The full
/// publicsuffix.org list has thousands of entries; this covers the long
/// tail Q's users will realistically see. Add to it when a real-world
/// site doesn't match.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    // United Kingdom
    "co.uk",
    "org.uk",
    "net.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "nhs.uk",
    "sch.uk",
    // Australia / NZ
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "id.au",
    "asn.au",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    // Japan / Korea
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "ad.jp",
    "go.jp",
    "lg.jp",
    "co.kr",
    "ne.kr",
    "or.kr",
    "go.kr",
    "ac.kr",
    // Greater China / SE Asia
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "com.hk",
    "net.hk",
    "org.hk",
    "edu.hk",
    "gov.hk",
    "com.tw",
    "com.sg",
    "com.ph",
    "com.my",
    "com.vn",
    "co.th",
    "co.id",
    // Rest of world
    "co.in",
    "net.in",
    "org.in",
    "ac.in",
    "gov.in",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "edu.br",
    "com.mx",
    "co.za",
    "co.il",
    "com.tr",
    "com.ar",
    "com.eg",
    "com.sa",
    // PSL "private" suffixes users treat as separate sites.
    "github.io",
    "gitlab.io",
    "pages.dev",
    "vercel.app",
    "netlify.app",
];

/// Return the registrable domain for `host`, or `None` if `host` is an
/// IP literal or single-label name (e.g. `localhost`) for which fuzzy
/// matching shouldn't apply.
pub fn registrable_domain(host: &str) -> Option<&str> {
    if host.is_empty() || host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    for suffix in MULTI_LABEL_SUFFIXES {
        if let Some(prefix) = host.strip_suffix(suffix) {
            if prefix.is_empty() {
                return None;
            }
            if let Some(rest) = prefix.strip_suffix('.') {
                let last = rest.rsplit('.').next().unwrap_or(rest);
                if !last.is_empty() {
                    let start = host.len() - last.len() - 1 - suffix.len();
                    return Some(&host[start..]);
                }
            }
        }
    }
    let mut parts = host.rsplitn(3, '.');
    let tld = parts.next()?;
    let sld = parts.next()?;
    if tld.is_empty() || sld.is_empty() {
        return None;
    }
    let start = host.len() - tld.len() - 1 - sld.len();
    Some(&host[start..])
}

/// Lookup key used by the fill path. Two canonical origins map to the
/// same key iff they share scheme + registrable domain. Hosts without a
/// registrable domain (IP literals, `localhost`) preserve the full
/// origin including port, so `http://127.0.0.1:8000` doesn't collide
/// with `http://127.0.0.1:9000`.
pub fn origin_match_key(canonical_origin: &str) -> String {
    let Ok(url) = Url::parse(canonical_origin) else {
        return canonical_origin.to_string();
    };
    let host = url.host_str().unwrap_or("");
    match registrable_domain(host) {
        Some(rd) => format!("{}://{}", url.scheme(), rd),
        None => canonical_origin.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_default_port_dropped() {
        let o = Origin::parse("https://github.com/login?x=1#frag").unwrap();
        assert_eq!(o.as_str(), "https://github.com");
    }

    #[test]
    fn keeps_explicit_non_default_port() {
        let o = Origin::parse("http://localhost:3000/path").unwrap();
        assert_eq!(o.as_str(), "http://localhost:3000");
    }

    #[test]
    fn drops_default_port_when_explicit() {
        let o = Origin::parse("https://github.com:443/").unwrap();
        assert_eq!(o.as_str(), "https://github.com");
        let o = Origin::parse("http://example.com:80/").unwrap();
        assert_eq!(o.as_str(), "http://example.com");
    }

    #[test]
    fn lowercases_scheme_and_host() {
        let o = Origin::parse("HTTPS://GitHub.com/").unwrap();
        assert_eq!(o.as_str(), "https://github.com");
    }

    #[test]
    fn subdomains_are_distinct() {
        let a = Origin::parse("https://github.com").unwrap();
        let b = Origin::parse("https://www.github.com").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(matches!(
            Origin::parse("file:///etc/passwd"),
            Err(OriginError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            Origin::parse("javascript:alert(1)"),
            Err(OriginError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn rejects_userinfo() {
        assert_eq!(
            Origin::parse("https://attacker@github.com").unwrap_err(),
            OriginError::UserInfoNotAllowed
        );
        assert_eq!(
            Origin::parse("https://user:pass@github.com").unwrap_err(),
            OriginError::UserInfoNotAllowed
        );
    }

    #[test]
    fn idn_punycode_normalised() {
        // German "bücher" lowercased becomes punycode xn--bcher-kva
        let o = Origin::parse("https://Bücher.example/").unwrap();
        assert_eq!(o.as_str(), "https://xn--bcher-kva.example");
    }

    #[test]
    fn ipv6_literal_kept_with_brackets() {
        let o = Origin::parse("http://[::1]:8080/").unwrap();
        assert_eq!(o.as_str(), "http://[::1]:8080");
    }

    #[test]
    fn rejects_empty_or_garbage() {
        assert!(Origin::parse("").is_err());
        assert!(Origin::parse("not a url").is_err());
    }

    #[test]
    fn registrable_domain_two_label_host() {
        assert_eq!(registrable_domain("github.com"), Some("github.com"));
        assert_eq!(registrable_domain("foundation.xyz"), Some("foundation.xyz"));
    }

    #[test]
    fn registrable_domain_strips_subdomains() {
        assert_eq!(registrable_domain("gist.github.com"), Some("github.com"));
        assert_eq!(registrable_domain("a.b.c.example.com"), Some("example.com"));
        assert_eq!(
            registrable_domain("www.foundation.xyz"),
            Some("foundation.xyz")
        );
    }

    #[test]
    fn registrable_domain_handles_multi_label_suffixes() {
        assert_eq!(registrable_domain("example.co.uk"), Some("example.co.uk"));
        assert_eq!(
            registrable_domain("foo.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("a.b.example.com.au"),
            Some("example.com.au")
        );
        assert_eq!(registrable_domain("user.github.io"), Some("user.github.io"));
        assert_eq!(
            registrable_domain("project.user.github.io"),
            Some("user.github.io")
        );
    }

    #[test]
    fn registrable_domain_rejects_bare_suffix() {
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("github.io"), None);
    }

    #[test]
    fn registrable_domain_rejects_ip_and_localhost() {
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain("[::1]"), None);
        assert_eq!(registrable_domain("localhost"), None);
    }

    #[test]
    fn match_key_collapses_subdomains() {
        let a = Origin::parse("https://github.com").unwrap();
        let b = Origin::parse("https://gist.github.com").unwrap();
        assert_eq!(origin_match_key(a.as_str()), origin_match_key(b.as_str()));
    }

    #[test]
    fn match_key_keeps_scheme_distinct() {
        let a = origin_match_key("https://github.com");
        let b = origin_match_key("http://github.com");
        assert_ne!(a, b);
    }

    #[test]
    fn match_key_drops_port_for_domain_hosts() {
        let a = origin_match_key("https://github.com");
        let b = origin_match_key("https://github.com:8443");
        assert_eq!(a, b);
    }

    #[test]
    fn match_key_keeps_port_for_ip_and_localhost() {
        // 127.0.0.1:8000 and 127.0.0.1:9000 are different sites for
        // password-manager scoping.
        let a = origin_match_key("http://127.0.0.1:8000");
        let b = origin_match_key("http://127.0.0.1:9000");
        assert_ne!(a, b);
        // Localhost is single-label — exact match only.
        let a = origin_match_key("http://localhost:8000");
        let b = origin_match_key("http://localhost:9000");
        assert_ne!(a, b);
    }

    #[test]
    fn match_key_does_not_match_evil_suffix_attack() {
        // attacker.example.com.evil.com must NOT match example.com.
        let stored = origin_match_key("https://example.com");
        let evil = origin_match_key("https://attacker.example.com.evil.com");
        assert_ne!(stored, evil);
    }
}
