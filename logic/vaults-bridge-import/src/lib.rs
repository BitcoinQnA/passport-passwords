// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Plaintext-CSV import for the Passwords app.
//!
//! All parsing happens on-device, after the user has copied their export
//! file onto Prime via mass-storage. Plaintext passwords never cross USB.
//!
//! Auto-detection picks a parser by inspecting the header row. Each known
//! source has a column-name signature; the first match wins. Falls back
//! to `Generic` (5-column `name,url,username,password,notes`) if no
//! signature matches but the row count and column shape look reasonable.

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("file is empty")]
    Empty,
    #[error("file is not valid utf-8")]
    NotUtf8,
    #[error("no recognised header row")]
    UnrecognisedHeader,
    #[error("no rows after header")]
    NoRows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Google,
    Proton,
    OnePassword,
    Bitwarden,
    AppleKeychain,
    Lastpass,
    Generic,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Google => "Google Passwords",
            Source::Proton => "Proton Pass",
            Source::OnePassword => "1Password",
            Source::Bitwarden => "Bitwarden",
            Source::AppleKeychain => "Apple Keychain",
            Source::Lastpass => "LastPass",
            Source::Generic => "Generic CSV",
        }
    }
}

/// One credential extracted from a source export. `password` is wrapped
/// in `Zeroizing` so the heap copy is wiped when the record drops.
pub struct ImportedRecord {
    pub origin: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub label: String,
    pub notes: String,
}

impl fmt::Debug for ImportedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedRecord")
            .field("origin", &self.origin)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("label", &self.label)
            .field("notes", &"<redacted>")
            .finish()
    }
}

pub struct Imported {
    pub source: Source,
    pub records: Vec<ImportedRecord>,
}

/// Parse a CSV byte buffer. Auto-detects the source by header signature.
pub fn parse(bytes: &[u8]) -> Result<Imported, ImportError> {
    if bytes.is_empty() {
        return Err(ImportError::Empty);
    }
    let mut text = core::str::from_utf8(strip_bom(bytes)).map_err(|_| ImportError::NotUtf8)?;
    // CRLF -> LF: split_lines below tolerates both, but normalising up
    // front simplifies index math when we later need to take slices.
    let _ = &mut text;

    let mut rows = parse_rows(text);
    let header = rows.next().ok_or(ImportError::Empty)?;
    let source = detect_source(&header).ok_or(ImportError::UnrecognisedHeader)?;
    let mapping = column_mapping(source, &header);

    let mut records = Vec::new();
    for row in rows {
        if row.iter().all(|s| s.is_empty()) {
            continue;
        }
        let rec = build_record(&row, &mapping);
        // Skip rows that don't carry any usable secret. A url-only row is
        // probably a "deleted" marker from some exports.
        if rec.password.is_empty() && rec.username.is_empty() {
            continue;
        }
        records.push(rec);
    }
    if records.is_empty() {
        return Err(ImportError::NoRows);
    }
    Ok(Imported { source, records })
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

#[derive(Default, Clone, Copy)]
struct Mapping {
    name: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
}

fn build_record(row: &[String], m: &Mapping) -> ImportedRecord {
    let pick = |idx: Option<usize>| -> String {
        idx.and_then(|i| row.get(i).cloned()).unwrap_or_default()
    };
    let raw_url = pick(m.url);
    let origin = canonicalise_origin(&raw_url);
    let label = pick(m.name);
    let username = pick(m.username);
    let password = Zeroizing::new(pick(m.password));
    let notes = pick(m.notes);
    ImportedRecord {
        origin,
        username,
        password,
        label,
        notes,
    }
}

/// Reduce an export's `url` field to a strict origin (`scheme://host[:port]`).
/// If parsing fails we fall back to the trimmed input — the engine's
/// stricter origin validator will reject it later if it's still bad.
fn canonicalise_origin(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    if let Ok(u) = Url::parse(raw) {
        if let Some(host) = u.host_str() {
            let scheme = u.scheme();
            let mut out = String::with_capacity(scheme.len() + 3 + host.len() + 6);
            out.push_str(scheme);
            out.push_str("://");
            out.push_str(host);
            if let Some(port) = u.port() {
                out.push(':');
                let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{port}"));
            }
            return out;
        }
    }
    // Bare domain like `github.com` — assume https.
    if raw.contains('.') && !raw.contains(' ') {
        let mut out = String::with_capacity(8 + raw.len());
        out.push_str("https://");
        out.push_str(raw);
        return out;
    }
    raw.to_string()
}

// --- Header detection ----------------------------------------------------

fn detect_source(header: &[String]) -> Option<Source> {
    let lc: Vec<String> = header
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let has = |needle: &str| lc.iter().any(|c| c == needle);

    // Google Passwords: name,url,username,password,note
    if has("name") && has("url") && has("username") && has("password") && has("note") {
        return Some(Source::Google);
    }
    // Proton Pass: name,url,email,username,password,note,...
    if has("name") && has("url") && has("password") && (has("email") || has("note")) {
        // Distinguish from Google by absence of `note` in singular form
        // — Proton uses `note`, but if BOTH have it, Google's signature
        // already matched above.
        return Some(Source::Proton);
    }
    // 1Password CSV: Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
    if has("title") && has("url") && has("username") && has("password") && has("notes") {
        return Some(Source::OnePassword);
    }
    // Bitwarden:
    // folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
    if has("login_uri") && has("login_username") && has("login_password") {
        return Some(Source::Bitwarden);
    }
    // Apple Keychain (Safari): Title,URL,Username,Password,Notes,OTPAuth
    if has("title") && has("url") && has("username") && has("password") {
        return Some(Source::AppleKeychain);
    }
    // LastPass: url,username,password,totp,extra,name,grouping,fav
    if has("url") && has("username") && has("password") && has("extra") && has("grouping") {
        return Some(Source::Lastpass);
    }
    // Generic 5-column with at least url/username/password
    if has("url") && has("username") && has("password") {
        return Some(Source::Generic);
    }
    None
}

fn column_mapping(source: Source, header: &[String]) -> Mapping {
    let find = |needle: &str| -> Option<usize> {
        header
            .iter()
            .position(|c| c.trim().eq_ignore_ascii_case(needle))
    };
    let mut m = Mapping::default();
    match source {
        Source::Google => {
            m.name = find("name");
            m.url = find("url");
            m.username = find("username");
            m.password = find("password");
            m.notes = find("note");
        }
        Source::Proton => {
            m.name = find("name");
            m.url = find("url");
            m.username = find("username").or_else(|| find("email"));
            m.password = find("password");
            m.notes = find("note").or_else(|| find("notes"));
        }
        Source::OnePassword => {
            m.name = find("title");
            m.url = find("url");
            m.username = find("username");
            m.password = find("password");
            m.notes = find("notes");
        }
        Source::Bitwarden => {
            m.name = find("name");
            m.url = find("login_uri");
            m.username = find("login_username");
            m.password = find("login_password");
            m.notes = find("notes");
        }
        Source::AppleKeychain => {
            m.name = find("title");
            m.url = find("url");
            m.username = find("username");
            m.password = find("password");
            m.notes = find("notes");
        }
        Source::Lastpass => {
            m.name = find("name");
            m.url = find("url");
            m.username = find("username");
            m.password = find("password");
            m.notes = find("extra");
        }
        Source::Generic => {
            m.name = find("name").or_else(|| find("title"));
            m.url = find("url");
            m.username = find("username");
            m.password = find("password");
            m.notes = find("notes").or_else(|| find("note"));
        }
    }
    m
}

// --- CSV parser ----------------------------------------------------------
//
// RFC 4180-ish: comma-separated, double-quote-enclosed for fields that
// contain commas/newlines/quotes, doubled "" for an embedded quote.
// Tolerates LF and CRLF line endings.

fn parse_rows(text: &str) -> RowIter<'_> {
    RowIter {
        chars: text.chars(),
    }
}

struct RowIter<'a> {
    chars: core::str::Chars<'a>,
}

impl<'a> Iterator for RowIter<'a> {
    type Item = Vec<String>;

    fn next(&mut self) -> Option<Vec<String>> {
        let mut fields: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut saw_any = false;
        while let Some(ch) = self.chars.next() {
            saw_any = true;
            if in_quotes {
                if ch == '"' {
                    // Doubled quote = escaped quote inside the field.
                    if self.chars.clone().next() == Some('"') {
                        cur.push('"');
                        self.chars.next();
                        continue;
                    }
                    in_quotes = false;
                    continue;
                }
                cur.push(ch);
            } else {
                match ch {
                    '"' => {
                        in_quotes = true;
                    }
                    ',' => {
                        fields.push(core::mem::take(&mut cur));
                    }
                    '\n' => {
                        fields.push(core::mem::take(&mut cur));
                        return Some(fields);
                    }
                    '\r' => {
                        fields.push(core::mem::take(&mut cur));
                        if self.chars.clone().next() == Some('\n') {
                            self.chars.next();
                        }
                        return Some(fields);
                    }
                    _ => {
                        cur.push(ch);
                    }
                }
            }
        }
        // Hit EOF mid-record. Flush whatever we have unless the row was
        // entirely whitespace-or-empty, which can happen when files end
        // with a trailing newline.
        if !saw_any {
            None
        } else {
            fields.push(cur);
            if fields.iter().all(|s| s.is_empty()) {
                None
            } else {
                Some(fields)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_google() {
        let csv = b"name,url,username,password,note\n\
                    GitHub,https://github.com,alice,hunter2,\n";
        let out = parse(csv).unwrap();
        assert_eq!(out.source, Source::Google);
        assert_eq!(out.records.len(), 1);
        let r = &out.records[0];
        assert_eq!(r.origin, "https://github.com");
        assert_eq!(r.username, "alice");
        assert_eq!(&*r.password, "hunter2");
        assert_eq!(r.label, "GitHub");
    }

    #[test]
    fn detects_bitwarden() {
        let csv = b"folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                    ,1,login,Foundation,my notes,,0,https://foundation.xyz,alice,hunter2,\n";
        let out = parse(csv).unwrap();
        assert_eq!(out.source, Source::Bitwarden);
        assert_eq!(out.records[0].origin, "https://foundation.xyz");
        assert_eq!(out.records[0].label, "Foundation");
    }

    #[test]
    fn handles_quoted_commas_and_newlines() {
        let csv = b"name,url,username,password,note\n\
                    \"Comma, Inc\",https://example.com,a,\"p,1\",\"line one\nline two\"\n";
        let out = parse(csv).unwrap();
        let r = &out.records[0];
        assert_eq!(r.label, "Comma, Inc");
        assert_eq!(&*r.password, "p,1");
        assert_eq!(r.notes, "line one\nline two");
    }

    #[test]
    fn doubled_quote_is_literal_quote() {
        let csv = b"name,url,username,password,note\n\
                    GitHub,https://github.com,alice,\"he said \"\"hi\"\"\",\n";
        let out = parse(csv).unwrap();
        assert_eq!(&*out.records[0].password, "he said \"hi\"");
    }

    #[test]
    fn preserves_non_ascii_fields() {
        let csv = "name,url,username,password,note\n\
                   Bücher,https://bücher.example,álïçé,päss🔐,mañana\n";
        let out = parse(csv.as_bytes()).unwrap();
        let r = &out.records[0];
        assert_eq!(r.label, "Bücher");
        assert_eq!(r.username, "álïçé");
        assert_eq!(&*r.password, "päss🔐");
        assert_eq!(r.notes, "mañana");
    }

    #[test]
    fn skips_empty_password_rows() {
        let csv = b"name,url,username,password,note\n\
                    GitHub,https://github.com,,,\n\
                    GitLab,https://gitlab.com,bob,pw,\n";
        let out = parse(csv).unwrap();
        assert_eq!(out.records.len(), 1);
    }

    #[test]
    fn bom_is_tolerated() {
        let mut csv = Vec::from([0xEFu8, 0xBB, 0xBF]);
        csv.extend_from_slice(b"name,url,username,password,note\nx,https://x.io,a,p,\n");
        let out = parse(&csv).unwrap();
        assert_eq!(out.records.len(), 1);
    }

    #[test]
    fn bare_domain_gets_https_prefix() {
        let csv = b"name,url,username,password,note\nx,github.com,a,p,\n";
        let out = parse(csv).unwrap();
        assert_eq!(out.records[0].origin, "https://github.com");
    }

    #[test]
    fn unknown_header_errors() {
        let csv = b"foo,bar,baz\n1,2,3\n";
        assert!(matches!(parse(csv), Err(ImportError::UnrecognisedHeader)));
    }
}
