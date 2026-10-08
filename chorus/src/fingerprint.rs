use percent_encoding::percent_decode_str;
use serde_json::{Map, Value};
use std::{error::Error, fmt, net::Ipv6Addr, str::FromStr};
use url::{Position, Url};

const ATOM_DOMAIN: &[u8] = b"chorus-atom-v1\0";

/// Computes deterministic fingerprints for the supported IOC objects in a STIX bundle.
pub fn compute_atom_fingerprints(stix_bundle: &[u8]) -> Result<Vec<[u8; 32]>, FingerprintError> {
    let bundle: Value =
        serde_json::from_slice(stix_bundle).map_err(FingerprintError::InvalidJson)?;
    let objects = bundle
        .get("objects")
        .and_then(Value::as_array)
        .ok_or(FingerprintError::MissingObjects)?;
    let mut atoms = Vec::new();
    for (index, value) in objects.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or(FingerprintError::InvalidObject(index))?;
        let object_type = string_field(object, index, "type")?;
        let revoked = optional_bool_field(object, index, "revoked")?.unwrap_or(false);
        match object_type {
            "ipv4-addr" => push_atom(
                &mut atoms,
                "ipv4",
                normalize_ipv4(string_field(object, index, "value")?, index)?,
                revoked,
            ),
            "ipv6-addr" => push_atom(
                &mut atoms,
                "ipv6",
                normalize_ipv6(string_field(object, index, "value")?, index)?,
                revoked,
            ),
            "domain-name" => push_atom(
                &mut atoms,
                "domain",
                normalize_domain(string_field(object, index, "value")?, index)?,
                revoked,
            ),
            "url" => push_atom(
                &mut atoms,
                "url",
                normalize_url(string_field(object, index, "value")?, index)?,
                revoked,
            ),
            "file" => extract_hashes(object, index, revoked, &mut atoms)?,
            "vulnerability" => push_atom(
                &mut atoms,
                "cve",
                string_field(object, index, "name")?.to_ascii_uppercase(),
                revoked,
            ),
            "attack-pattern" => extract_mitre_ids(object, index, revoked, &mut atoms)?,
            "indicator" => extract_indicator(object, index, revoked, &mut atoms)?,
            "email-addr" | "windows-registry-key" => {
                return Err(FingerprintError::UnsupportedObjectType {
                    object: index,
                    object_type: object_type.to_owned(),
                })
            }
            _ => {}
        }
    }
    atoms.sort_unstable();
    atoms.dedup();
    Ok(atoms
        .iter()
        .map(|atom| structured_digest_v1(atom))
        .collect())
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    index: usize,
    field: &'static str,
) -> Result<&'a str, FingerprintError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(FingerprintError::InvalidField {
            object: index,
            field,
        })
}

fn optional_bool_field(
    object: &Map<String, Value>,
    index: usize,
    field: &'static str,
) -> Result<Option<bool>, FingerprintError> {
    object
        .get(field)
        .map(|value| {
            value.as_bool().ok_or(FingerprintError::InvalidField {
                object: index,
                field,
            })
        })
        .transpose()
}

fn normalize_ipv4(value: &str, object: usize) -> Result<String, FingerprintError> {
    let octets = value
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_observable(object, "ipv4-addr", value))?;
    if octets.len() != 4 {
        return Err(invalid_observable(object, "ipv4-addr", value));
    }
    Ok(octets
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

fn normalize_ipv6(value: &str, object: usize) -> Result<String, FingerprintError> {
    Ipv6Addr::from_str(value)
        .map(|address| address.to_string())
        .map_err(|_| invalid_observable(object, "ipv6-addr", value))
}

fn normalize_domain(value: &str, object: usize) -> Result<String, FingerprintError> {
    let value = value.trim_end_matches('.');
    let (domain, result) = idna::domain_to_unicode(value);
    if value.is_empty() || result.is_err() {
        return Err(invalid_observable(object, "domain-name", value));
    }
    Ok(domain.to_lowercase())
}

fn normalize_url(value: &str, object: usize) -> Result<String, FingerprintError> {
    let explicit_path = has_explicit_path(value);
    let mut url = Url::parse(value).map_err(|_| invalid_observable(object, "url", value))?;
    if !url.has_host() || url.cannot_be_a_base() {
        return Err(invalid_observable(object, "url", value));
    }
    let path = percent_decode_str(url.path())
        .decode_utf8()
        .map_err(|_| invalid_observable(object, "url", value))?
        .into_owned();
    url.set_path(&path);
    let mut query = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if url.query().is_some() {
        query.sort_by(|left, right| left.0.cmp(&right.0));
        url.query_pairs_mut().clear().extend_pairs(&query);
    }
    url.set_fragment(None);
    let host = match url.domain() {
        Some(domain) => normalize_domain(domain, object)?,
        None => url[Position::BeforeHost..Position::AfterHost].to_owned(),
    };
    let path = if explicit_path { url.path() } else { "" };
    Ok(format!(
        "{}{}{}{}{}",
        &url[..Position::BeforeHost],
        host,
        &url[Position::AfterHost..Position::BeforePath],
        path,
        &url[Position::AfterPath..]
    ))
}

fn has_explicit_path(value: &str) -> bool {
    value
        .split_once("://")
        .and_then(|(_, authority)| {
            authority
                .find(['/', '?', '#'])
                .map(|delimiter| authority.as_bytes()[delimiter] == b'/')
        })
        .unwrap_or(false)
}

fn extract_hashes(
    object: &Map<String, Value>,
    index: usize,
    revoked: bool,
    atoms: &mut Vec<String>,
) -> Result<(), FingerprintError> {
    let hashes =
        object
            .get("hashes")
            .and_then(Value::as_object)
            .ok_or(FingerprintError::InvalidField {
                object: index,
                field: "hashes",
            })?;
    for value in hashes.values() {
        let value = value.as_str().ok_or(FingerprintError::InvalidField {
            object: index,
            field: "hashes",
        })?;
        let normalized = normalize_hash(value, index)?;
        push_atom(atoms, "hash", normalized, revoked);
    }
    Ok(())
}

fn normalize_hash(value: &str, object: usize) -> Result<String, FingerprintError> {
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_hexdigit() {
            normalized.push(character.to_ascii_lowercase());
        } else if character == ':' || character == '-' || character.is_ascii_whitespace() {
            continue;
        } else {
            return Err(invalid_observable(object, "file hash", value));
        }
    }
    if normalized.is_empty() || normalized.len() % 2 != 0 {
        return Err(invalid_observable(object, "file hash", value));
    }
    Ok(normalized)
}

fn extract_mitre_ids(
    object: &Map<String, Value>,
    index: usize,
    revoked: bool,
    atoms: &mut Vec<String>,
) -> Result<(), FingerprintError> {
    let references = object
        .get("external_references")
        .and_then(Value::as_array)
        .ok_or(FingerprintError::InvalidField {
            object: index,
            field: "external_references",
        })?;
    for reference in references {
        let reference = reference
            .as_object()
            .ok_or(FingerprintError::InvalidField {
                object: index,
                field: "external_references",
            })?;
        if reference.get("source_name").and_then(Value::as_str) == Some("mitre-attack") {
            push_atom(
                atoms,
                "mitre",
                string_field(reference, index, "external_id")?.to_ascii_uppercase(),
                revoked,
            );
        }
    }
    Ok(())
}

fn extract_indicator(
    object: &Map<String, Value>,
    index: usize,
    revoked: bool,
    atoms: &mut Vec<String>,
) -> Result<(), FingerprintError> {
    if let Some(pattern_type) = object.get("pattern_type") {
        if pattern_type.as_str() != Some("stix") {
            return Err(FingerprintError::InvalidField {
                object: index,
                field: "pattern_type",
            });
        }
    }
    extract_pattern(
        string_field(object, index, "pattern")?,
        index,
        revoked,
        atoms,
    )
}

fn extract_pattern(
    pattern: &str,
    object: usize,
    revoked: bool,
    atoms: &mut Vec<String>,
) -> Result<(), FingerprintError> {
    for (path, value) in PatternParser::new(pattern, object)?.comparisons()? {
        match path.as_str() {
            "ipv4-addr:value" => push_atom(atoms, "ipv4", normalize_ipv4(&value, object)?, revoked),
            "ipv6-addr:value" => push_atom(atoms, "ipv6", normalize_ipv6(&value, object)?, revoked),
            "domain-name:value" => {
                push_atom(atoms, "domain", normalize_domain(&value, object)?, revoked)
            }
            "url:value" => push_atom(atoms, "url", normalize_url(&value, object)?, revoked),
            path if path.starts_with("file:hashes:") => {
                push_atom(atoms, "hash", normalize_hash(&value, object)?, revoked)
            }
            "file:name" => {}
            _ => {
                return Err(FingerprintError::UnsupportedPattern {
                    object,
                    offset: 0,
                    reason: "unsupported STIX object path",
                })
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    String(String),
    Equal,
    Colon,
    Dot,
    LeftBracket,
    RightBracket,
    LeftParenthesis,
    RightParenthesis,
}

struct PatternParser {
    tokens: Vec<(Token, usize)>,
    next: usize,
    object: usize,
}

impl PatternParser {
    fn new(pattern: &str, object: usize) -> Result<Self, FingerprintError> {
        Ok(Self {
            tokens: tokenize(pattern, object)?,
            next: 0,
            object,
        })
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.next).map(|(token, _)| token)
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.next).map(|(token, _)| token.clone());
        self.next += usize::from(token.is_some());
        token
    }

    fn expect(&mut self, expected: Token) -> Result<(), FingerprintError> {
        if self.take() == Some(expected) {
            Ok(())
        } else {
            Err(self.error("unexpected token in STIX pattern"))
        }
    }

    fn comparisons(mut self) -> Result<Vec<(String, String)>, FingerprintError> {
        self.expect(Token::LeftBracket)?;
        let mut comparisons = Vec::new();
        self.expression(&mut comparisons)?;
        self.expect(Token::RightBracket)?;
        if self.peek().is_some() {
            return Err(self.error("STIX pattern qualifiers are not supported"));
        }
        Ok(comparisons)
    }

    fn expression(
        &mut self,
        comparisons: &mut Vec<(String, String)>,
    ) -> Result<(), FingerprintError> {
        self.term(comparisons)?;
        while matches!(self.peek(), Some(Token::Word(word)) if word.eq_ignore_ascii_case("AND") || word.eq_ignore_ascii_case("OR"))
        {
            self.take();
            self.term(comparisons)?;
        }
        Ok(())
    }

    fn term(&mut self, comparisons: &mut Vec<(String, String)>) -> Result<(), FingerprintError> {
        if self.peek() == Some(&Token::LeftParenthesis) {
            self.take();
            self.expression(comparisons)?;
            self.expect(Token::RightParenthesis)
        } else {
            let path = self.path()?;
            self.expect(Token::Equal)?;
            let value = self.string()?;
            comparisons.push((path, value));
            Ok(())
        }
    }

    fn path(&mut self) -> Result<String, FingerprintError> {
        let start = self.next;
        while !matches!(self.peek(), Some(Token::Equal) | None) {
            if matches!(
                self.peek(),
                Some(Token::LeftParenthesis | Token::RightParenthesis | Token::RightBracket)
            ) {
                return Err(self.error("missing equality operator in STIX pattern"));
            }
            self.next += 1;
        }
        let tokens = &self.tokens[start..self.next];
        let mut parts = Vec::new();
        for (position, (token, _)) in tokens.iter().enumerate() {
            match (position % 2, token) {
                (0, Token::Word(part) | Token::String(part)) => parts.push(part.as_str()),
                (1, Token::Colon | Token::Dot) => {}
                _ => return Err(self.error("invalid STIX object path")),
            }
        }
        if parts.is_empty() {
            return Err(self.error("missing STIX object path"));
        }
        Ok(parts.join(":"))
    }

    fn string(&mut self) -> Result<String, FingerprintError> {
        match self.take() {
            Some(Token::String(value)) => Ok(value),
            _ => Err(self.error("STIX comparison value must be a string")),
        }
    }

    fn error(&self, reason: &'static str) -> FingerprintError {
        FingerprintError::UnsupportedPattern {
            object: self.object,
            offset: self
                .tokens
                .get(self.next)
                .or_else(|| self.tokens.last())
                .map(|(_, offset)| *offset)
                .unwrap_or(0),
            reason,
        }
    }
}

fn tokenize(pattern: &str, object: usize) -> Result<Vec<(Token, usize)>, FingerprintError> {
    let mut characters = pattern.char_indices().peekable();
    let mut tokens = Vec::new();
    while let Some((offset, character)) = characters.next() {
        let token = match character {
            character if character.is_whitespace() => continue,
            '[' => Token::LeftBracket,
            ']' => Token::RightBracket,
            '(' => Token::LeftParenthesis,
            ')' => Token::RightParenthesis,
            ':' => Token::Colon,
            '.' => Token::Dot,
            '=' => Token::Equal,
            '\'' => Token::String(read_pattern_string(&mut characters, object, offset)?),
            character if character.is_alphanumeric() || character == '-' || character == '_' => {
                let mut word = String::from(character);
                while let Some((_, next)) = characters.peek() {
                    if next.is_alphanumeric() || *next == '-' || *next == '_' {
                        word.push(*next);
                        characters.next();
                    } else {
                        break;
                    }
                }
                Token::Word(word)
            }
            _ => {
                return Err(FingerprintError::UnsupportedPattern {
                    object,
                    offset,
                    reason: "unsupported character in STIX pattern",
                })
            }
        };
        tokens.push((token, offset));
    }
    Ok(tokens)
}

fn read_pattern_string(
    characters: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    object: usize,
    start: usize,
) -> Result<String, FingerprintError> {
    let mut value = String::new();
    while let Some((offset, character)) = characters.next() {
        match character {
            '\'' => return Ok(value),
            '\\' => match characters.next() {
                Some((_, '\\')) => value.push('\\'),
                Some((_, '\'')) => value.push('\''),
                _ => {
                    return Err(FingerprintError::UnsupportedPattern {
                        object,
                        offset,
                        reason: "unsupported escape in STIX string",
                    })
                }
            },
            _ => value.push(character),
        }
    }
    Err(FingerprintError::UnsupportedPattern {
        object,
        offset: start,
        reason: "unterminated string in STIX pattern",
    })
}

fn push_atom(atoms: &mut Vec<String>, kind: &str, value: String, revoked: bool) {
    let suffix = if revoked { "|revoked" } else { "" };
    atoms.push(format!("{}:{}{}", kind, value, suffix));
}

fn structured_digest_v1(atom: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ATOM_DOMAIN);
    hasher.update(atom.as_bytes());
    *hasher.finalize().as_bytes()
}

fn invalid_observable(object: usize, kind: &'static str, value: &str) -> FingerprintError {
    FingerprintError::InvalidObservable {
        object,
        kind,
        value: value.to_owned(),
    }
}

#[derive(Debug)]
pub enum FingerprintError {
    InvalidJson(serde_json::Error),
    MissingObjects,
    InvalidObject(usize),
    InvalidField {
        object: usize,
        field: &'static str,
    },
    InvalidObservable {
        object: usize,
        kind: &'static str,
        value: String,
    },
    UnsupportedObjectType {
        object: usize,
        object_type: String,
    },
    UnsupportedPattern {
        object: usize,
        offset: usize,
        reason: &'static str,
    },
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(error) => write!(formatter, "invalid STIX JSON: {}", error),
            Self::MissingObjects => formatter.write_str("STIX bundle has no objects array"),
            Self::InvalidObject(index) => {
                write!(formatter, "STIX object {} is not an object", index)
            }
            Self::InvalidField { object, field } => {
                write!(
                    formatter,
                    "STIX object {} has an invalid {} field",
                    object, field
                )
            }
            Self::InvalidObservable {
                object,
                kind,
                value,
            } => write!(
                formatter,
                "STIX object {} contains invalid {} value {:?}",
                object, kind, value
            ),
            Self::UnsupportedObjectType {
                object,
                object_type,
            } => write!(
                formatter,
                "STIX object {} has no CHORUS normalization rule for type {:?}",
                object, object_type
            ),
            Self::UnsupportedPattern {
                object,
                offset,
                reason,
            } => write!(
                formatter,
                "unsupported STIX pattern in object {} at byte {}: {}",
                object, offset, reason
            ),
        }
    }
}

impl Error for FingerprintError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidJson(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_order_and_duplicate_objects_do_not_change_fingerprints() {
        let first = br#"{"type":"bundle","objects":[
            {"type":"domain-name","value":"Example.COM.","description":"first report"},
            {"type":"ipv4-addr","value":"192.168.001.002"},
            {"type":"domain-name","value":"example.com"}
        ]}"#;
        let second = br#"{"type":"bundle","objects":[
            {"type":"ipv4-addr","value":"192.168.1.2","created":"2026-01-01"},
            {"type":"domain-name","value":"example.com","description":"other report"}
        ]}"#;
        assert_eq!(
            compute_atom_fingerprints(first).unwrap(),
            compute_atom_fingerprints(second).unwrap()
        );
    }

    #[test]
    fn relevant_value_change_changes_fingerprint() {
        let first = br#"{"objects":[{"type":"domain-name","value":"one.example"}]}"#;
        let second = br#"{"objects":[{"type":"domain-name","value":"two.example"}]}"#;
        assert_ne!(
            compute_atom_fingerprints(first).unwrap(),
            compute_atom_fingerprints(second).unwrap()
        );
    }

    #[test]
    fn revoked_status_changes_fingerprint() {
        let active = br#"{"objects":[{"type":"ipv6-addr","value":"2001:0db8:0:0:0:0:0:1"}]}"#;
        let revoked = br#"{"objects":[{"type":"ipv6-addr","value":"2001:db8::1","revoked":true}]}"#;
        assert_ne!(
            compute_atom_fingerprints(active).unwrap(),
            compute_atom_fingerprints(revoked).unwrap()
        );
    }

    #[test]
    fn malformed_observable_returns_an_error() {
        let bundle = br#"{"objects":[{"type":"ipv4-addr","value":"999.1.2.3"}]}"#;
        assert!(matches!(
            compute_atom_fingerprints(bundle),
            Err(FingerprintError::InvalidObservable {
                kind: "ipv4-addr",
                ..
            })
        ));
    }

    #[test]
    fn equivalent_urls_and_idn_domains_have_the_same_fingerprint() {
        let first = br#"{"objects":[{"type":"url","value":"HTTPS://XN--BCHER-KVA.EXAMPLE:443/a/%7Euser?b=2&a=1#part"}]}"#;
        let second =
            r#"{"objects":[{"type":"url","value":"https://bücher.example/a/~user?a=1&b=2"}]}"#;
        assert_eq!(
            compute_atom_fingerprints(first).unwrap(),
            compute_atom_fingerprints(second.as_bytes()).unwrap()
        );
    }

    #[test]
    fn empty_and_explicit_slash_url_paths_stay_distinct() {
        let empty = br#"{"objects":[{"type":"url","value":"https://example.com"}]}"#;
        let slash = br#"{"objects":[{"type":"url","value":"https://example.com/"}]}"#;
        assert_ne!(
            compute_atom_fingerprints(empty).unwrap(),
            compute_atom_fingerprints(slash).unwrap()
        );
    }

    #[test]
    fn indicator_and_direct_objects_produce_the_same_fingerprints() {
        let indicator = br#"{"objects":[{"type":"indicator","pattern_type":"stix","pattern":"[domain-name:value = 'Example.COM.' AND file:hashes.'SHA-256' = 'AA-BB']"}]}"#;
        let direct = br#"{"objects":[
            {"type":"domain-name","value":"example.com"},
            {"type":"file","hashes":{"SHA-256":"aabb"}}
        ]}"#;
        assert_eq!(
            compute_atom_fingerprints(indicator).unwrap(),
            compute_atom_fingerprints(direct).unwrap()
        );
    }

    #[test]
    fn unsupported_pattern_operator_returns_an_error() {
        let bundle = br#"{"objects":[{"type":"indicator","pattern":"[domain-name:value LIKE '%.example']"}]}"#;
        assert!(matches!(
            compute_atom_fingerprints(bundle),
            Err(FingerprintError::UnsupportedPattern { .. })
        ));
    }
}
