//! Reads Apple Passwords exports. Rows are held in erasing strings, and errors point at row
//! numbers so a bad file never prints a password to a terminal or log.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::env_file::parse as parse_env_file;
use crate::ids::SpaceId;
use crate::item::{Kind, Meta, Secret, printable};
use crate::vault::Vault;
use crate::{Error, Result};

/// A file read into memory, ready to preview. Nothing has touched the vault.
#[derive(Debug)]
pub struct ImportFile {
    pub items: Vec<(Meta, Secret)>,
    pub unreadable: Vec<usize>,
}

impl ImportFile {
    /// Reads a `.csv` as an Apple Passwords export, and anything else as a `.env` file.
    pub fn read(path: &Path) -> Result<Self> {
        let text = String::from_utf8(std::fs::read(path)?).map_err(|_| Error::Unreadable("that file is not UTF-8 text".to_owned()))?;
        if path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("csv")) {
            let parsed = parse_apple_passwords(&text);
            if parsed.logins.is_empty() && parsed.unreadable_rows.is_empty() {
                // Not the columns themselves: a file with no header has someone's password here.
                return Err(Error::Unreadable(format!(
                    "this is not an Apple Passwords export. It has {} columns, and not the ones expected",
                    parsed.columns.len()
                )));
            }
            let items = parsed.logins.into_iter().map(|login| (login.meta, login.secret)).collect();
            return Ok(Self { items, unreadable: parsed.unreadable_rows });
        }
        let parsed = parse_env_file(&text);
        let items = parsed.vars.iter().map(|var| (Meta::env(var.name.clone()), Secret::Env { value: var.value.to_string() })).collect();
        Ok(Self { items, unreadable: parsed.unreadable_lines })
    }
}

/// What an import did. Identical items are skipped, and a clashing name gets a suffix, so an
/// import can never overwrite anything.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imported {
    pub added: usize,
    pub skipped: usize,
    pub renamed: usize,
}

impl Vault {
    /// Adds items as one batch, so one `undo` removes them all.
    pub fn import(&mut self, space: &SpaceId, items: Vec<(Meta, Secret)>) -> Result<Imported> {
        let mut existing = Vec::new();
        for item in self.items(space)? {
            if let Ok(secret) = self.secret(space, &item.id) {
                existing.push((item.meta.name, secret));
            }
        }
        let mut imported = Imported::default();
        let mut fresh: Vec<(Meta, Secret)> = Vec::with_capacity(items.len());
        for (mut meta, secret) in items {
            let same = |(name, value): &(String, Secret)| *name == meta.name && *value == secret;
            if existing.iter().any(same) || fresh.iter().any(|(other, value)| other.name == meta.name && *value == secret) {
                imported.skipped += 1;
                continue;
            }
            let base = meta.name.clone();
            let mut suffix = 1;
            while existing.iter().any(|(name, _)| *name == meta.name) || fresh.iter().any(|(other, _)| other.name == meta.name) {
                suffix += 1;
                // A variable's name has to stay one a shell can use.
                meta.name = if meta.kind == Kind::Env { format!("{base}_{suffix}") } else { format!("{base} {suffix}") };
            }
            imported.renamed += usize::from(suffix > 1);
            fresh.push((meta, secret));
        }
        imported.added = fresh.len();
        if !fresh.is_empty() {
            self.add_many(space, &fresh)?;
        }
        Ok(imported)
    }
}

/// One login from the export.
#[derive(Debug)]
pub struct AppleLogin {
    pub meta: Meta,
    pub secret: Secret,
}

#[derive(Debug, Default)]
pub struct ApplePasswords {
    pub logins: Vec<AppleLogin>,
    pub unreadable_rows: Vec<usize>,
    /// Column names, for "unknown format" errors. Headers hold no secrets.
    pub columns: Vec<String>,
}

/// Splits CSV into rows of fields per RFC 4180, including quoted newlines.
fn rows(text: &str) -> Vec<Vec<Zeroizing<String>>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::replace(&mut field, Zeroizing::new(String::new()))),
            (false, '\n') => {
                row.push(std::mem::replace(&mut field, Zeroizing::new(String::new())));
                rows.push(std::mem::take(&mut row));
            }
            (false, '\r') => {}
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Parses the CSV from Passwords, File, Export. Returns no logins for an unknown format, with
/// `columns` set so the caller can say what it found instead.
pub(crate) fn parse_apple_passwords(text: &str) -> ApplePasswords {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = rows(text).into_iter();
    let Some(header) = rows.next() else { return ApplePasswords::default() };
    let columns: Vec<String> = header.iter().map(|field| field.trim().to_owned()).collect();
    let column = |name: &str| columns.iter().position(|column| column.eq_ignore_ascii_case(name));

    let mut parsed = ApplePasswords::default();
    let (Some(title), Some(url), Some(username), Some(password)) = (column("Title"), column("URL"), column("Username"), column("Password")) else {
        parsed.columns = columns;
        return parsed;
    };
    let otp = column("OTPAuth");

    for (index, row) in rows.enumerate() {
        // The header is row 1.
        let number = index + 2;
        if row.len() != columns.len() {
            parsed.unreadable_rows.push(number);
            continue;
        }
        if row[password].is_empty() {
            parsed.unreadable_rows.push(number);
            continue;
        }
        let name = printable(if row[title].is_empty() { &row[url] } else { &row[title] });
        let mut meta = Meta::new(Kind::Login, name);
        meta.username = Some(printable(&row[username])).filter(|username| !username.is_empty());
        if !row[url].is_empty() {
            meta.urls.push(printable(&row[url]));
        }
        let totp = otp.map(|index| row[index].to_string()).filter(|code| !code.is_empty());
        parsed.logins.push(AppleLogin { meta, secret: Secret::Login { password: row[password].to_string(), totp } });
    }
    parsed.columns = columns;
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Title,URL,Username,Password,Notes,OTPAuth\n";

    #[test]
    fn reads_a_login_with_two_factor() {
        let csv = format!("{HEADER}GitHub,https://github.com,me,hunter2,,otpauth://totp/x?secret=ABC\n");
        let parsed = parse_apple_passwords(&csv);
        assert_eq!(parsed.logins.len(), 1);
        let login = &parsed.logins[0];
        assert_eq!(login.meta.name, "GitHub");
        assert_eq!(login.meta.username.as_deref(), Some("me"));
        assert_eq!(login.meta.urls, ["https://github.com"]);
        assert_eq!(login.secret, Secret::Login { password: "hunter2".to_owned(), totp: Some("otpauth://totp/x?secret=ABC".to_owned()) });
    }

    #[test]
    fn quoted_fields_keep_commas_quotes_and_newlines() {
        let csv = format!("{HEADER}\"Bank, Inc\",https://bank.com,me,\"pa\"\"ss,word\",\"two\nlines\",\n");
        let parsed = parse_apple_passwords(&csv);
        assert_eq!(parsed.logins[0].meta.name, "Bank, Inc");
        assert_eq!(parsed.logins[0].secret, Secret::Login { password: "pa\"ss,word".to_owned(), totp: None });
    }

    #[test]
    fn a_bad_row_is_named_and_does_not_stop_the_rest() {
        let csv = format!("{HEADER}Good,https://a.com,u,p,,\nshort,row\nNoPassword,https://b.com,u,,,\nAlsoGood,https://c.com,u,p,,\n");
        let parsed = parse_apple_passwords(&csv);
        assert_eq!(parsed.logins.len(), 2);
        assert_eq!(parsed.unreadable_rows, [3, 4]);
    }

    #[test]
    fn an_unknown_format_reports_its_columns_and_reads_nothing() {
        let parsed = parse_apple_passwords("site,login\na,b\n");
        assert!(parsed.logins.is_empty());
        assert_eq!(parsed.columns, ["site", "login"]);
    }
}
