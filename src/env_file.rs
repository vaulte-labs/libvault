//! Parses `.env` files the way dotenv tools do: `export`, single and double quotes, escapes,
//! comments and multi-line quoted values.

use zeroize::Zeroizing;

/// One variable. Line numbers let errors point at a row without showing its contents.
#[derive(Debug, PartialEq, Eq)]
pub struct EnvVar {
    pub name: String,
    pub value: Zeroizing<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct EnvFile {
    pub vars: Vec<EnvVar>,
    pub unreadable_lines: Vec<usize>,
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Reads a quoted value starting after the opening quote, across lines if needed. Returns the
/// value and the number of lines consumed after the first.
fn quoted(lines: &[&str], start: &str, quote: char) -> Option<(String, usize)> {
    let mut value = String::new();
    let mut rest = start;
    let mut used = 0;
    loop {
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            if c == quote {
                return Some((value, used));
            }
            if c == '\\' && quote == '"' {
                match chars.next() {
                    Some('n') => value.push('\n'),
                    Some('r') => value.push('\r'),
                    Some('t') => value.push('\t'),
                    Some(other) => value.push(other),
                    None => {}
                }
            } else {
                value.push(c);
            }
        }
        used += 1;
        rest = lines.get(used)?;
        value.push('\n');
    }
}

fn unquoted(raw: &str) -> &str {
    let comment = raw.char_indices().find(|&(index, c)| c == '#' && (index == 0 || raw[..index].ends_with(char::is_whitespace)));
    comment.map_or(raw, |(index, _)| &raw[..index]).trim()
}

/// Parses a `.env` file. Lines that make no sense are reported by number, never by content.
pub fn parse(text: &str) -> EnvFile {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut file = EnvFile::default();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim_start();
        let number = index + 1;
        index += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let assignment = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((name, raw)) = assignment.split_once('=') else {
            file.unreadable_lines.push(number);
            continue;
        };
        let name = name.trim();
        if !valid_name(name) {
            file.unreadable_lines.push(number);
            continue;
        }
        let raw = raw.trim_start();
        let value = match raw.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                if let Some((value, used)) = quoted(&lines[index - 1..], &raw[1..], quote) {
                    index += used;
                    value
                } else {
                    file.unreadable_lines.push(number);
                    continue;
                }
            }
            _ => unquoted(raw).to_owned(),
        };
        file.vars.push(EnvVar { name: name.to_owned(), value: Zeroizing::new(value) });
    }
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(text: &str) -> Vec<(String, String)> {
        parse(text).vars.iter().map(|var| (var.name.clone(), var.value.to_string())).collect()
    }

    #[test]
    fn handles_the_forms_real_files_use() {
        let parsed = pairs("# comment\nPLAIN=value\nexport EXPORTED=yes\nSPACED = trimmed  \nEMPTY=\nCOMMENTED=value # note\nHASH=abc#def\n");
        let expected = [("PLAIN", "value"), ("EXPORTED", "yes"), ("SPACED", "trimmed"), ("EMPTY", ""), ("COMMENTED", "value"), ("HASH", "abc#def")];
        assert_eq!(parsed, expected.map(|(a, b)| (a.to_owned(), b.to_owned())));
    }

    #[test]
    fn quotes_and_escapes_follow_shell_rules() {
        assert_eq!(pairs(r#"A="line\nbreak""#)[0].1, "line\nbreak");
        assert_eq!(pairs(r"A='line\nraw'")[0].1, r"line\nraw");
        assert_eq!(pairs(r#"A="has # hash""#)[0].1, "has # hash");
        assert_eq!(pairs(r#"A="quote \" inside""#)[0].1, "quote \" inside");
    }

    #[test]
    fn a_quoted_value_can_span_lines() {
        let parsed = pairs("KEY=\"-----BEGIN\nabc\n-----END\"\nNEXT=1\n");
        assert_eq!(parsed[0].1, "-----BEGIN\nabc\n-----END");
        assert_eq!(parsed[1].0, "NEXT");
    }

    #[test]
    fn a_bom_does_not_break_the_first_name() {
        assert_eq!(pairs("\u{feff}FIRST=1")[0].0, "FIRST");
    }

    #[test]
    fn bad_lines_are_reported_by_number_and_the_rest_still_parse() {
        let parsed = parse("GOOD=1\nnot an assignment\n1BAD=2\nALSO_GOOD=3\nOPEN=\"never closed\n");
        assert_eq!(parsed.vars.len(), 2);
        assert_eq!(parsed.unreadable_lines, [2, 3, 5]);
    }
}
