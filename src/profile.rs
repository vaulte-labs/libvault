//! A person's details for forms. All of it is secret: a list shows only the profile's own name,
//! and a page gets the details only through a fill a person approves.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Any field may be empty. Named for what a person reads; a browser maps a page's `autocomplete`
/// tokens onto them. Kept inside a `Secret`, which erases it on drop.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(default)]
pub struct Profile {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone: String,
    /// As `1990-04-21`.
    pub birth_date: String,
    pub address_line1: String,
    pub address_line2: String,
    pub city: String,
    /// A state, province or region.
    pub region: String,
    pub postal_code: String,
    /// Two capital letters, as `US` or `DE`.
    pub country: String,
}

/// Like `Secret`, never shows what it holds.
impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Profile(..)")
    }
}

impl Profile {
    fn fields(&self) -> [&str; 11] {
        [
            &self.first_name,
            &self.last_name,
            &self.email,
            &self.phone,
            &self.birth_date,
            &self.address_line1,
            &self.address_line2,
            &self.city,
            &self.region,
            &self.postal_code,
            &self.country,
        ]
    }

    /// Rejects details no form could take, so a fill never puts a typo on a page.
    pub(crate) fn check(&self) -> Result<()> {
        let given: Vec<&str> = self.fields().into_iter().filter(|field| !field.is_empty()).collect();
        if given.is_empty() {
            return Err(Error::Invalid("a profile needs at least one detail"));
        }
        given.into_iter().try_for_each(crate::item::validate_text)?;
        let wrong = |given: &str, right: fn(&str) -> bool| !given.is_empty() && !right(given);
        if wrong(&self.email, is_email) {
            return Err(Error::Invalid("an email address is a name, an @ and a domain"));
        }
        if wrong(&self.phone, is_phone) {
            return Err(Error::Invalid("a phone number is digits, with spaces and + - ( ) . at most"));
        }
        if wrong(&self.birth_date, is_date) {
            return Err(Error::Invalid("give the birth date as year-month-day, like 1990-04-21"));
        }
        if wrong(&self.country, |country| country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())) {
            return Err(Error::Invalid("give the country as two capital letters, like US"));
        }
        Ok(())
    }
}

fn is_email(email: &str) -> bool {
    let Some((name, domain)) = email.split_once('@') else { return false };
    !name.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.contains(char::is_whitespace)
}

fn is_phone(phone: &str) -> bool {
    phone.chars().all(|c| c.is_ascii_digit() || " +-().".contains(c)) && phone.chars().filter(char::is_ascii_digit).count() >= 3
}

fn is_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let number = |range: std::ops::Range<usize>| date.get(range)?.parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else { return false };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1..=12 => 31,
        _ => return false,
    };
    year >= 1900 && (1..=days).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jane() -> Profile {
        Profile {
            first_name: "Jane".into(),
            last_name: "Doe".into(),
            email: "jane@example.com".into(),
            phone: "+1 (555) 010-0199".into(),
            birth_date: "1990-04-21".into(),
            address_line1: "1 Main St".into(),
            city: "Springfield".into(),
            region: "IL".into(),
            postal_code: "62701".into(),
            country: "US".into(),
            ..Profile::default()
        }
    }

    #[test]
    fn a_whole_profile_and_a_partial_one_are_both_fine() {
        assert!(jane().check().is_ok());
        assert!(Profile { birth_date: "1990-01-31".into(), ..jane() }.check().is_ok());
        assert!(Profile { email: "a@b.co".into(), ..Profile::default() }.check().is_ok());
    }

    #[test]
    fn an_empty_profile_is_refused() {
        assert!(Profile::default().check().is_err());
    }

    #[test]
    fn details_no_form_would_take_are_refused() {
        let with = |change: fn(&mut Profile)| {
            let mut profile = jane();
            change(&mut profile);
            profile.check().is_err()
        };
        assert!(with(|p| p.email = "jane.example.com".into()));
        assert!(with(|p| p.email = "jane@localhost".into()));
        assert!(with(|p| p.email = "jane @example.com".into()));
        assert!(with(|p| p.phone = "call me".into()));
        assert!(with(|p| p.phone = "12".into()));
        assert!(with(|p| p.birth_date = "21/04/1990".into()));
        assert!(with(|p| p.birth_date = "2023-02-29".into()));
        assert!(with(|p| p.birth_date = "1990-13-01".into()));
        assert!(with(|p| p.birth_date = "1850-01-01".into()));
        assert!(with(|p| p.birth_date = "1990-04-31".into()));
        assert!(with(|p| p.birth_date = "1990-01-011".into()));
        assert!(with(|p| p.birth_date = "1990x01-01".into()));
        assert!(with(|p| p.birth_date = "1990-01x01".into()));
        assert!(with(|p| p.country = "us".into()));
        assert!(with(|p| p.country = "USA".into()));
        assert!(with(|p| p.city = "two\nlines".into()));
    }

    #[test]
    fn a_leap_day_is_a_birth_date() {
        assert!(Profile { birth_date: "2000-02-29".into(), ..Profile::default() }.check().is_ok());
        assert!(Profile { birth_date: "1900-02-29".into(), ..Profile::default() }.check().is_err());
    }
}
