//! When cards run out. A card is good through the last day of the month printed on it.

/// How close to running out a card has to be for anyone to be told.
const WARNING_MONTHS: i64 = 2;
const SECONDS_PER_DAY: u64 = 86_400;

/// Turns what is printed on a card, such as `12/30` or `12/2030`, into `2030-12`.
pub(crate) fn normalized(printed: &str) -> Option<String> {
    let (month, year) = printed.trim().split_once(['/', '-'])?;
    let (month, year) = (month.trim().parse::<u32>().ok()?, year.trim());
    let digits = year.len();
    let year = year.parse::<u32>().ok()?;
    let year = match digits {
        2 => 2000 + year,
        4 => year,
        _ => return None,
    };
    (1..=12).contains(&month).then(|| format!("{year}-{month:02}"))
}

fn months_since_zero(year: i64, month: i64) -> i64 {
    year * 12 + month
}

fn stored_month(expires: &str) -> Option<i64> {
    let (year, month) = expires.split_once('-')?;
    Some(months_since_zero(year.parse().ok()?, month.parse().ok()?))
}

/// The calendar month of a moment, from days since 1970. Howard Hinnant's `civil_from_days`.
fn month_of(unix_seconds: u64) -> i64 {
    let days = i64::try_from(unix_seconds / SECONDS_PER_DAY).unwrap_or(i64::MAX / 2) + 719_468;
    let era = days / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    months_since_zero(year, month)
}

/// Whether a card has run out, or will within the warning. An `expires` that cannot be read says
/// nothing, because a warning about nothing teaches people to ignore the real ones.
pub(crate) fn runs_out_soon(expires: &str, unix_seconds: u64) -> bool {
    stored_month(expires).is_some_and(|month| month - month_of(unix_seconds) <= WARNING_MONTHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-02, and the first and last seconds of months either side.
    const NOW: u64 = 1_793_577_600;
    const FEB_29_2024: u64 = 1_709_164_800;
    const LAST_SECOND_OF_2025: u64 = 1_767_225_599;
    const FIRST_SECOND_OF_2026: u64 = 1_767_225_600;

    #[test]
    fn printed_dates_are_understood() {
        for printed in ["12/30", "12/2030", "12-30", " 12 / 30 ", "12-2030"] {
            assert_eq!(normalized(printed).as_deref(), Some("2030-12"), "{printed}");
        }
        assert_eq!(normalized("1/30").as_deref(), Some("2030-01"));
    }

    #[test]
    fn anything_else_is_not_a_date() {
        for printed in ["", "12", "13/30", "00/30", "12/3", "12/203", "12/20300", "ab/30", "12/ab", "1230"] {
            assert_eq!(normalized(printed), None, "{printed}");
        }
    }

    #[test]
    fn months_come_from_the_calendar() {
        assert_eq!(month_of(NOW), months_since_zero(2026, 11));
        assert_eq!(month_of(FEB_29_2024), months_since_zero(2024, 2));
        assert_eq!(month_of(LAST_SECOND_OF_2025), months_since_zero(2025, 12));
        assert_eq!(month_of(FIRST_SECOND_OF_2026), months_since_zero(2026, 1));
        assert_eq!(month_of(0), months_since_zero(1970, 1));
    }

    #[test]
    fn a_warning_covers_this_month_the_next_two_and_the_past() {
        assert!(runs_out_soon("2026-10", NOW), "already run out");
        assert!(runs_out_soon("2026-11", NOW));
        assert!(runs_out_soon("2027-01", NOW), "two months out");
        assert!(!runs_out_soon("2027-02", NOW));
        assert!(!runs_out_soon("2030-12", NOW));
    }

    #[test]
    fn an_unreadable_date_warns_of_nothing() {
        assert!(!runs_out_soon("soon", NOW));
        assert!(!runs_out_soon("", NOW));
    }
}
