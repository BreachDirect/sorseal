//! Minimal RFC 3339 (UTC) formatting from Unix seconds — no date-time
//! dependency, so the dependency tree stays small and audit-friendly.

/// Now as an RFC 3339 UTC timestamp, e.g. `2026-08-05T20:00:00Z`.
pub fn now_rfc3339_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc_rfc3339(secs)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` in UTC.
pub fn utc_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since 1970-01-01 to a civil (year, month, day) date.
/// Standard `civil_from_days` algorithm (Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_epoch() {
        assert_eq!(utc_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(utc_rfc3339(1_600_000_000), "2020-09-13T12:26:40Z");
    }

    #[test]
    fn leap_day_is_correct() {
        assert_eq!(utc_rfc3339(1_583_020_800), "2020-03-01T00:00:00Z");
    }
}
