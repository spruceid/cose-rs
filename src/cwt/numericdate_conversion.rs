use crate::cwt::NumericDate;
use fmul_to_int::FloatMulToInt;
use time::OffsetDateTime;

const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Errors that can occur when converting between
/// OffsetDateTime and NumericDate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TryFromIntError: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error("OffsetComponentError: {0}")]
    OffsetComponent(#[from] time::error::ComponentRange),
    #[error("NumericDate conversion overflows")]
    ConversionOverflow,
}

impl TryFrom<NumericDate> for OffsetDateTime {
    type Error = Error;

    /// For IntegerSeconds: Attempts to downcast from i128 -> 164,
    /// before converting to UNIX timestamp.
    /// For FractionalSeconds: truncates to (max) 9 decimal places.
    fn try_from(value: NumericDate) -> Result<Self, Self::Error> {
        match value {
            NumericDate::IntegerSeconds(i) => {
                let i: i64 = i.try_into()?;
                Ok(OffsetDateTime::from_unix_timestamp(i)?)
            }
            NumericDate::FractionalSeconds(f) => {
                if f.is_finite() {
                    // Compute this in nanoseconds to avoid manually reimplementing logic
                    // of negative signs before/after UNIX epoch.
                    if let Ok(nanos) = f.mul_to_int(NANOS_PER_SECOND as f64) {
                        return Ok(OffsetDateTime::from_unix_timestamp_nanos(nanos)?);
                    }
                }
                Err(Error::ConversionOverflow)
            }
        }
    }
}

impl TryFrom<OffsetDateTime> for NumericDate {
    type Error = Error;
    /// To IntegerSeconds: lossless conversion.
    /// To FractionalSeconds: computes the f64 from the seconds
    /// and then converts nanoseconds into a decimal.
    /// May return an error if too many nanoseconds are returned by OffsetDateTime,
    /// but that should not happen according to OffsetDateTime's docs.
    fn try_from(value: OffsetDateTime) -> Result<Self, Self::Error> {
        match value.nanosecond() {
            0 => Ok(NumericDate::IntegerSeconds(value.unix_timestamp().into())),
            nanos => {
                // Expected by OffsetDateTime docs
                if nanos >= NANOS_PER_SECOND {
                    return Err(Error::ConversionOverflow);
                }
                // Values through year 9999 (max handled by OffsetDateTime) fit completely into f64
                let mut seconds = value.unix_timestamp() as f64;
                seconds += (nanos as f64) / (NANOS_PER_SECOND as f64);
                Ok(NumericDate::FractionalSeconds(seconds))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use time::{Date, Duration, Month, Time};

    fn success_conversion_cases() -> Vec<(&'static str, OffsetDateTime, NumericDate, Duration)> {
        vec![
            (
                "max OffsetDateTime without nanos",
                OffsetDateTime::new_utc(Date::MAX, Time::from_hms(23, 59, 59).unwrap()),
                NumericDate::IntegerSeconds(253402300799),
                Duration::new(0, 0),
            ),
            // N.B. This case is ignored for conversion into datetime,
            // see note below
            (
                "max OffsetDateTime with nanos",
                OffsetDateTime::new_utc(
                    Date::MAX,
                    Time::from_hms_nano(23, 59, 59, 999_999_999).unwrap(),
                ),
                NumericDate::FractionalSeconds(253402300799.999999999),
                Duration::new(0, 1000),
            ),
            (
                "max OffsetDateTime (15 sig figs) with nanos",
                OffsetDateTime::new_utc(
                    Date::MAX,
                    Time::from_hms_nano(23, 59, 59, 999_000_000).unwrap(),
                ),
                NumericDate::FractionalSeconds(253402300799.999),
                Duration::new(0, 10000000),
            ),
            (
                "min OffsetDateTime without nanos",
                OffsetDateTime::new_utc(Date::MIN, Time::from_hms(0, 0, 0).unwrap()),
                NumericDate::IntegerSeconds(-377705116800),
                Duration::new(0, 0),
            ),
            (
                "min OffsetDateTime with 1 nano",
                OffsetDateTime::new_utc(Date::MIN, Time::from_hms_nano(0, 0, 0, 1).unwrap()),
                NumericDate::FractionalSeconds(-377705116799.99999999),
                Duration::new(0, 100000),
            ),
            (
                "min OffsetDateTime with 1 nano (15 sig figs)",
                OffsetDateTime::new_utc(
                    Date::MIN,
                    Time::from_hms_nano(0, 0, 0, 1_000_000).unwrap(),
                ),
                NumericDate::FractionalSeconds(-377705116799.999),
                Duration::new(0, 100000),
            ),
            (
                "UNIX epoch",
                OffsetDateTime::UNIX_EPOCH,
                NumericDate::IntegerSeconds(0),
                Duration::new(0, 0),
            ),
            (
                "normal date close to UNIX epoch with nanos",
                OffsetDateTime::new_utc(
                    Date::from_calendar_date(1970, Month::January, 1).unwrap(),
                    Time::from_hms_nano(0, 0, 10, 987654321).unwrap(),
                ),
                NumericDate::FractionalSeconds(10.987654321),
                Duration::new(0, 0),
            ),
            (
                "normal date (+) without nanos",
                OffsetDateTime::new_utc(
                    Date::from_calendar_date(2024, Month::March, 10).unwrap(),
                    Time::from_hms(16, 40, 32).unwrap(),
                ),
                NumericDate::IntegerSeconds(1710088832),
                Duration::new(0, 0),
            ),
            (
                "normal date (-) without",
                OffsetDateTime::new_utc(
                    Date::from_calendar_date(1960, Month::June, 24).unwrap(),
                    Time::from_hms(7, 14, 34).unwrap(),
                ),
                NumericDate::IntegerSeconds(-300473126),
                Duration::new(0, 0),
            ),
            (
                "normal date (+) with nanos",
                OffsetDateTime::new_utc(
                    Date::from_calendar_date(2024, Month::March, 10).unwrap(),
                    Time::from_hms_nano(16, 40, 32, 235_432_100).unwrap(),
                ),
                NumericDate::FractionalSeconds(1710088832.2354321),
                Duration::new(0, 10000),
            ),
            (
                "normal date (+) with nanos & f significand = 2^54",
                OffsetDateTime::new_utc(
                    Date::from_calendar_date(1970, Month::July, 28).unwrap(),
                    Time::from_hms_nano(11, 59, 58, 509481984).unwrap(),
                ),
                NumericDate::FractionalSeconds(18014398.509481984),
                Duration::new(0, 1000),
            ),
            (
                "normal date (-) with nanos",
                OffsetDateTime::new_utc(
                    Date::from_calendar_date(1960, Month::June, 24).unwrap(),
                    Time::from_hms_nano(7, 14, 34, 800_000_000).unwrap(),
                ),
                NumericDate::FractionalSeconds(-300473125.2),
                Duration::new(0, 100),
            ),
        ]
    }

    #[test]
    fn offset_to_numeric_date() {
        for (case, odt, expected_nd, _) in success_conversion_cases() {
            let nd: NumericDate = odt
                .try_into()
                .unwrap_or_else(|_| panic!("failed to convert {}", case));
            assert_eq!(nd, expected_nd, "case: {}", case);
        }
    }

    #[test]
    fn numeric_date_to_offset() {
        let ignore_cases = [
            // This case is ignored because the full float value gets rounded up
            // before the datetime conversion occurs (due to floating point imprecision
            // above 15 significant figures), causing the value to be too large (out of range).
            // Instead, this case is still covered by an almost identical case
            // ("max OffsetDateTime (15 sig figs) with nanos") which limits the
            // float value to 15 digits and then rounds down the nanos
            "max OffsetDateTime with nanos",
        ];

        for (case, expected_odt, nd, epsilon) in success_conversion_cases() {
            if ignore_cases.contains(&case) {
                println!("skipping case: {case}");
                continue;
            }
            let odt: OffsetDateTime = nd
                .clone()
                .try_into()
                .unwrap_or_else(|_| panic!("failed to convert {}", case));
            match nd {
                NumericDate::IntegerSeconds(_) => {
                    assert_eq!(odt, expected_odt, "case: {}", case);
                }
                NumericDate::FractionalSeconds(_) => {
                    let difference: Duration = (expected_odt - odt).abs();
                    assert!(
                        difference <= epsilon,
                        "comparison failure case: {}\ndifference: {}\nexpected: {}\nactual: {}",
                        case,
                        difference,
                        expected_odt,
                        odt
                    );
                }
            }
        }
    }

    #[test]
    fn numeric_date_to_offset_fails() {
        let cases = [
            ("i128 max", NumericDate::IntegerSeconds(std::i128::MAX)),
            ("i128 min", NumericDate::IntegerSeconds(std::i128::MIN)),
            ("f64 max", NumericDate::FractionalSeconds(std::f64::MAX)),
            ("f64 min", NumericDate::FractionalSeconds(std::f64::MIN)),
            (
                "f64 inf",
                NumericDate::FractionalSeconds(std::f64::INFINITY),
            ),
            (
                "f64 -inf",
                NumericDate::FractionalSeconds(std::f64::NEG_INFINITY),
            ),
        ];
        for (case, nd) in cases {
            <NumericDate as std::convert::TryInto<OffsetDateTime>>::try_into(nd)
                .expect_err(&format!("undefined behavior for case {case}"));
        }
    }
}
