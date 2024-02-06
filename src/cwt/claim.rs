use fmul_to_int::FloatMulToInt;
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use time::OffsetDateTime;

/// Representation of CWT claims, as defined in
/// [RFC8392](https://datatracker.ietf.org/doc/html/rfc8392).
pub trait Claim: Into<Value> + TryFrom<Value, Error = Error> {
    fn key() -> Key;
}

/// Representation of the CBOR map key used to identify a claim
/// within a CWT claims set, and restricted to text and integer values,
/// per [RFC8392](https://datatracker.ietf.org/doc/html/rfc8392).
pub enum Key {
    Text(String),
    Integer(i128),
}

impl From<Key> for Value {
    fn from(key: Key) -> Value {
        match key {
            Key::Text(k) => Value::Text(k),
            Key::Integer(k) => Value::Integer(k),
        }
    }
}

/// Errors that can occur when parsing values into claims.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("claim requires NumericDate (int or float)")]
    NumericDateRequired,
    #[error("claim requires Bytes value")]
    BytesValueRequired,
    #[error("conversion error: {0}")]
    ConversionError(#[from] serde_cbor::Error),
    #[error("TryFromIntError: {0}")]
    TryFromIntError(#[from] std::num::TryFromIntError),
    #[error("OffsetComponentError: {0}")]
    OffsetComponentError(#[from] time::error::ComponentRange),
    #[error("NumericDate conversion overflows")]
    ConversionOverflow,
}

/// Numerical representation of seconds relative to the Unix Epoch,
/// as defined in [RFC7049](https://www.rfc-editor.org/rfc/rfc7049#section-2.4.1)
/// with the leading tag 1 omitted.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(try_from = "Value", into = "Value")]
pub enum NumericDate {
    IntegerSeconds(i128),
    FractionalSeconds(f64),
}

impl From<NumericDate> for Value {
    fn from(value: NumericDate) -> Self {
        match value {
            NumericDate::IntegerSeconds(i) => Value::Integer(i),
            NumericDate::FractionalSeconds(f) => Value::Float(f),
        }
    }
}

impl TryFrom<Value> for NumericDate {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Integer(i) => Ok(NumericDate::IntegerSeconds(i)),
            Value::Float(f) => Ok(NumericDate::FractionalSeconds(f)),
            _ => Err(Error::NumericDateRequired),
        }
    }
}

const NANOS_PER_SECOND: u32 = 1_000_000_000;

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

/// Simple macro for defining generic claims with implementations of
/// the Claim and From<> for serde_cbor::Value traits.
/// Custom value_type's must implement From<value_type> for serde_cbor::Value.
macro_rules! define_claim {
    ($name:ident, $value_type: ty, $key: expr) => {
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        pub struct $name($value_type);
        impl $name {
            pub fn new(value: $value_type) -> $name {
                $name(value)
            }
        }

        impl Claim for $name {
            fn key() -> Key {
                $key
            }
        }

        impl From<$name> for Value {
            fn from(value: $name) -> Self {
                value.0.into()
            }
        }

        impl TryFrom<Value> for $name {
            type Error = Error;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                Ok(Self(serde_cbor::value::from_value(value)?))
            }
        }
    };
}

define_claim!(Issuer, String, Key::Integer(1));
define_claim!(Subject, String, Key::Integer(2));
define_claim!(Audience, String, Key::Integer(3));
define_claim!(ExpirationTime, NumericDate, Key::Integer(4));
define_claim!(NotBefore, NumericDate, Key::Integer(5));
define_claim!(IssuedAt, NumericDate, Key::Integer(6));

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(try_from = "Value", into = "Value")]
pub struct CWTId(Vec<u8>);
impl CWTId {
    pub fn new(value: Vec<u8>) -> CWTId {
        CWTId(value)
    }
}

impl Claim for CWTId {
    fn key() -> Key {
        Key::Integer(7)
    }
}

impl From<CWTId> for Value {
    fn from(value: CWTId) -> Self {
        value.0.into()
    }
}

impl TryFrom<Value> for CWTId {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Bytes(bytes) = value {
            Ok(CWTId(bytes))
        } else {
            Err(Error::BytesValueRequired)
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
