use crate::header_map::Header;
use serde_cbor::Value;
use std::convert::TryFrom;
use std::fmt;

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> Algorithm;
}

/// COSE algorithms from the
/// [IANA COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub enum Algorithm {
    RS1,
    WalnutDSA,
    RS512,
    RS384,
    RS256,
    ES256K,
    HSS_LMS,
    SHAKE256,
    SHA_512,
    SHA_384,
    RSAES_OAEP_512,
    RSAES_OAEP_256,
    RSAES_OAEP_1,
    PS512,
    PS384,
    PS256,
    ES512,
    ES384,
    ECDH_SS_A256KW,
    ECDH_SS_A192KW,
    ECDH_SS_A128KW,
    ECDH_ES_A256KW,
    ECDH_ES_A192KW,
    ECDH_ES_A128KW,
    ECDH_SS_HKDF_512,
    ECDH_SS_HKDF_256,
    ECDH_ES_HKDF_512,
    ECDH_ES_HKDF_256,
    SHAKE128,
    SHA_512_256,
    SHA_256,
    SHA_256_64,
    SHA_1,
    Direct_HKDF_AES_256,
    Direct_HKDF_AES_128,
    Direct_HKDF_SHA_512,
    Direct_HKDF_SHA_256,
    EdDSA,
    ES256,
    Direct,
    A256KW,
    A192KW,
    A128KW,
    A128GCM,
    A192GCM,
    A256GCM,
    HMAC_256_64,
    HMAC_256_256,
    HMAC_384_384,
    HMAC_512_512,
    AES_CCM_16_64_128,
    AES_CCM_16_64_256,
    AES_CCM_64_64_128,
    AES_CCM_64_64_256,
    AES_MAC_128_64,
    AES_MAC_256_64,
    ChaCha20_Poly1305,
    AES_MAC_128_128,
    AES_MAC_256_128,
    AES_CCM_16_128_128,
    AES_CCM_16_128_256,
    AES_CCM_64_128_128,
    AES_CCM_64_128_256,
    IV_Generation,
}

impl Algorithm {
    /// Name of the algorithm according to the IANA COSE Algorithms registry.
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::RS1 => "RS1",
            Algorithm::WalnutDSA => "WalnutDSA",
            Algorithm::RS512 => "RS512",
            Algorithm::RS384 => "RS384",
            Algorithm::RS256 => "RS256",
            Algorithm::ES256K => "ES256K",
            Algorithm::HSS_LMS => "HSS-LMS",
            Algorithm::SHAKE256 => "SHAKE256",
            Algorithm::SHA_512 => "SHA-512",
            Algorithm::SHA_384 => "SHA-384",
            Algorithm::RSAES_OAEP_512 => "RSAES-OAEP w/ SHA-512",
            Algorithm::RSAES_OAEP_256 => "RSAES-OAEP w/ SHA-256",
            Algorithm::RSAES_OAEP_1 => "RSAES-OAEP w/ RFC 8017 default parameters",
            Algorithm::PS512 => "PS512",
            Algorithm::PS384 => "PS384",
            Algorithm::PS256 => "PS256",
            Algorithm::ES512 => "ES512",
            Algorithm::ES384 => "ES384",
            Algorithm::ECDH_SS_A256KW => "ECDH-SS + A256KW",
            Algorithm::ECDH_SS_A192KW => "ECDH-SS + A192KW",
            Algorithm::ECDH_SS_A128KW => "ECDH-SS + A128KW",
            Algorithm::ECDH_ES_A256KW => "ECDH-ES + A256KW",
            Algorithm::ECDH_ES_A192KW => "ECDH-ES + A192KW",
            Algorithm::ECDH_ES_A128KW => "ECDH-ES + A128KW",
            Algorithm::ECDH_SS_HKDF_512 => "ECDH-SS + HKDF-512",
            Algorithm::ECDH_SS_HKDF_256 => "ECDH-SS + HKDF-256",
            Algorithm::ECDH_ES_HKDF_512 => "ECDH-ES + HKDF-512",
            Algorithm::ECDH_ES_HKDF_256 => "ECDH-ES + HKDF-256",
            Algorithm::SHAKE128 => "SHAKE128",
            Algorithm::SHA_512_256 => "SHA-512/256",
            Algorithm::SHA_256 => "SHA-256",
            Algorithm::SHA_256_64 => "SHA-256/64",
            Algorithm::SHA_1 => "SHA-1",
            Algorithm::Direct_HKDF_AES_256 => "Direct+HKDF-AES-256",
            Algorithm::Direct_HKDF_AES_128 => "Direct+HKDF-AES-128",
            Algorithm::Direct_HKDF_SHA_512 => "Direct+HKDF-SHA-512",
            Algorithm::Direct_HKDF_SHA_256 => "Direct+HKDF-SHA-256",
            Algorithm::EdDSA => "EdDSA",
            Algorithm::ES256 => "ES256",
            Algorithm::Direct => "Direct",
            Algorithm::A256KW => "A256KW",
            Algorithm::A192KW => "A192KW",
            Algorithm::A128KW => "A128KW",
            Algorithm::A128GCM => "A128GCM",
            Algorithm::A192GCM => "A192GCM",
            Algorithm::A256GCM => "A256GCM",
            Algorithm::HMAC_256_64 => "HMAC 256/64",
            Algorithm::HMAC_256_256 => "HMAC 256/256",
            Algorithm::HMAC_384_384 => "HMAC 384/384",
            Algorithm::HMAC_512_512 => "HMAC 512/512",
            Algorithm::AES_CCM_16_64_128 => "AES-CCM-16-64-128",
            Algorithm::AES_CCM_16_64_256 => "AES-CCM-16-64-256",
            Algorithm::AES_CCM_64_64_128 => "AES-CCM-64-64-128",
            Algorithm::AES_CCM_64_64_256 => "AES-CCM-64-64-256",
            Algorithm::AES_MAC_128_64 => "AES-MAC 128/64",
            Algorithm::AES_MAC_256_64 => "AES-MAC 256/64",
            Algorithm::ChaCha20_Poly1305 => "ChaCha20/Poly1305",
            Algorithm::AES_MAC_128_128 => "AES-MAC 128/128",
            Algorithm::AES_MAC_256_128 => "AES-MAC 256/128",
            Algorithm::AES_CCM_16_128_128 => "AES-CCM-16-128-128",
            Algorithm::AES_CCM_16_128_256 => "AES-CCM-16-128-256",
            Algorithm::AES_CCM_64_128_128 => "AES-CCM-64-128-128",
            Algorithm::AES_CCM_64_128_256 => "AES-CCM-64-128-256",
            Algorithm::IV_Generation => "IV-GENERATION",
        }
    }

    /// Description of the algorithm according to the IANA COSE Algorithms registry.
    pub fn description(&self) -> &'static str {
        match self {
            Algorithm::RS1 => "RSASSA-PKCS1-v1_5 using SHA-1",
            Algorithm::WalnutDSA => "WalnutDSA signature",
            Algorithm::RS512 => "RSASSA-PKCS1-v1_5 using SHA-512",
            Algorithm::RS384 => "RSASSA-PKCS1-v1_5 using SHA-384",
            Algorithm::RS256 => "RSASSA-PKCS1-v1_5 using SHA-256",
            Algorithm::ES256K => "ECDSA using secp256k1 curve and SHA-256",
            Algorithm::HSS_LMS => "HSS/LMS hash-based digital signature",
            Algorithm::SHAKE256 => "SHAKE-256 512-bit Hash Value",
            Algorithm::SHA_512 => "SHA-2 512-bit Hash",
            Algorithm::SHA_384 => "SHA-2 384-bit Hash",
            Algorithm::RSAES_OAEP_512 => "RSAES-OAEP w/ SHA-512",
            Algorithm::RSAES_OAEP_256 => "RSAES-OAEP w/ SHA-256",
            Algorithm::RSAES_OAEP_1 => "RSAES-OAEP w/ SHA-1",
            Algorithm::PS512 => "RSASSA-PSS w/ SHA-512",
            Algorithm::PS384 => "RSASSA-PSS w/ SHA-384",
            Algorithm::PS256 => "RSASSA-PSS w/ SHA-256",
            Algorithm::ES512 => "ECDSA w/ SHA-512",
            Algorithm::ES384 => "ECDSA w/ SHA-384",
            Algorithm::ECDH_SS_A256KW => "ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key",
            Algorithm::ECDH_SS_A192KW => "ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key",
            Algorithm::ECDH_SS_A128KW => "ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key",
            Algorithm::ECDH_ES_A256KW => "ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key",
            Algorithm::ECDH_ES_A192KW => "ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key",
            Algorithm::ECDH_ES_A128KW => "ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key",
            Algorithm::ECDH_SS_HKDF_512 => "ECDH SS w/ HKDF - generate key Directly",
            Algorithm::ECDH_SS_HKDF_256 => "ECDH SS w/ HKDF - generate key Directly",
            Algorithm::ECDH_ES_HKDF_512 => "ECDH ES w/ HKDF - generate key Directly",
            Algorithm::ECDH_ES_HKDF_256 => "ECDH ES w/ HKDF - generate key Directly",
            Algorithm::SHAKE128 => "SHAKE-128 256-bit Hash Value",
            Algorithm::SHA_512_256 => "SHA-2 512-bit Hash truncated to 256-bits",
            Algorithm::SHA_256 => "SHA-2 256-bit Hash",
            Algorithm::SHA_256_64 => "SHA-2 256-bit Hash truncated to 64-bits",
            Algorithm::SHA_1 => "SHA-1 Hash",
            Algorithm::Direct_HKDF_AES_256 => "Shared secret w/ AES-MAC 256-bit key",
            Algorithm::Direct_HKDF_AES_128 => "Shared secret w/ AES-MAC 128-bit key",
            Algorithm::Direct_HKDF_SHA_512 => "Shared secret w/ HKDF and SHA-512",
            Algorithm::Direct_HKDF_SHA_256 => "Shared secret w/ HKDF and SHA-256",
            Algorithm::EdDSA => "EdDSA",
            Algorithm::ES256 => "ECDSA w/ SHA-256",
            Algorithm::Direct => "Direct use of CEK",
            Algorithm::A256KW => "AES Key Wrap w/ 256-bit key",
            Algorithm::A192KW => "AES Key Wrap w/ 192-bit key",
            Algorithm::A128KW => "AES Key Wrap w/ 128-bit key",
            Algorithm::A128GCM => "AES-GCM mode w/ 128-bit key, 128-bit tag",
            Algorithm::A192GCM => "AES-GCM mode w/ 192-bit key, 128-bit tag",
            Algorithm::A256GCM => "AES-GCM mode w/ 256-bit key, 128-bit tag",
            Algorithm::HMAC_256_64 => "HMAC w/ SHA-256 truncated to 64 bits",
            Algorithm::HMAC_256_256 => "HMAC w/ SHA-256",
            Algorithm::HMAC_384_384 => "HMAC w/ SHA-384",
            Algorithm::HMAC_512_512 => "HMAC w/ SHA-512",
            Algorithm::AES_CCM_16_64_128 => "AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce",
            Algorithm::AES_CCM_16_64_256 => "AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce",
            Algorithm::AES_CCM_64_64_128 => "AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce",
            Algorithm::AES_CCM_64_64_256 => "AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce",
            Algorithm::AES_MAC_128_64 => "AES-MAC 128-bit key, 64-bit tag",
            Algorithm::AES_MAC_256_64 => "AES-MAC 256-bit key, 64-bit tag",
            Algorithm::ChaCha20_Poly1305 => "ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag",
            Algorithm::AES_MAC_128_128 => "AES-MAC 128-bit key, 128-bit tag",
            Algorithm::AES_MAC_256_128 => "AES-MAC 256-bit key, 128-bit tag",
            Algorithm::AES_CCM_16_128_128 => "AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce",
            Algorithm::AES_CCM_16_128_256 => "AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce",
            Algorithm::AES_CCM_64_128_128 => "AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce",
            Algorithm::AES_CCM_64_128_256 => "AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce",
            Algorithm::IV_Generation => "For doing IV generation for symmetric algorithms.",
        }
    }

    /// CBOR representation of the algorithm according to the IANA COSE Algorithms registry.
    pub fn value(&self) -> i32 {
        match self {
            Algorithm::RS1 => -65535,
            Algorithm::WalnutDSA => -260,
            Algorithm::RS512 => -259,
            Algorithm::RS384 => -258,
            Algorithm::RS256 => -257,
            Algorithm::ES256K => -47,
            Algorithm::HSS_LMS => -46,
            Algorithm::SHAKE256 => -45,
            Algorithm::SHA_512 => -44,
            Algorithm::SHA_384 => -43,
            Algorithm::RSAES_OAEP_512 => -42,
            Algorithm::RSAES_OAEP_256 => -41,
            Algorithm::RSAES_OAEP_1 => -40,
            Algorithm::PS512 => -39,
            Algorithm::PS384 => -38,
            Algorithm::PS256 => -37,
            Algorithm::ES512 => -36,
            Algorithm::ES384 => -35,
            Algorithm::ECDH_SS_A256KW => -34,
            Algorithm::ECDH_SS_A192KW => -33,
            Algorithm::ECDH_SS_A128KW => -32,
            Algorithm::ECDH_ES_A256KW => -31,
            Algorithm::ECDH_ES_A192KW => -30,
            Algorithm::ECDH_ES_A128KW => -29,
            Algorithm::ECDH_SS_HKDF_512 => -28,
            Algorithm::ECDH_SS_HKDF_256 => -27,
            Algorithm::ECDH_ES_HKDF_512 => -26,
            Algorithm::ECDH_ES_HKDF_256 => -25,
            Algorithm::SHAKE128 => -18,
            Algorithm::SHA_512_256 => -17,
            Algorithm::SHA_256 => -16,
            Algorithm::SHA_256_64 => -15,
            Algorithm::SHA_1 => -14,
            Algorithm::Direct_HKDF_AES_256 => -13,
            Algorithm::Direct_HKDF_AES_128 => -12,
            Algorithm::Direct_HKDF_SHA_512 => -11,
            Algorithm::Direct_HKDF_SHA_256 => -10,
            Algorithm::EdDSA => -8,
            Algorithm::ES256 => -7,
            Algorithm::Direct => -6,
            Algorithm::A256KW => -5,
            Algorithm::A192KW => -4,
            Algorithm::A128KW => -3,
            Algorithm::A128GCM => 1,
            Algorithm::A192GCM => 2,
            Algorithm::A256GCM => 3,
            Algorithm::HMAC_256_64 => 4,
            Algorithm::HMAC_256_256 => 5,
            Algorithm::HMAC_384_384 => 6,
            Algorithm::HMAC_512_512 => 7,
            Algorithm::AES_CCM_16_64_128 => 10,
            Algorithm::AES_CCM_16_64_256 => 11,
            Algorithm::AES_CCM_64_64_128 => 12,
            Algorithm::AES_CCM_64_64_256 => 13,
            Algorithm::AES_MAC_128_64 => 14,
            Algorithm::AES_MAC_256_64 => 15,
            Algorithm::ChaCha20_Poly1305 => 24,
            Algorithm::AES_MAC_128_128 => 25,
            Algorithm::AES_MAC_256_128 => 26,
            Algorithm::AES_CCM_16_128_128 => 30,
            Algorithm::AES_CCM_16_128_256 => 31,
            Algorithm::AES_CCM_64_128_128 => 32,
            Algorithm::AES_CCM_64_128_256 => 33,
            Algorithm::IV_Generation => 34,
        }
    }
}

impl TryFrom<i32> for Algorithm {
    type Error = &'static str;

    fn try_from(i: i32) -> Result<Self, Self::Error> {
        Ok(match i {
            -65535 => Algorithm::RS1,
            -260 => Algorithm::WalnutDSA,
            -259 => Algorithm::RS512,
            -258 => Algorithm::RS384,
            -257 => Algorithm::RS256,
            -47 => Algorithm::ES256K,
            -46 => Algorithm::HSS_LMS,
            -45 => Algorithm::SHAKE256,
            -44 => Algorithm::SHA_512,
            -43 => Algorithm::SHA_384,
            -42 => Algorithm::RSAES_OAEP_512,
            -41 => Algorithm::RSAES_OAEP_256,
            -40 => Algorithm::RSAES_OAEP_1,
            -39 => Algorithm::PS512,
            -38 => Algorithm::PS384,
            -37 => Algorithm::PS256,
            -36 => Algorithm::ES512,
            -35 => Algorithm::ES384,
            -34 => Algorithm::ECDH_SS_A256KW,
            -33 => Algorithm::ECDH_SS_A192KW,
            -32 => Algorithm::ECDH_SS_A128KW,
            -31 => Algorithm::ECDH_ES_A256KW,
            -30 => Algorithm::ECDH_ES_A192KW,
            -29 => Algorithm::ECDH_ES_A128KW,
            -28 => Algorithm::ECDH_SS_HKDF_512,
            -27 => Algorithm::ECDH_SS_HKDF_256,
            -26 => Algorithm::ECDH_ES_HKDF_512,
            -25 => Algorithm::ECDH_ES_HKDF_256,
            -18 => Algorithm::SHAKE128,
            -17 => Algorithm::SHA_512_256,
            -16 => Algorithm::SHA_256,
            -15 => Algorithm::SHA_256_64,
            -14 => Algorithm::SHA_1,
            -13 => Algorithm::Direct_HKDF_AES_256,
            -12 => Algorithm::Direct_HKDF_AES_128,
            -11 => Algorithm::Direct_HKDF_SHA_512,
            -10 => Algorithm::Direct_HKDF_SHA_256,
            -8 => Algorithm::EdDSA,
            -7 => Algorithm::ES256,
            -6 => Algorithm::Direct,
            -5 => Algorithm::A256KW,
            -4 => Algorithm::A192KW,
            -3 => Algorithm::A128KW,
            1 => Algorithm::A128GCM,
            2 => Algorithm::A192GCM,
            3 => Algorithm::A256GCM,
            4 => Algorithm::HMAC_256_64,
            5 => Algorithm::HMAC_256_256,
            6 => Algorithm::HMAC_384_384,
            7 => Algorithm::HMAC_512_512,
            10 => Algorithm::AES_CCM_16_64_128,
            11 => Algorithm::AES_CCM_16_64_256,
            12 => Algorithm::AES_CCM_64_64_128,
            13 => Algorithm::AES_CCM_64_64_256,
            14 => Algorithm::AES_MAC_128_64,
            15 => Algorithm::AES_MAC_256_64,
            24 => Algorithm::ChaCha20_Poly1305,
            25 => Algorithm::AES_MAC_128_128,
            26 => Algorithm::AES_MAC_256_128,
            30 => Algorithm::AES_CCM_16_128_128,
            31 => Algorithm::AES_CCM_16_128_256,
            32 => Algorithm::AES_CCM_64_128_128,
            33 => Algorithm::AES_CCM_64_128_256,
            34 => Algorithm::IV_Generation,
            _ => return Err("unknown algorithm"),
        })
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Header for Algorithm {
    fn key() -> crate::header_map::Key {
        crate::header_map::Key::Integer(1)
    }
}

impl From<Algorithm> for Value {
    fn from(value: Algorithm) -> Self {
        Value::Text(value.to_string())
    }
}

impl TryFrom<Value> for Algorithm {
    type Error = serde_cbor::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(serde_cbor::value::from_value::<String>(value)?.parse()?)
    }
}

#[cfg(feature = "p256")]
mod p256 {
    use super::{Algorithm, SignatureAlgorithm};
    use p256::ecdsa::{SigningKey, VerifyingKey};

    impl SignatureAlgorithm for SigningKey {
        fn algorithm(&self) -> Algorithm {
            Algorithm::ES256
        }
    }

    impl SignatureAlgorithm for VerifyingKey {
        fn algorithm(&self) -> Algorithm {
            Algorithm::ES256
        }
    }
}

#[cfg(feature = "p384")]
mod p384 {
    use super::{Algorithm, SignatureAlgorithm};
    use p384::ecdsa::{SigningKey, VerifyingKey};

    impl SignatureAlgorithm for SigningKey {
        fn algorithm(&self) -> Algorithm {
            Algorithm::ES384
        }
    }

    impl SignatureAlgorithm for VerifyingKey {
        fn algorithm(&self) -> Algorithm {
            Algorithm::ES384
        }
    }
}
