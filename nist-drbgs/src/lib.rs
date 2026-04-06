//! A `no_std` implementation of the NIST SP 800-90A Rev. 1 Deterministic Random Bit Generators
//! (DRBGs).
//!
//! Three DRBG mechanisms are provided, each available behind a feature flag:
//! - **Hash DRBG** (`sha1`, `sha2`) — based on a cryptographic hash function
//! - **HMAC DRBG** (`hmac-sha1`, `hmac-sha2`) — based on HMAC
//! - **CTR DRBG** (`aes-ctr`, `tdea-ctr`) — based on a block cipher in counter mode
//!
//! All implementations follow the construction described in
//! [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final).
//!
//! # Usage
//!
//! Each DRBG is instantiated with entropy, a nonce, an optional personalization string, and a
//! [`Policy`]. Once instantiated, random bytes are produced by calling [`Drbg::generate`]. The
//! DRBG must be reseeded periodically; if the reseed counter is exhausted before reseeding,
//! [`Drbg::generate`] returns [`SeedError::CounterExhausted`].
//!
//! ```rust
//! use nist_drbg_rs::{HmacSha256Drbg, Policy, Drbg};
//!
//! let entropy = [0u8; 32];
//! let nonce = [0u8; 16];
//! let personalization_string = b"";
//!
//! let mut drbg = HmacSha256Drbg::new(&entropy, &nonce, personalization_string, Policy::default())
//!     .expect("sufficient entropy provided");
//!
//! let mut output = [0u8; 64];
//! drbg.generate(&mut output).expect("counter not exhausted");
//! ```

#![no_std]

use core::{error::Error, fmt::Display};
use digest::OutputSizeUser;

// Should we feature lock this? We don't need it for Hmac, but will for Hash
// and CTR
mod arithmetic;

#[cfg(any(feature = "sha1", feature = "sha2"))]
pub mod hash;

#[cfg(any(feature = "sha1", feature = "sha2"))]
pub use hash::*;

#[cfg(any(feature = "hmac-sha1", feature = "hmac-sha2"))]
pub mod hmac;

#[cfg(any(feature = "hmac-sha1", feature = "hmac-sha2"))]
pub use hmac::*;

#[cfg(any(feature = "aes-ctr", feature = "tdea-ctr"))]
pub mod ctr;

#[cfg(any(feature = "aes-ctr", feature = "tdea-ctr"))]
pub use ctr::*;

/// Errors returned by DRBG operations.
#[derive(Debug)]
pub enum SeedError {
    /// The entropy provided was shorter than the minimum length required by the
    /// security strength of the chosen DRBG. Ensure the entropy input is at least
    /// as long as the security size reported for your chosen hash or cipher.
    InsufficientEntropy,

    /// A provided input (entropy, nonce, personalization string, or additional input)
    /// exceeded the maximum length permitted by the NIST specification for this DRBG,
    /// or the requested output length exceeded the per-call output limit.
    LengthError { max_size: u64, requested_size: u64 },

    /// The entropy provided to CTR DRBG without a derivation function was not exactly
    /// the required `seedlen` bytes.
    IncorrectLength { expected_size: u64, given_size: u64 },

    /// The reseed counter has reached the configured limit. Call [`Drbg::reseed`] or
    /// [`Drbg::reseed_ctx`] before requesting further output. This error is also
    /// returned on every generate call when [`PredictionResistance::Enabled`] is set
    /// and a reseed has not been performed since the last generate.
    CounterExhausted,
}

impl Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SeedError::InsufficientEntropy => f.write_str(
                "Insufficient entropy was provided to meet the minimum supported entropy level",
            ),
            SeedError::LengthError {
                max_size,
                requested_size,
            } => {
                write!(
                    f,
                    "Requested size of {requested_size} bytes exceeds maximum size of {max_size} bytes"
                )
            }
            SeedError::IncorrectLength {
                expected_size,
                given_size,
            } => {
                write!(
                    f,
                    "Requested size of {given_size} bytes is not equal to {expected_size} bytes"
                )
            }
            SeedError::CounterExhausted => f.write_str("Counter has been exhausted, reseed"),
        }
    }
}

impl Error for SeedError {}

/// Auxiliary function to determine security strength as per SP 800-57 from
/// the digest size for hash and hmac based drbg
fn hash_security_size<H: OutputSizeUser>() -> usize {
    let digest_size = H::output_size();
    if digest_size <= 20 {
        16
    } else if digest_size <= 28 {
        24
    } else {
        32
    }
}

/// Common interface for all DRBG mechanisms defined in NIST SP 800-90A Rev. 1.
///
/// A DRBG produces unpredictable output from an internal state that is seeded
/// with entropy during construction and periodically refreshed via reseeding.
///
/// # Reseeding
///
/// Each DRBG maintains a reseed counter. Once the counter reaches the configured
/// limit (see [`Policy`]), [`Drbg::generate`] returns [`SeedError::CounterExhausted`]
/// and the caller must call [`Drbg::reseed`] or [`Drbg::reseed_ctx`] before
/// generating further output. The limit defaults to the NIST recommended interval
/// for each mechanism if not set explicitly via [`Policy::with_reseed_limit`].
///
/// # Additional Input
///
/// The `_ctx` variants of both generate and reseed accept an `additional_input`
/// parameter. This is mixed into the internal state before the operation and
/// provides a caller-supplied contribution to the entropy. It does not replace
/// the need for good entropy at construction or reseed time.
pub trait Drbg {
    /// Reseed the DRBG with fresh entropy.
    ///
    /// Resets the reseed counter to 1. The entropy must meet the minimum length
    /// required for the security strength of the chosen DRBG, otherwise
    /// [`SeedError::InsufficientEntropy`] is returned.
    fn reseed(&mut self, entropy: &[u8]) -> Result<(), SeedError>;

    /// Reseed the DRBG with fresh entropy and additional input.
    ///
    /// Behaves identically to [`Drbg::reseed`] but also mixes `additional_input`
    /// into the internal state update. `additional_input` may be empty.
    fn reseed_ctx(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), SeedError>;

    /// Fill `buf` with pseudorandom bytes.
    ///
    /// The number of bytes generated is determined by the length of `buf`. Returns
    /// [`SeedError::CounterExhausted`] if the reseed counter has reached its limit,
    /// in which case [`Drbg::reseed`] must be called before generating further output.
    /// Returns [`SeedError::LengthError`] if `buf` exceeds the per-call output limit
    /// for this DRBG mechanism.
    fn generate(&mut self, buf: &mut [u8]) -> Result<(), SeedError>;

    /// Fill `buf` with pseudorandom bytes, mixing in additional input.
    ///
    /// Behaves identically to [`Drbg::generate`] but also mixes `additional_input`
    /// into the internal state before generating output. `additional_input` may be
    /// empty.
    fn generate_ctx(&mut self, buf: &mut [u8], additional_input: &[u8]) -> Result<(), SeedError>;
}

/// Configuration for a DRBG instance.
///
/// `Policy` controls the operational limits of a DRBG. It is passed at construction
/// time and cannot be changed afterwards. Use the builder methods to override the
/// defaults.
///
/// # Defaults
///
/// When constructed via [`Policy::default()`], the NIST recommended reseed interval
/// for the chosen mechanism is used and prediction resistance is disabled.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    reseed_limit: Option<u64>,
    prediction_resistance: PredictionResistance,
}

/// Whether prediction resistance is enabled for a DRBG instance.
///
/// When [`PredictionResistance::Enabled`] is set, the DRBG will return
/// [`SeedError::CounterExhausted`] after every generate call, forcing the caller
/// to reseed with fresh entropy before the next generate. This ensures that
/// compromise of the internal state after a generate cannot be used to predict
/// past outputs.
///
/// [`PredictionResistance::Disabled`] is the default and allows multiple generate
/// calls between reseeds up to the configured reseed limit.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionResistance {
    Enabled,
    #[default]
    Disabled,
}

impl Policy {
    /// Set the maximum number of generate calls permitted before a reseed is required.
    ///
    /// The value is clamped to the range `[2, MAX_RESEED_INTERVAL]` for the chosen
    /// DRBG mechanism. If not set, the NIST recommended interval for the mechanism
    /// is used. Has no effect when [`PredictionResistance::Enabled`] is set, since
    /// reseeding is forced after every generate call regardless.
    pub fn with_reseed_limit(self, reseed_limit: u64) -> Self {
        Self {
            reseed_limit: Some(reseed_limit),
            ..self
        }
    }

    /// Set whether prediction resistance is enabled.
    ///
    /// See [`PredictionResistance`] for details on the behavioral difference.
    pub fn with_prediction_resistance(self, prediction_resistance: PredictionResistance) -> Self {
        Self {
            prediction_resistance,
            ..self
        }
    }
}

#[cfg(feature = "rng")]
mod rand_core_impls {
    use super::*;

    // impl rand_core::TryRng and rand_core::TryCryptoRng for a type $drbg
    macro_rules! impl_rand_core_traits {
        ($drbg:ty) => {
            impl rand_core::TryRng for $drbg {
                type Error = SeedError;

                fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                    let mut bytes = [0; 4];
                    self.generate(&mut bytes)?;
                    Ok(u32::from_ne_bytes(bytes))
                }

                fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                    let mut bytes = [0; 8];
                    self.generate(&mut bytes)?;
                    Ok(u64::from_ne_bytes(bytes))
                }

                fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                    self.generate(dst)
                }
            }

            impl rand_core::TryCryptoRng for $drbg {}
        };
    }

    // impl rand_core::TryRng and rand_core::TryCryptoRng for many types
    macro_rules! impl_rand_core_traits_many {
        ($($drbg:ty),+ $(,)?) => {
            $(
                impl_rand_core_traits!($drbg);
            )*
        };
    }

    #[cfg(feature = "aes-ctr")]
    impl_rand_core_traits_many!(Aes128CtrDrbg, Aes192CtrDrbg, Aes256CtrDrbg);

    #[cfg(feature = "tdea-ctr")]
    impl_rand_core_traits!(TdeaCtrDrbg);

    #[cfg(feature = "sha1")]
    impl_rand_core_traits!(Sha1Drbg);

    #[cfg(feature = "sha2")]
    impl_rand_core_traits_many!(
        Sha224Drbg,
        Sha512_224Drbg,
        Sha256Drbg,
        Sha512_256Drbg,
        Sha384Drbg,
        Sha512Drbg,
    );

    #[cfg(feature = "hmac-sha1")]
    impl_rand_core_traits!(HmacSha1Drbg);

    #[cfg(feature = "hmac-sha2")]
    impl_rand_core_traits_many!(
        HmacSha224Drbg,
        HmacSha512_224Drbg,
        HmacSha256Drbg,
        HmacSha512_256Drbg,
        HmacSha384Drbg,
        HmacSha512Drbg,
    );
}
