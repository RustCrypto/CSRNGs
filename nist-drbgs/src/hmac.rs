use core::marker::PhantomData;
use digest::{FixedOutputReset, KeyInit, array::Array};
use hmac::{HmacReset, Mac};

use crate::{Drbg, Policy, PredictionResistance, SeedError, hash_security_size};

/// What is the maximum length allowed for the entropy input, additional data and personalization string (in bytes)
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const HMAC_MAX_LENGTH: u64 = 1 << (35 - 3);

/// What is the maximum number of bytes allowed to be generated in a single call
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const HMAC_MAX_OUTPUT: u64 = 1 << (19 - 3);

/// What is the maximum number of calls to HMAC DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const HMAC_MAX_RESEED_INTERVAL: u64 = 1 << 48;

/// What is the recommended number of calls to HMAC DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) Appendix B2
pub const HMAC_NIST_RESEED_INTERVAL: u64 = 10_000;

pub struct HmacDrbg<H: Mac + KeyInit + FixedOutputReset> {
    // key - Value of `seedlen` bits
    key: Array<u8, H::OutputSize>,

    // V - Value of `seedlen` bits
    value: Array<u8, H::OutputSize>,

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // Limits for max calls to generate before reseeding
    limits: HmacDrbgPolicy,

    _hasher: PhantomData<H>,
}

// policy specifically for the HmacDrbg, we can use this to enforce limits on a per-DRBG type basis
struct HmacDrbgPolicy {
    policy: crate::Policy,
}

impl From<crate::Policy> for HmacDrbgPolicy {
    fn from(policy: crate::Policy) -> Self {
        Self { policy }
    }
}

impl HmacDrbgPolicy {
    fn reseed_limit(&self) -> u64 {
        // When prediction resistance is enabled, a reseed is forced after every
        // call to generate, which is the same as a max-limit of 2 for our code
        if self.prediction_resistance() == PredictionResistance::Enabled {
            return 2;
        }
        self.policy
            .reseed_limit
            .unwrap_or(HMAC_NIST_RESEED_INTERVAL)
            .clamp(2, HMAC_MAX_RESEED_INTERVAL)
    }

    fn prediction_resistance(&self) -> PredictionResistance {
        self.policy.prediction_resistance
    }
}

impl<H: Mac + KeyInit + FixedOutputReset> HmacDrbg<H> {
    pub fn new(
        entropy: &[u8],
        nonce: &[u8],
        personalization_string: &[u8],
        policy: Policy,
    ) -> Result<Self, SeedError> {
        // Check that the entropy has the minimum length
        if entropy.len() < hash_security_size::<H>() {
            return Err(SeedError::InsufficientEntropy);
        }

        // Check the input lengths are below the maximal bounds
        // TODO: is there an upper length for nonce? I can't see one documented.
        for slice in [entropy, personalization_string] {
            if (slice.len() as u64) > HMAC_MAX_LENGTH {
                return Err(SeedError::LengthError {
                    max_size: HMAC_MAX_LENGTH,
                    requested_size: slice.len() as u64,
                });
            }
        }

        let mut key = Array::<u8, H::OutputSize>::default();
        let mut value = Array::<u8, H::OutputSize>::default();

        // Default key:   0x00 ... 0x00
        // Default value: 0x01 ... 0x01
        for (ki, vi) in key.iter_mut().zip(value.iter_mut()) {
            *ki = 0x00;
            *vi = 0x01;
        }

        let mut hmac_drbg = Self {
            key,
            value,
            reseed_counter: 1,
            limits: policy.into(),
            _hasher: PhantomData,
        };
        hmac_drbg.hmac_drbg_update(&[entropy, nonce, personalization_string]);
        Ok(hmac_drbg)
    }

    fn new_mac(&self) -> H {
        <H as KeyInit>::new_from_slice(&self.key).unwrap()
    }

    // Auxiliary function in section 10.1.2.2
    fn hmac_drbg_update(&mut self, provided_data: &[&[u8]]) {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut mac = self
            .new_mac()
            .chain_update(&self.value)
            .chain_update([0x00]);
        for block in provided_data {
            Mac::update(&mut mac, block);
        }
        self.key = mac.finalize_reset().into_bytes();

        // V = HMAC(K, V)
        mac = self.new_mac().chain_update(&self.value);
        self.value = mac.finalize_reset().into_bytes();

        if provided_data.iter().all(|block| block.is_empty()) {
            return;
        }

        // K = HMAC(K, V || 0x01 || provided_data)
        Mac::update(&mut mac, &self.value);
        Mac::update(&mut mac, &[0x01]);
        for block in provided_data {
            Mac::update(&mut mac, block);
        }
        self.key = mac.finalize_reset().into_bytes();

        // V = HMAC(K, V)
        mac = self.new_mac().chain_update(&self.value);
        self.value = mac.finalize_reset().into_bytes();
    }

    fn reseed_core(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        // Check that the entropy has the minimum length
        if entropy.len() < hash_security_size::<H>() {
            return Err(SeedError::InsufficientEntropy);
        }

        // Check the input lengths are below the maximal bounds
        if (entropy.len() as u64) > HMAC_MAX_LENGTH {
            return Err(SeedError::LengthError {
                max_size: HMAC_MAX_LENGTH,
                requested_size: entropy.len() as u64,
            });
        }

        // Next if the additional input is present, check that it's not too long
        let additional_input = additional_input.unwrap_or(b"");
        if (additional_input.len() as u64) > HMAC_MAX_LENGTH {
            return Err(SeedError::LengthError {
                max_size: HMAC_MAX_LENGTH,
                requested_size: additional_input.len() as u64,
            });
        }

        self.hmac_drbg_update(&[entropy, additional_input]);
        self.reseed_counter = 1;

        Ok(())
    }

    fn generate_core(
        &mut self,
        buf: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        // First check we do not require a reseed per the Drbg policy
        if self.reseed_counter > self.limits.reseed_limit() {
            return Err(SeedError::CounterExhausted);
        }

        // Now we ensure we're not requesting too many bytes
        if (buf.len() as u64) > HMAC_MAX_OUTPUT {
            return Err(SeedError::LengthError {
                max_size: HMAC_MAX_OUTPUT,
                requested_size: buf.len() as u64,
            });
        }

        // Next if the additional input is present, check that it's not too long
        // then run HMAC update
        let additional_input = additional_input.unwrap_or(b"");
        if (additional_input.len() as u64) > HMAC_MAX_LENGTH {
            return Err(SeedError::LengthError {
                max_size: HMAC_MAX_LENGTH,
                requested_size: additional_input.len() as u64,
            });
        }
        if !additional_input.is_empty() {
            self.hmac_drbg_update(&[additional_input])
        }

        // The random bytes we return are the output of repeatedly
        // computing V = HMAC(K, V)
        let bufsz = buf.len();
        let hashsz = self.value.len(); // Seems like a dumb hack
        let m = bufsz.div_ceil(hashsz);

        let mut mac = self.new_mac();
        for i in 0..m {
            Mac::update(&mut mac, &self.value);
            self.value = mac.finalize_reset().into_bytes();

            // buffer = buffer || HMAC(K, V)
            let lower = i * hashsz;
            let upper = (i + 1) * hashsz;
            if upper < buf.len() {
                buf[lower..upper].copy_from_slice(&self.value);
            } else {
                buf[lower..].copy_from_slice(&self.value[..bufsz - lower]);
            }
        }

        self.hmac_drbg_update(&[additional_input]);
        self.reseed_counter += 1;

        Ok(())
    }
}

impl<H: Mac + KeyInit + FixedOutputReset> Drbg for HmacDrbg<H> {
    #[inline]
    fn reseed(&mut self, entropy: &[u8]) -> Result<(), SeedError> {
        self.reseed_core(entropy, None)
    }

    #[inline]
    fn reseed_ctx(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), SeedError> {
        self.reseed_core(entropy, Some(additional_input))
    }

    #[inline]
    fn generate(&mut self, buf: &mut [u8]) -> Result<(), SeedError> {
        self.generate_core(buf, None)
    }

    #[inline]
    fn generate_ctx(
        &mut self,
        buf: &mut [u8],
        additional_input: &[u8],
    ) -> Result<(), crate::SeedError> {
        self.generate_core(buf, Some(additional_input))
    }
}

#[cfg(feature = "hmac-sha1")]
pub type HmacSha1Drbg = HmacDrbg<HmacReset<sha1::Sha1>>;

#[cfg(feature = "hmac-sha2")]
pub type HmacSha224Drbg = HmacDrbg<HmacReset<sha2::Sha224>>;

#[cfg(feature = "hmac-sha2")]
pub type HmacSha512_224Drbg = HmacDrbg<HmacReset<sha2::Sha512_224>>;

#[cfg(feature = "hmac-sha2")]
pub type HmacSha256Drbg = HmacDrbg<HmacReset<sha2::Sha256>>;

#[cfg(feature = "hmac-sha2")]
pub type HmacSha512_256Drbg = HmacDrbg<HmacReset<sha2::Sha512_256>>;

#[cfg(feature = "hmac-sha2")]
pub type HmacSha384Drbg = HmacDrbg<HmacReset<sha2::Sha384>>;

#[cfg(feature = "hmac-sha2")]
pub type HmacSha512Drbg = HmacDrbg<HmacReset<sha2::Sha512>>;
