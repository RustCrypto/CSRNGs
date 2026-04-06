use core::marker::PhantomData;
use digest::{Digest, OutputSizeUser};

use crate::arithmetic::{add_into, increment};
use crate::{Drbg, Policy, PredictionResistance, SeedError, hash_security_size};

/// What is the maximum length allowed for the entropy input, additional data and personalization string (in bytes)
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const HASH_MAX_LENGTH: u64 = 1 << (35 - 3);

/// What is the maximum number of bytes allowed to be generated in a single call
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const HASH_MAX_OUTPUT: u64 = 1 << (19 - 3);

/// What is the maximum number of calls to Hash_DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const HASH_MAX_RESEED_INTERVAL: u64 = 1 << 48;

/// What is the recommended number of calls to Hash_DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) Appendix B1
pub const HASH_NIST_RESEED_INTERVAL: u64 = 100_000;

pub struct HashDrbg<H: Digest, const SEEDLEN: usize> {
    // V - Value of `seedlen` bits
    value: [u8; SEEDLEN],

    // C - Constant of `seedlen` bits
    constant: [u8; SEEDLEN],

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // Limits for max calls to generate before reseeding
    limits: HashDrbgPolicy,

    _hasher: PhantomData<H>,
}

// policy specifically for the HashDrbg, we can use this to enforce limits on a per-DRBG type basis
struct HashDrbgPolicy {
    policy: crate::Policy,
}

impl From<crate::Policy> for HashDrbgPolicy {
    fn from(policy: crate::Policy) -> Self {
        Self { policy }
    }
}

impl HashDrbgPolicy {
    fn reseed_limit(&self) -> u64 {
        // When prediction resistance is enabled, a reseed is forced after every
        // call to generate, which is the same as a max-limit of 2 for our code
        if self.prediction_resistance() == PredictionResistance::Enabled {
            return 2;
        }
        self.policy
            .reseed_limit
            .unwrap_or(HASH_NIST_RESEED_INTERVAL)
            .clamp(2, HASH_MAX_RESEED_INTERVAL)
    }

    fn prediction_resistance(&self) -> PredictionResistance {
        self.policy.prediction_resistance
    }
}

impl<H: Digest, const SEEDLEN: usize> HashDrbg<H, SEEDLEN> {
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
            if (slice.len() as u64) > HASH_MAX_LENGTH {
                return Err(SeedError::LengthError {
                    max_size: HASH_MAX_LENGTH,
                    requested_size: slice.len() as u64,
                });
            }
        }

        let mut value = [0u8; SEEDLEN];
        hash_df::<H>(&[entropy, nonce, personalization_string], &mut value)?;

        let mut constant = [0u8; SEEDLEN];
        hash_df::<H>(&[&[0x00], &value], &mut constant)?;

        Ok(Self {
            value,
            constant,
            reseed_counter: 1,
            limits: policy.into(),
            _hasher: PhantomData,
        })
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
        if (entropy.len() as u64) > HASH_MAX_LENGTH {
            return Err(SeedError::LengthError {
                max_size: HASH_MAX_LENGTH,
                requested_size: entropy.len() as u64,
            });
        }

        // Next if the additional input is present, check that it's not too long
        let additional_input = additional_input.unwrap_or(b"");
        if (additional_input.len() as u64) > HASH_MAX_LENGTH {
            return Err(SeedError::LengthError {
                max_size: HASH_MAX_LENGTH,
                requested_size: additional_input.len() as u64,
            });
        }

        // We hash 0x01 || V || entropy || additional_input
        let mut seed = self.value;
        hash_df::<H>(
            &[&[0x01], &self.value, entropy, additional_input],
            &mut seed,
        )?;
        self.value = seed;

        // We hash 0x00 || V
        hash_df::<H>(&[&[0x00], &self.value], &mut self.constant)?;
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
        if (buf.len() as u64) > HASH_MAX_OUTPUT {
            return Err(SeedError::LengthError {
                max_size: HASH_MAX_OUTPUT,
                requested_size: buf.len() as u64,
            });
        }

        // Next if the additional input is present, check that it's not too long
        let additional_input = additional_input.unwrap_or(b"");
        if (additional_input.len() as u64) > HASH_MAX_LENGTH {
            return Err(SeedError::LengthError {
                max_size: HASH_MAX_LENGTH,
                requested_size: additional_input.len() as u64,
            });
        }

        if !additional_input.is_empty() {
            // w = Hash(0x02 || V || additional_input)
            let w = H::new_with_prefix([0x02])
                .chain_update(self.value)
                .chain_update(additional_input)
                .finalize();

            // V = V + w mod 2^seedlen
            add_into(&mut self.value, &w);
        }

        // Fill the buffer with bytes using hashgen and update V
        hashgen::<H, SEEDLEN>(self.value, buf);

        // Modify the V value
        // H = Hash(0x03 || V)
        let h = H::new_with_prefix([0x03])
            .chain_update(self.value)
            .finalize();

        // V = V + H + C + reseed_counter mod 2^seedlen
        add_into(&mut self.value, &h);
        add_into(&mut self.value, &self.constant);
        add_into(&mut self.value, &self.reseed_counter.to_be_bytes());

        self.reseed_counter += 1;

        Ok(())
    }
}

impl<H: Digest, const SEEDLEN: usize> Drbg for HashDrbg<H, SEEDLEN> {
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

/// Auxiliary function defined in 10.3.1
fn hash_df<H: Digest>(seed_material: &[&[u8]], out: &mut [u8]) -> Result<(), SeedError> {
    let hashsz = <H as OutputSizeUser>::output_size();
    let outsz = out.len();

    if outsz > hashsz * 255 {
        return Err(SeedError::LengthError {
            max_size: (255 * hashsz) as u64,
            requested_size: outsz as u64,
        });
    }

    // Number of hash blocks to request
    let m = outsz.div_ceil(hashsz) as u8;
    let num_bits_to_return = (u8::BITS * outsz as u32).to_be_bytes();

    for counter in 1..=m {
        // hash_output = Hash(counter || (output_size_bytes * 8) || *seed_material)
        let mut hasher = H::new_with_prefix([counter]);
        hasher.update(num_bits_to_return);
        for block in seed_material {
            hasher.update(block)
        }
        let hash_output = hasher.finalize();

        // counter starts from 1 so offset to get the index
        let lower = (counter as usize - 1) * hashsz;
        let upper = counter as usize * hashsz;
        if upper < out.len() {
            out[lower..upper].copy_from_slice(&hash_output);
        } else {
            out[lower..].copy_from_slice(&hash_output[..outsz - lower]);
        }
    }

    Ok(())
}

/// Auxiliary function defined in 10.1.1.4
fn hashgen<H: Digest, const SEEDLEN: usize>(value: [u8; SEEDLEN], out: &mut [u8]) {
    let hashsz = <H as OutputSizeUser>::output_size();
    let outsz = out.len();
    let m = outsz.div_ceil(hashsz);
    let mut data = value;
    for i in 0..m {
        // w = Hash(data)
        let w = H::new_with_prefix(data).finalize();

        // W = W || w
        let lower = i * hashsz;
        let upper = (i + 1) * hashsz;
        if upper < out.len() {
            out[lower..upper].copy_from_slice(&w);
        } else {
            out[lower..].copy_from_slice(&w[..outsz - lower]);
        }

        // data = (data + 1) % 2^seedlen
        increment(&mut data);
    }
}

#[cfg(feature = "sha1")]
pub type Sha1Drbg = HashDrbg<sha1::Sha1, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha224Drbg = HashDrbg<sha2::Sha224, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha512_224Drbg = HashDrbg<sha2::Sha512_224, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha256Drbg = HashDrbg<sha2::Sha256, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha512_256Drbg = HashDrbg<sha2::Sha512_256, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha384Drbg = HashDrbg<sha2::Sha384, { 888 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha512Drbg = HashDrbg<sha2::Sha512, { 888 / 8 }>;
