use core::marker::PhantomData;

use aes::cipher::{
    Array, BlockCipherEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
    typenum::{U8, U21, U24},
};
use aes::{Aes128Enc, Aes192Enc, Aes256Enc};
use des::TdesEde3;

use crate::arithmetic::increment;
use crate::{Drbg, Policy, PredictionResistance, SeedError};

/// What is the maximum length allowed for the entropy input, additional data and personalization string (in bytes)
/// when using CTR DRBG and a derivation function
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 3
pub const CTR_MAX_LENGTH: u64 = 1 << (35 - 3);

pub struct CtrDrbg<C: BlockCipherEncrypt + KeyInit, L: CtrModeLimits, const SEEDLEN: usize> {
    // key used for block cipher encryption
    key: Array<u8, C::KeySize>,

    // V - value which has blocklen bits
    value: Array<u8, C::BlockSize>,

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // Whether or not to use a derivation function for seeding and reseeding
    derivation_function: bool,

    // Limits for max calls to generate before reseeding
    limits: CtrDrbgPolicy<L>,
}

// policy specifically for the CtrDrbg, we can use this to enforce limits on a per-DRBG type basis
struct CtrDrbgPolicy<L: CtrModeLimits> {
    policy: crate::Policy,
    _limits: PhantomData<L>,
}

impl<L: CtrModeLimits> From<crate::Policy> for CtrDrbgPolicy<L> {
    fn from(policy: crate::Policy) -> Self {
        Self {
            policy,
            _limits: PhantomData,
        }
    }
}

impl<L: CtrModeLimits> CtrDrbgPolicy<L> {
    fn reseed_limit(&self) -> u64 {
        // When prediction resistance is enabled, a reseed is forced after every
        // call to generate, which is the same as a max-limit of 2 for our code
        if self.prediction_resistance() == PredictionResistance::Enabled {
            2
        } else {
            self.policy
                .reseed_limit
                .unwrap_or(L::DEFAULT_RESEED_INTERVAL)
                .clamp(2, L::MAX_RESEED_INTERVAL)
        }
    }

    fn max_output(&self) -> u64 {
        L::MAX_OUTPUT
    }

    fn prediction_resistance(&self) -> PredictionResistance {
        self.policy.prediction_resistance
    }
}

impl<C: BlockCipherEncrypt + KeyInit, L: CtrModeLimits, const SEEDLEN: usize>
    CtrDrbg<C, L, SEEDLEN>
{
    /// Create a CTR DRBG instance without the use of a derivation function
    pub fn new(
        entropy: &[u8],
        personalization_string: &[u8],
        policy: Policy,
    ) -> Result<Self, SeedError> {
        // Check that the entropy has exactly SEEDLEN
        if entropy.len() != SEEDLEN {
            return Err(SeedError::IncorrectLength {
                expected_size: SEEDLEN as u64,
                given_size: entropy.len() as u64,
            });
        }

        // Check that personalization_string is at most SEEDLEN
        if personalization_string.len() > SEEDLEN {
            return Err(SeedError::LengthError {
                max_size: SEEDLEN as u64,
                requested_size: personalization_string.len() as u64,
            });
        }

        Self::new_impl(entropy, None, personalization_string, policy)
    }

    /// Create a CTR DRBG instance with the use of a derivation function
    pub fn new_with_df(
        entropy: &[u8],
        nonce: &[u8],
        personalization_string: &[u8],
        policy: Policy,
    ) -> Result<Self, SeedError> {
        // Check that the entropy has the minimum length required
        if entropy.len() < block_cipher_security_size::<C>() {
            return Err(SeedError::InsufficientEntropy);
        }

        // Check the input lengths are below the maximal bounds
        for slice in [entropy, personalization_string] {
            if (slice.len() as u64) > CTR_MAX_LENGTH {
                return Err(SeedError::LengthError {
                    max_size: CTR_MAX_LENGTH,
                    requested_size: slice.len() as u64,
                });
            }
        }

        Self::new_impl(entropy, Some(nonce), personalization_string, policy)
    }

    fn new_impl(
        entropy: &[u8],
        nonce: Option<&[u8]>,
        personalization_string: &[u8],
        policy: Policy,
    ) -> Result<Self, SeedError> {
        let mut seed_material: [u8; SEEDLEN] = [0; SEEDLEN];

        // When a derivation function is used then the entropy input is
        // seed_material = entropy || nonce || personalization_string
        // which is fed into a derivation function before being used
        // as the value to be processed by ctr_drbg_update
        if let Some(nonce) = &nonce {
            // Compute the seed material from the derivation function and user supplied entropy
            ctr_drbg_df::<C, SEEDLEN>(
                &[entropy, nonce, personalization_string],
                &mut seed_material[..],
            );
        }
        // Otherwise seed_material = entropy ^ pad(personalization_string)
        else {
            // The personalization string must be padded with zeros on the right to
            // ensure it has length SEEDLEN. We can do this by copying personalization_string
            // into seed_material
            seed_material[..personalization_string.len()].copy_from_slice(personalization_string);

            // seed_material = entropy ^ pad(personalization_string)
            xor_into(&mut seed_material[..], entropy);
        }

        // We now have the processed seed material, which we now pass into the update function
        let mut ctr_drbg = Self {
            key: Default::default(),
            value: Default::default(),
            reseed_counter: 1,
            derivation_function: nonce.is_some(),
            limits: policy.into(),
        };
        ctr_drbg.ctr_drbg_update(&seed_material);
        Ok(ctr_drbg)
    }

    // Auxiliary function in section 10.1.2.2
    fn ctr_drbg_update(&mut self, provided_data: &[u8]) {
        // Buffer to fill with update bytes
        let mut tmp: [u8; SEEDLEN] = [0; SEEDLEN];

        // Create a cipher to encrypt blocks
        let cipher = C::new(&self.key);

        let block_len = C::block_size();
        let m = SEEDLEN.div_ceil(block_len);
        for i in 0..m {
            // TODO: Issue #3
            // Here we assume ctr_len = block_len, however in the NIST document
            // ctr_len is allowed to be any value within the range 4 <= ctr_ln <= block_len
            // If this change is implemented, then the increment below will need to be
            // generalized to accommodate this change.

            // V = V + 1 mod 2^block_len
            increment(&mut self.value);

            // Add an encryption block, note encrypt_block works in-place
            let mut ct = self.value.clone();
            cipher.encrypt_block(&mut ct);

            // tmp = tmp || Enc_K(V)
            let lower = i * block_len;
            let upper = (i + 1) * block_len;
            if upper < SEEDLEN {
                tmp[lower..upper].copy_from_slice(&ct);
            } else {
                tmp[lower..].copy_from_slice(&ct[..SEEDLEN - lower]);
            }
        }

        // tmp = tmp XOR provided_data
        xor_into(&mut tmp, provided_data);

        let key_len = self.key.len();
        self.key.copy_from_slice(&tmp[..key_len]);
        self.value.copy_from_slice(&tmp[key_len..]);
    }

    fn reseed_core(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        let mut seed_material: [u8; SEEDLEN] = [0; SEEDLEN];
        let additional_input = additional_input.unwrap_or(b"");

        // If we use a derivation function, then entropy has a minimum
        // length and seed_material is computed via ctr_drbg_df
        if self.derivation_function {
            // Check that the entropy has the minimum length
            if entropy.len() < block_cipher_security_size::<C>() {
                return Err(SeedError::InsufficientEntropy);
            }

            // Check entropy and additional_input are not too large
            for slice in [entropy, additional_input] {
                if (slice.len() as u64) > CTR_MAX_LENGTH {
                    return Err(SeedError::LengthError {
                        max_size: CTR_MAX_LENGTH,
                        requested_size: slice.len() as u64,
                    });
                }
            }

            // Compute the seed material from the derivation function and user supplied entropy
            ctr_drbg_df::<C, SEEDLEN>(&[entropy, additional_input], &mut seed_material[..]);
        }
        // Otherwise, seed_material is computed via a XOR with the entropy and strict
        // length requirements are made.
        else {
            // Check that the entropy has exactly SEEDLEN
            if entropy.len() != SEEDLEN {
                return Err(SeedError::IncorrectLength {
                    expected_size: SEEDLEN as u64,
                    given_size: entropy.len() as u64,
                });
            }

            // Ensure additional_input is not too long
            if additional_input.len() > SEEDLEN {
                return Err(SeedError::LengthError {
                    max_size: SEEDLEN as u64,
                    requested_size: additional_input.len() as u64,
                });
            }

            // The personalization string must be padded with zeros on the right to
            // ensure it has length SEEDLEN. We can do this by copying personalization_string
            // into seed_material
            seed_material[..additional_input.len()].copy_from_slice(additional_input);

            // Compute:
            // seed_material = entropy ^ pad(additional_data)
            xor_into(&mut seed_material[..], entropy);
        }

        // Set key, V using the update function
        self.ctr_drbg_update(&seed_material);
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
        if (buf.len() as u64) > self.limits.max_output() {
            return Err(SeedError::LengthError {
                max_size: self.limits.max_output(),
                requested_size: buf.len() as u64,
            });
        }

        let mut seed_material: [u8; SEEDLEN] = [0; SEEDLEN];

        // Deal with the additional input, if it is not empty
        let additional_input = additional_input.unwrap_or(b"");
        if !additional_input.is_empty() {
            // When a derivation function is used, the seed material is generated
            // directly from the additional data
            if self.derivation_function {
                if additional_input.len() as u64 > CTR_MAX_LENGTH {
                    return Err(SeedError::LengthError {
                        max_size: CTR_MAX_LENGTH,
                        requested_size: additional_input.len() as u64,
                    });
                }
                ctr_drbg_df::<C, SEEDLEN>(&[additional_input], &mut seed_material[..]);
            }
            // Otherwise we simply pad the additional input to the length of the seed
            else {
                if additional_input.len() > SEEDLEN {
                    return Err(SeedError::LengthError {
                        max_size: SEEDLEN as u64,
                        requested_size: additional_input.len() as u64,
                    });
                }
                seed_material[..additional_input.len()].copy_from_slice(additional_input);
            }
            self.ctr_drbg_update(&seed_material);
        }

        // Create a cipher to encrypt blocks
        let cipher = C::new(&self.key);

        // Fill buf with random bytes by repeatedly appending encryptions
        let block_len = C::block_size();
        let bufsz = buf.len();
        let m = bufsz.div_ceil(block_len);
        for i in 0..m {
            // TODO: Issue #3 (as above)
            // Here we assume ctr_len = block_len, however in the NIST document
            // ctr_len is allowed to be any value within the range 4 <= ctr_ln <= block_len
            // If this change is implemented, then the increment below will need to be
            // generalized to accommodate this change.

            // V = V + 1 mod 2^block_len
            increment(&mut self.value);

            // Add an encryption block, note encrypt_block works in-place
            let mut ct = self.value.clone();
            cipher.encrypt_block(&mut ct);

            // buf = buf || Enc_K(V)
            let lower = i * block_len;
            let upper = (i + 1) * block_len;
            if upper < bufsz {
                buf[lower..upper].copy_from_slice(&ct);
            } else {
                buf[lower..].copy_from_slice(&ct[..bufsz - lower]);
            }
        }

        // Update for backtracking resistance
        self.ctr_drbg_update(&seed_material);
        self.reseed_counter += 1;

        Ok(())
    }
}

/// Auxiliary function to determine security strength as per SP 800-57 from
/// the keysize for hash and hmac based drbg
fn block_cipher_security_size<C: BlockSizeUser + KeySizeUser>() -> usize {
    // For AES, the key size is the same as the security size,
    // For TDEA we have 21 byte keys but only 112 bits of security,
    // so when TDEA is used (8 byte block size) we return 112 / 8 = 14
    if C::block_size() == 8 {
        return 14;
    }
    C::key_size()
}

/// Auxiliary function in Section 10.3.2
fn ctr_drbg_df<C: BlockCipherEncrypt + KeyInit, const SEEDLEN: usize>(
    seed_material: &[&[u8]],
    out: &mut [u8],
) {
    /*
     * This first block of code is to make: S = L || N || input || 0x80 || 0x00 ... 0x00
     * however, we don't know the length of the input at compile time, so instead of allocating
     * space for this at runtime, we instead modify the bcc function to take the input data and
     * then encrypt this with BCC and pad during runtime.
     */

    /*
     * This step makes a key 0x00 0x01 0x02 ... 0xXX and uses this to encrypt
     * a value with BCC to generate SEEDLEN bytes which are used to derive a
     * new key and new value X which we use to fill the output buffer
     */
    let mut key = Array::<u8, C::KeySize>::default();
    for (i, ki) in key.iter_mut().enumerate() {
        *ki = i as u8;
    }

    // Fill the output bytes with values from BCC to generate SEEDLEN new bytes
    let mut iv = Array::<u8, C::BlockSize>::default();
    let mut ct = Array::<u8, C::BlockSize>::default();
    let block_len = C::block_size();
    let outsz = out.len();
    let m = outsz.div_ceil(block_len);
    for i in 0..m {
        // IV = (i as u32 to big endian bytes) || 0x00 ... 0x00
        iv[..4].copy_from_slice(&(i as u32).to_be_bytes());

        // now we obtain block_size bytes from BCC
        bcc::<C, SEEDLEN>(&key, &iv, seed_material, &mut ct);

        // out = out || BCC(K, IV || S)
        let lower = i * block_len;
        let upper = (i + 1) * block_len;
        if upper < outsz {
            out[lower..upper].copy_from_slice(&ct);
        } else {
            out[lower..].copy_from_slice(&ct[..outsz - lower]);
        }
    }

    let key_len = key.len();
    key.copy_from_slice(&out[..key_len]);
    ct.copy_from_slice(&out[key_len..]);

    /*
     * Now we have a new key and value X = ct, we repeatedly encrypt this and fill the out
     * buffer with these bytes
     */
    let cipher = C::new(&key);
    for i in 0..m {
        // Note that encryption works in place
        cipher.encrypt_block(&mut ct);

        // out = out || Enc(K, ct)
        let lower = i * block_len;
        let upper = (i + 1) * block_len;
        if upper < outsz {
            out[lower..upper].copy_from_slice(&ct);
        } else {
            out[lower..].copy_from_slice(&ct[..outsz - lower]);
        }
    }
}

/// Helper function which computes A = A XOR B
fn xor_into(a: &mut [u8], b: &[u8]) {
    debug_assert_eq!(
        a.len(),
        b.len(),
        "xor_into called on slices with mismatching lengths"
    );

    for (ai, bi) in a.iter_mut().zip(b.iter()) {
        *ai ^= bi
    }
}

fn bcc<C: BlockCipherEncrypt + KeyInit, const SEEDLEN: usize>(
    key: &Array<u8, C::KeySize>,
    iv: &[u8],
    data: &[&[u8]],
    out: &mut Array<u8, C::BlockSize>,
) {
    // Instead of taking a value S as input, in out implementation we are given
    // some data of type &[&u8], and we need to create blocks during runtime of
    // the format
    //     s = L || N || data.flatten() || 0x80 || 0x00 ... 0x00
    // right padded with zeros so that there's an exactly block length

    // Compute the length of the input and output as four bytes big endian
    let input_len: usize = data.iter().map(|block| block.len()).sum();
    let input_len_bytes = (input_len as u32).to_be_bytes();
    let output_len_bytes = (SEEDLEN as u32).to_be_bytes();

    // Ensure our chaining value is all zeros to begin with
    for c in out.iter_mut() {
        *c = 0;
    }

    // First we XOR the IV into the chaining value and encrypt
    let cipher = C::new(key);
    xor_into(out, iv);
    cipher.encrypt_block(out);

    // Now we iterate through all the various data values and make blocks to encrypt
    let block_len = out.len();
    // We will perform n block encryptions, filling this block with the input data
    let mut block = Array::<u8, C::BlockSize>::default();
    let mut block_bytes_filled = 0;

    // The first block starts with input_len || block_len
    // For AES this is 1/2 a block, but for DES this is a full block, so we can always directly copy
    block[..4].copy_from_slice(&input_len_bytes);
    block_bytes_filled += 4;
    block[4..8].copy_from_slice(&output_len_bytes);
    block_bytes_filled += 4;

    // Now we need to fill blocks with the bytes in data, we do this by
    // iterating through the slice
    for byte in data.iter().flat_map(|slice| slice.iter()) {
        // When the block is filled, we should perform an encryption and start again
        if block_bytes_filled == block_len {
            // Actually do the work
            xor_into(out, &block);
            cipher.encrypt_block(out);

            // update internal helpers after encryption
            block_bytes_filled = 0;
        }

        // Now add the next byte to the block to encrypt
        block[block_bytes_filled] = *byte;
        block_bytes_filled += 1; // update the counter
    }

    // check if the block is filled after the last loop
    if block_bytes_filled == block_len {
        xor_into(out, &block);
        cipher.encrypt_block(out);
        block_bytes_filled = 0;
    }

    // Finally we need to append the byte 0x80 followed by zeros for the
    // final block
    block[block_bytes_filled] = 0x80;
    block_bytes_filled += 1;

    // pad with zeros...
    for i in block_bytes_filled..block_len {
        block[i] = 0x00;
    }

    // Perform the final encryption
    xor_into(out, &block);
    cipher.encrypt_block(out);
}

impl<C: BlockCipherEncrypt + KeyInit, L: CtrModeLimits, const SEEDLEN: usize> Drbg
    for CtrDrbg<C, L, SEEDLEN>
{
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

pub trait CtrModeLimits {
    /// The recommended number of calls to CTR DRBG before the DRBG must be reseeded
    const DEFAULT_RESEED_INTERVAL: u64;

    /// The maximum number of calls to CTR DRBG before the DRBG must be reseeded
    const MAX_RESEED_INTERVAL: u64;

    /// The maximum number of bytes allowed to be generated in a single call
    const MAX_OUTPUT: u64;
}

pub struct AesLimits;

impl CtrModeLimits for AesLimits {
    const DEFAULT_RESEED_INTERVAL: u64 = 10_000;
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;
    const MAX_OUTPUT: u64 = 65536;
}

pub struct TdeaLimits;

impl CtrModeLimits for TdeaLimits {
    const DEFAULT_RESEED_INTERVAL: u64 = 1000; // what should this be?
    const MAX_RESEED_INTERVAL: u64 = 1 << 32;
    const MAX_OUTPUT: u64 = 1024;
}
/// A wrapper around des::TdesEde3 which supports a key without parity bits
pub struct TdesEde3ShortKey(TdesEde3);

/* BlockCipher + KeyInit + BlockEncrypt */

impl BlockSizeUser for TdesEde3ShortKey {
    type BlockSize = U8;
}

impl BlockCipherEncrypt for TdesEde3ShortKey {
    fn encrypt_with_backend(
        &self,
        f: impl aes::cipher::BlockCipherEncClosure<BlockSize = Self::BlockSize>,
    ) {
        self.0.encrypt_with_backend(f);
    }
}

impl KeySizeUser for TdesEde3ShortKey {
    type KeySize = U21;
}

impl KeyInit for TdesEde3ShortKey {
    fn new(key: &Array<u8, U21>) -> Self {
        let mut wide_key: Array<u8, U24> = Array::default();
        derive_tdea_key(key, &mut wide_key);
        Self(TdesEde3::new(&wide_key))
    }
}

/// Auxiliary function to compute and set parity bits of TDEA key
fn derive_tdea_key(in_key: &Array<u8, U21>, out_key: &mut Array<u8, U24>) {
    derive_des_key(&mut out_key[..8], &in_key[..7]);
    derive_des_key(&mut out_key[8..16], &in_key[7..14]);
    derive_des_key(&mut out_key[16..24], &in_key[14..21]);
}

/// Auxiliary function to compute and set parity bits of DES key
fn derive_des_key(out_key: &mut [u8], in_key: &[u8]) {
    // First set key as a u64 to extract out 7-bit chunks
    let mut k = u64::from_be_bytes([
        0, in_key[0], in_key[1], in_key[2], in_key[3], in_key[4], in_key[5], in_key[6],
    ]);

    // ensure key bits are always in the top 7 bits of the lowest byte as we shift
    k <<= 1;

    // Set the 8 bytes of the out key with 7-bits from the key and one
    // parity bit
    for i in 0..8 {
        let key_byte = k as u8;
        k >>= 7;
        let parity_bit = (key_byte.count_ones() & 1) as u8;
        out_key[7 - i] = parity_bit | (key_byte & !1);
    }
}

// SEEDLEN = BlockSize + KeySize
#[cfg(feature = "tdea-ctr")]
pub type TdeaCtrDrbg = CtrDrbg<TdesEde3ShortKey, TdeaLimits, { 21 + 8 }>;

#[cfg(feature = "aes-ctr")]
pub type Aes128CtrDrbg = CtrDrbg<Aes128Enc, AesLimits, { 16 + 16 }>;

#[cfg(feature = "aes-ctr")]
pub type Aes192CtrDrbg = CtrDrbg<Aes192Enc, AesLimits, { 24 + 16 }>;

#[cfg(feature = "aes-ctr")]
pub type Aes256CtrDrbg = CtrDrbg<Aes256Enc, AesLimits, { 32 + 16 }>;
