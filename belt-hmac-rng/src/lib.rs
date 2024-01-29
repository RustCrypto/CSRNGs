//! Pure Rust implementation of the Belt-HMAC-HBELT random number generator.
//! [STB 34.101.47-2017].
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [STB 34.101.47-2017]: https://apmi.bsu.by/assets/files/std/brng-spec25.pdf
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

use belt_hash::BeltHash;
use hmac::{
    digest::{
        generic_array::GenericArray,
        typenum::{U32, U64},
        FixedOutputReset,
    },
    Hmac, Mac,
};
use rand_core::{
    block::{BlockRng, BlockRngCore},
    CryptoRng, Error, RngCore, SeedableRng,
};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Belt-HMAC-HBELT random number generator.
pub struct BrngHmacHbelt(BlockRng<BeltHmacRngCore>);

type HmacHbelt = Hmac<BeltHash>;

const BUFSIZE: usize = 32;

/// Belt-HMAC-HBELT random number generator core.
pub struct BeltHmacRngCore {
    r: GenericArray<u8, U32>,
    s: GenericArray<u8, U32>,
    hmac: HmacHbelt,
}

impl BeltHmacRngCore {
    /// Fill the buffer with random data.
    pub fn fill(&mut self, dest: &mut [u8]) {
        // 𝑌𝑖 ← hmac[ℎ](𝐾, 𝑟 ‖ 𝑆);
        self.hmac.update(&self.r);
        self.hmac.update(&self.s);
        let y = self.hmac.finalize_fixed_reset();
        dest[..BUFSIZE].copy_from_slice(&y);

        // 𝑟 ← hmac[ℎ](𝐾, 𝑟).
        self.hmac.update(&self.r);
        self.hmac.finalize_into_reset(&mut self.r);
    }
}

impl BlockRngCore for BeltHmacRngCore {
    type Item = u32;
    type Results = [u32; 8];

    fn generate(&mut self, results: &mut Self::Results) {
        let mut buf = [0u8; BUFSIZE];
        self.fill(&mut buf);

        for i in 0..BUFSIZE / 4 {
            results[i] =
                u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]]);
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for BeltHmacRngCore {}

impl SeedableRng for BeltHmacRngCore {
    type Seed = GenericArray<u8, U64>;

    #[allow(unused_mut)]
    #[allow(clippy::let_and_return)]
    fn from_seed(mut seed: Self::Seed) -> Self {
        let rng_core = {
            let key = &seed[..BUFSIZE];
            let iv = &seed[BUFSIZE..BUFSIZE + BUFSIZE];
            let mut hmac = HmacHbelt::new_from_slice(key).unwrap();

            // 𝑟 ← hmac[ℎ](𝐾, 𝑆).
            hmac.update(iv);
            let r = hmac.finalize_fixed_reset();

            BeltHmacRngCore {
                r,
                hmac,
                s: GenericArray::<u8, U32>::clone_from_slice(iv),
            }
        };

        #[cfg(feature = "zeroize")]
        seed.zeroize();

        rng_core
    }
}

impl SeedableRng for BrngHmacHbelt {
    type Seed = <BeltHmacRngCore as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        BrngHmacHbelt(BlockRng::<BeltHmacRngCore>::from_seed(seed))
    }

    fn from_rng<R: RngCore>(rng: R) -> Result<Self, Error> {
        BlockRng::<BeltHmacRngCore>::from_rng(rng).map(BrngHmacHbelt)
    }
}

impl RngCore for BrngHmacHbelt {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for BrngHmacHbelt {}
