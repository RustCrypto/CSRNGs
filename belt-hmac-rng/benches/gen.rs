#![feature(test)]
#![allow(non_snake_case)]

extern crate test;

use test::{black_box, Bencher};

use rand_core::{RngCore, SeedableRng};

use belt_hmac_rng::BrngHmacHbelt;

const RAND_BENCH_N: u64 = 1000;
const BYTES_LEN: usize = 1024;

#[bench]
fn gen_bytes_belt(b: &mut Bencher) {
    let mut rng = BrngHmacHbelt::from_entropy();
    let mut buf = [0u8; BYTES_LEN];
    b.iter(|| {
        for _ in 0..RAND_BENCH_N {
            rng.fill_bytes(&mut buf);
            black_box(buf);
        }
    });
    b.bytes = BYTES_LEN as u64 * RAND_BENCH_N;
}

#[bench]
fn belt_uint32(b: &mut Bencher) {
    let mut rng = BrngHmacHbelt::from_entropy();
    b.iter(|| {
        for _ in 0..RAND_BENCH_N {
            black_box(rng.next_u32());
        }
    });
    b.bytes = 4 * RAND_BENCH_N;
}

#[bench]
fn belt_uint64(b: &mut Bencher) {
    let mut rng = BrngHmacHbelt::from_entropy();
    b.iter(|| {
        for _ in 0..RAND_BENCH_N {
            black_box(rng.next_u64());
        }
    });
    b.bytes = 8 * RAND_BENCH_N;
}
