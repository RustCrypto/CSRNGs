extern crate aes_rng;
extern crate rand;
extern crate xoshiro;

#[macro_use]
extern crate criterion;

use rand::{RngCore, FromEntropy, SeedableRng};
use criterion::{Criterion, Fun};

fn fill(c: &mut Criterion) {
    const BUF_SIZE: usize = 1024 * 1024 * 100;
    let fill_aes = {
        let mut rng = aes_rng::AesRng::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ]);
        let mut buf = vec![0; BUF_SIZE];

        Fun::new("aes", move |b, _| b.iter(|| rng.fill_bytes(&mut buf)))
    };
    let fill_aescore = {
        let mut rng = aes_rng::AesCore::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ]);
        let mut buf = vec![0; BUF_SIZE];

        Fun::new("aescore", move |b, _| b.iter(|| rng.fill(&mut buf)))
    };
    let fill_xoshiro =
        {
            let mut rng = xoshiro::Xoshiro128StarStar::from_seed_u64(1);
            let mut buf = vec![0; BUF_SIZE];

            Fun::new("xoshiro", move |b, _| b.iter(|| rng.fill_bytes(&mut buf)))
        };
    let fill_std = {
        let mut rng = rand::StdRng::from_entropy();
        let mut buf = vec![0; BUF_SIZE];

        Fun::new("std", move |b, _| b.iter(|| rng.fill_bytes(&mut buf)))
    };
    c.bench_functions("fill", vec![fill_aes, fill_aescore, fill_xoshiro, fill_std], ());
}

fn next_u64(c: &mut Criterion) {
    let next_aes = {
        let mut rng = aes_rng::AesRng::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ]);
        Fun::new("aes", move |b, _| b.iter(|| rng.next_u64()))
    };
    let next_xoshiro =
        {
            let mut rng = xoshiro::Xoshiro128StarStar::from_seed_u64(1);
            Fun::new("xoshiro", move |b, _| b.iter(|| rng.next_u64()))
        };
    let next_std = {
        let mut rng = rand::StdRng::from_entropy();
        Fun::new("std", move |b, _| b.iter(|| rng.next_u64()))
    };
    c.bench_functions("next_u64", vec![next_aes, next_xoshiro, next_std], ());
}

fn new(c: &mut Criterion) {
    let new_aes = Fun::new("aes", |b, _| b.iter(|| aes_rng::AesRng::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ])));
    let new_aescore = Fun::new("aescore", |b, _| b.iter(|| aes_rng::AesCore::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ])));
    let new_xoshiro = Fun::new("xoshiro", |b, _| b.iter(|| xoshiro::Xoshiro128StarStar::from_seed_u64(1)));
    let new_std = Fun::new("std", |b, _| b.iter(|| rand::StdRng::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ])));
    c.bench_functions("new", vec![new_aes, new_aescore, new_xoshiro, new_std], ());
}

criterion_group!(benches, fill, next_u64, new);
criterion_main!(benches);
