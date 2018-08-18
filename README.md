# RustCrypto: CSRNGs [![Build Status](https://travis-ci.org/RustCrypto/CSRNGs.svg?branch=master)](https://travis-ci.org/RustCrypto/CSRNGs)
Collection of Cryptographically Secure Random Number Generators (CSRNG) written
in pure Rust.

All algorithms are split into separate crates and implemented using
[`rand_core`](https://docs.rs/rand_core) traits. Most of the crates
do not require the standard library (i.e. `no_std` capable) and can
be easily used for bare-metal programming.

## Warnings

Crates in this repository have not yet received any formal cryptographic and
security reviews.

**USE AT YOUR OWN RISK.**

## Crates
| Name | Crates.io | Documentation |
| ---- | :--------:| :------------:|
| `aes-rng` | [![crates.io](https://img.shields.io/crates/v/aes-rng.svg)](https://crates.io/crates/aes-rng) | [![Documentation](https://docs.rs/aes-rng/badge.svg)](https://docs.rs/aes-rng) |

### Minimum Rust version
All crates in this repository support Rust 1.27 or higher. In future minimum
supported Rust version can be changed, but it will be done with the minor
version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
