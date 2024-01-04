# RustCrypto: CSRNGs

Collection of Cryptographically Secure Random Number Generators (CSRNG) written
in pure Rust.

All algorithms are split into separate crates and implemented using
[`rand_core`](https://docs.rs/rand_core) traits. Most of the crates
do not require the standard library (i.e. `no_std` capable) and can
be easily used for bare-metal programming.

## Crates

| Name            | Crate name        | crates.io                                                                                                 | Docs                                                                             | MSRV                    |
|-----------------|-------------------|-----------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|-------------------------|
| [belt-hmac-rng] | [`belt-hmac-rng`] | [![crates.io](https://img.shields.io/crates/v/belt-hmac-rng.svg)](https://crates.io/crates/belt-hmac-rng) | [![Documentation](https://docs.rs/belt-hmac-rng/badge.svg)](https://docs.rs/aes) | ![MSRV 1.65][msrv-1.65] |

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.


[//]: # (badges)
[msrv-1.65]: https://img.shields.io/badge/rustc-1.65.0+-blue.svg

[//]: # (crates)
[`belt-hmac-rng`]: ./belt-hmac-rng

[//]: # (links)
[belt-hmac-rng]: https://apmi.bsu.by/assets/files/std/brng-spec25.pdf