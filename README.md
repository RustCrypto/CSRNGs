# RustCrypto: CSRNGs [![Build Status](https://travis-ci.org/RustCrypto/CSRNGs.svg?branch=master)](https://travis-ci.org/RustCrypto/CSRNGs)
Collection of Cryptographically Secure Random Number Generators (CSRNG) written
in pure Rust.

All algorithms are split into separate crates and implemented using
[`rand_core`](https://docs.rs/rand_core) traits. Most of the crates
do not require the standard library (i.e. `no_std` capable) and can
be easily used for bare-metal programming.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
