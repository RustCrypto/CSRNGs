# [RustCrypto]: HMAC_DRBG

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]

Pure Rust implementation of the `HMAC_DRBG` HMAC-based deterministic random bit generator as
described in [NIST SP800-90A].

## Minimum Supported Rust Version

This crate requires **Rust 1.85** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/hmacdrbg?logo=rust
[crate-link]: https://crates.io/crates/hmacdrbg
[docs-image]: https://docs.rs/hmacdrbg/badge.svg
[docs-link]: https://docs.rs/hmacdrbg/
[build-image]: https://github.com/RustCrypto/CSRNGs/actions/workflows/hmacdrbg.yml/badge.svg
[build-link]: https://github.com/RustCrypto/CSRNGs/actions/workflows/hmacdrbg.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[NIST SP800-90A]: https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
