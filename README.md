# RGB wallet & standard libraries for smart contracts on Bitcoin & Lightning

![Build](https://github.com/RGB-WG/rgb-wallet/workflows/Build/badge.svg)
![Tests](https://github.com/RGB-WG/rgb-wallet/workflows/Tests/badge.svg)
![Lints](https://github.com/RGB-WG/rgb-wallet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/RGB-WG/rgb-wallet/branch/master/graph/badge.svg)](https://codecov.io/gh/RGB-WG/rgb-wallet)

[![crates.io](https://img.shields.io/crates/v/rgb-wallet)](https://crates.io/crates/rgb-wallet)
[![Docs](https://docs.rs/rgb-wallet/badge.svg)](https://docs.rs/rgb-wallet)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/rgb-wallet)](./LICENSE)

RGB is confidential & scalable client-validated smart contracts for Bitcoin &
Lightning. To learn more about RGB please check [RGB blueprint][Blueprint] and
[RGB FAQ][FAQ] websites.

RGB wallet standard library provides non-consensus-critical high-level API for 
RGB applications. It is based on [RGB Core Lib][Core], implementing validation 
and consensus rules for RGB smart contracts.

The development of the project is supported and managed by [LNP/BP Standards
Association][Association]. The design of RGB smart contract system and
implementation of this and underlying consensus libraries was done in 2019-2022
by [Dr Maxim Orlovsky][Max] basing or earlier ideas of client-side-validation
and RGB as "assets for bitcoin and LN" by [Peter Todd][Todd] and
[Giacomo Zucco][Zucco]. Upon the release of RGBv1 the protocol will be immutable
and this library will accept only bugfixes; i.e. it will be ossified by
requiring consensus ACK for the new changes across the large set of maintainers.

The current list of the projects based on the library include:
* [RGB Node][RGB Node]: standalone & embeddable node for running RGB.
* [MyCitadel Node][MyCitadel Node]: wallet node providing RGB smart contract
  functionality integrated with Lightning network, bitcoin blockchain indexers,
  decentralized data storage and propagation (Storm) and wallet services. It can
  run as embedded, desktop, server or cloud-based node.

## Library

The library can be integrated into other rust projects via `Cargo.toml`
`[dependencies]` section:

```toml
rgb-wallet = "0.10.0"
```

If the library will be used for wallet applications and work with PSBT files,
than use `wallet` feature, which is non-default:

```toml
[dependencies]
rgb-wallet = { version = "0.8", features = ["wallet"] }
```

For serialization purposes library provides `serde` feature, which is turned off
by default.

### MSRV

Minimum supported rust compiler version (MSRV) is shown in `msrv-toolchain.toml`.

## Contributing

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are
not supported and not planned to be supported; pull requests targeting them will
be declined.

## License

See [LICENCE](LICENSE) file.


[LNPBPs]: https://github.com/LNP-BP/LNPBPs
[Association]: https://lnp-bp.org
[Blueprint]: https://rgb.network
[FAQ]: https://rgbfaq.com
[Foundation]: https://github.com/LNP-BP/client_side_validation
[BP]: https://github.com/BP-WG/bp-core
[RGB Std]: https://github.com/RGB-WG/rgb-std
[RGB Node]: https://github.com/RGB-WG/rgb-node
[Max]: https://github.com/dr-orlovsky
[Todd]: https://petertodd.org/
[Zucco]: https://giacomozucco.com/
