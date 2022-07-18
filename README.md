# RGB Standard Library

![Build](https://github.com/RGB-WG/rgb-std/workflows/Build/badge.svg)
![Tests](https://github.com/RGB-WG/rgb-std/workflows/Tests/badge.svg)
![Lints](https://github.com/RGB-WG/rgb-std/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/RGB-WG/rgb-std/branch/master/graph/badge.svg)](https://codecov.io/gh/RGB-WG/rgb-std)

[![crates.io](https://img.shields.io/crates/v/rgb-std)](https://crates.io/crates/rgb-std)
[![Docs](https://docs.rs/rgb-std/badge.svg)](https://docs.rs/rgb-std)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

RGB is confidential & scalable client-validated smart contracts for Bitcoin &
Lightning. To learn more about RGB please check [RGB blueprint][Blueprint] and
[RGB FAQ][FAQ] websites.

RGB standard library provides non-consensus-critical high-level API for RGB
applications. It is based on [RGB Core Lib][Core], implementing validation and
consensus rules for RGB smart contracts.

The development of the project is supported and managed by [LNP/BP Standards
Association][Association]. The design of RGB smart contract system and
implementation of this and underlying consensus libraries was done in 2019-2022
by [Dr Maxim Orlovsky][Max] basing or earlier ideas of client-side-validation
and RGB as "assets for bitcoin and LN" by [Peter Todd][Todd] and
[Giacomo Zucco][Zucco].

Nodes, implementing RGB functionality and using this library include:
* [RGB Node][RGB Node]: standalone & embeddable node for running RGB.
* [MyCitadel Node][MyCitadel Node]: wallet node providing RGB smart contract
  functionality integrated with Lightning network, bitcoin blockchain indexers,
  decentralized data storage and propagation (Storm) and wallet services. It can
  run as embedded, desktop, server or cloud-based node.

## Library

The library can be integrated into other rust projects via `Cargo.toml`
`[dependecies]` section:

```toml
rgb-std = "0.8.0"
```

If the library will be used for wallet applications and work with PSBT files,
than use `wallet` feature, which is non-default:

```toml
[dependencies]
rgb-core = { version = "0.8", features = ["wallet"] }
```

For serialization purposes library provides `serde` feature, which is turned off
by default.

## Command-line utility

The library also provides small command-line tool for hacking and debugging RGB
related data structures. In order to compile the tool you have to run the
following commands:

```console
rustup update
cargo install rgb-std
```

### Install with Docker

#### Build

Clone the repository and checkout to the desired version (here `v0.8.0`):

```console
$ git clone https://github.com/RGB-WG/rgb-std
$ cd rgb-std
$ git checkout v0.8.0
```

Build and tag the Docker image:

```console
$ docker build -t rgb:v0.8.0 .
```

#### Usage

```console
$ docker run rgb:v0.8.0 --help
```

### MSRV

Minimum supported rust compiler version (MSRV): 1.59, rust 2022 edition.

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
[Core]: https://github.com/RGB-WG/rgb-core
[RGB Node]: https://github.com/RGB-WG/rgb-node
[MyCitadel Node]: https://github.com/MyCitadel/mycitadel-node
[Max]: https://github.com/dr-orlovsky
[Todd]: https://petertodd.org/
[Zucco]: https://giacomozucco.com/
