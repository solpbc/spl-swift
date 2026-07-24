# spl-swift

The SPL (**solstone private link**) client library for Apple platforms, as a Swift package. Module name: **`SPLTunnel`**.

SPL is the encrypted connection between a [solstone](https://solstone.app) observer app and the owner's journal: mutual TLS with a pairing-minted client certificate, carried over a direct LAN connection or a WebSocket relay when no direct path exists. This package implements the client side end to end — pair-link parsing and the pairing ceremony, candidate racing, inner mTLS, stream multiplexing with flow control, device-token refresh, keychain-stored pairing state, and the local loopback proxy that carries application HTTP over the tunnel.

The wire protocol is specified in the [`proto/` directory of solpbc/spl](https://github.com/solpbc/spl/tree/main/proto); those documents are the source of truth for all wire behavior here, and this package's conformance test suite is keyed to them clause by clause.

## Status

Alpha. This package is the shared successor to the tunnel implementations previously vendored inside [solstone-macos](https://github.com/solpbc/solstone-macos) and [solstone-swift](https://github.com/solpbc/solstone-swift); both apps are migrating to consume it by exact version tag.

## Requirements

- Swift 6.2 toolchain
- macOS 15+ / iOS 26+
- Only dependency: [swift-crypto](https://github.com/apple/swift-crypto)

## Build and test

```sh
make install   # resolve dependencies
make test      # unit tests (macOS destination)
make ci        # hygiene gates + build + tests on macOS and iOS Simulator
```

Tests use Swift Testing. Integration suites that exercise a live journal or relay are environment-gated and off by default.

## Privacy

This library contains no telemetry, analytics, or crash reporting, and never will. It talks only to the owner's own journal and the relay endpoint the owner's pairing names.

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
