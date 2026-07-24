# spl-swift

The SPL (**solstone private link**) client library for Apple platforms, as a Swift package. Module name: **`SPLTunnel`**.

SPL is the encrypted connection between a [solstone](https://solstone.app) observer app and the owner's journal: mutual TLS with a pairing-minted client certificate, carried over a direct LAN connection or a WebSocket relay when no direct path exists. This package implements the client side end to end: pair-link parsing and the pairing ceremony, candidate racing, inner mTLS, stream multiplexing with flow control, device-token refresh, keychain-stored pairing state, and the local loopback proxy that carries application HTTP over the tunnel.

The wire protocol is specified in the [`proto/` directory of solpbc/spl](https://github.com/solpbc/spl/tree/main/proto). Those documents are the source of truth for all wire behavior here. Conformance tests cite the exact proto line ranges they pin, and the remaining client-surface gaps are documented explicitly: the undocumented 0x05 multi-candidate pair-link form, RESET receiver payload-length tolerance where the framing doc is silent, browser subprotocol failure semantics that this native package cannot observe, and the direct public-IP refusal clause that currently needs a source behavior change before it can be pinned end to end.

## Status

Alpha. This package is the shared successor to the tunnel implementations previously vendored inside [solstone-macos](https://github.com/solpbc/solstone-macos) and [solstone-swift](https://github.com/solpbc/solstone-swift); app migration is operator-driven and version-tagged.

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

Tests use Swift Testing. Local integration suites are disabled unless `SPL_INTEGRATION=1` is set. Live interop is disabled unless `SPL_LIVE=1` is set and both `SPL_PAIR_URL` and `SPL_RELAY_ENDPOINT` are supplied explicitly; there is no baked relay default.

## Policy configuration

Platform differences are configuration, not conditionals. Consuming apps supply:

- `KeychainPolicy` through `SPLKeychainStore(policy:)`, including `service`, `account`, optional `accessGroup`, `useDataProtectionKeychain`, and `accessibility`.
- `SessionPolicy`, composed from `RacePolicy` and `KeepalivePolicy`, when `TunnelSession` or `TunnelSupervisor` needs non-default timing.
- `SPLClientInfo`, whose `userAgent` becomes the per-app `User-Agent` on dial and pair requests.

## Adapter guidance

The library reports connection progress through `TunnelState` and `stateUpdates` on `TunnelSession` and `TunnelSupervisor`; it does not ship app-window state. A connect-window terminal signal is an adapter-layer pattern: the app observes those state transitions, decides which failures are terminal for its UI, and keeps that policy outside `SPLTunnel`.

`LoopbackProxy(opener:)` accepts any `MuxStreamOpening` implementation, so apps can hand it a `TunnelSession` for a single connection lifecycle or a `TunnelSupervisor` when reconnect behavior should preserve the loopback port.

## Privacy

This library contains no telemetry, analytics, or crash reporting, and never will. It talks only to the owner's own journal and the relay endpoint the owner's pairing names.

## License

AGPL-3.0-only - see [LICENSE](LICENSE).
