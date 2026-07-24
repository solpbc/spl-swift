# Agent guide — spl-swift

This repo is the SPL (solstone private link) client library for Apple platforms — module `SPLTunnel`. It is security-critical transport code consumed by the solstone macOS and iOS apps via exact version tags. Read this file fully before changing anything.

## What governs this codebase

1. **The protocol documents win.** All wire behavior follows the [`proto/` docs in solpbc/spl](https://github.com/solpbc/spl/tree/main/proto) (framing, session, pairing, pair-window, tokens). When code and doc disagree, the doc is authoritative; if the doc appears wrong, raise it — never silently invent wire behavior. Conformance tests cite the doc clause they pin; keep that discipline for every new wire behavior.
2. **This is a library with exactly two consumers.** Public API exists only for a need one of the consuming apps actually has today. No speculative generality, no configuration nobody sets, no platform abstractions for hypothetical futures.
3. **Platform differences are configuration, not conditionals.** Deliberate per-platform behavior (keychain policy, keepalive policy, timing) is expressed as explicit config values the consuming app supplies. The `#if os(...)` budget is **one**: TLS identity assembly. A change that adds a second platform conditional is wrong until proven otherwise.
4. **Strict concurrency, no escape hatches.** Swift 6 language mode; actors own mutable state; `nonisolated(unsafe)` and `DispatchQueue.main.async` are forbidden (CI-enforced). `@unchecked Sendable` is allowed only for lock-guarded one-shot bridges at framework-callback boundaries, each carrying a `// why:` comment.
5. **Dependencies: swift-crypto, and nothing else, ever.** No telemetry, analytics, or crash reporting in any form — this is a covenant, not a preference. A change that adds a dependency or any phone-home behavior will not ship.
6. **Never log secrets.** No token, key, certificate, nonce, pairing-link fragment, or payload bytes in any log line at any level. Lifecycle decisions log at `.notice` (they must survive to post-hoc log inspection); high-volume data-path lines stay at `.debug`.

## Conventions

- Layout: `Sources/SPLTunnel/{Framing,Mux,Dial,TLS,Tunnel,Loopback,Pair,Crypto,Keychain,Policy,Support}`, tests mirror it under `Tests/SPLTunnelTests/`.
- Build/test: `make install`, `make test`, `make ci` (hygiene gates + macOS + iOS Simulator destinations). All must be green before any commit.
- Tests use Swift Testing. Timing-sensitive suites run serialized; assert on completion signals, not wall-clock sleeps. A behavior fix lands with a test that fails on the pre-fix code where a compiling red is possible.
- Every Swift source file carries the SPDX header (`AGPL-3.0-only`).

## Safety rails

- **Never weaken a gate to get green** — no skipping tests, no loosening hygiene greps, no `-warnings-as-errors` removal. If a gate is red for environmental reasons, say so and stop.
- **Never retag or force-push a tag.** Consumers cache by tag hash; a moved tag silently serves stale or wrong code. New content = new tag, always.
- **No GitHub workflows.** CI is operator-run locally; do not add `.github/workflows/`.
- **No pushes to consumer repos from here.** Migrating the apps is separate, operator-driven work.
- Releases (tags) are operator approval only.
