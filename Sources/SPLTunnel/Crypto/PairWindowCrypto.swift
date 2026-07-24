// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation

struct PairWindowRelayKey: Sendable, Equatable {
    private let bytes: [UInt8]

    /// Derives RK with HKDF-SHA256 from S, using 32 zero salt bytes,
    /// info "spl-pair-window-v1", and a 16-byte output per proto/pair-window.md:16-22.
    init(sBytes: [UInt8]) throws {
        guard sBytes.count == 8 else {
            throw PairWindowRelayKeyError.invalidSLength(actual: sBytes.count)
        }

        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(sBytes)),
            salt: Data(count: 32),
            info: Data("spl-pair-window-v1".utf8),
            outputByteCount: 16
        )
        bytes = key.withUnsafeBytes { Array($0) }
    }

    var secPairKeyHeaderValue: String {
        CertChain.hex(bytes)
    }

    // Deliberately not CustomStringConvertible or Codable; proto/pair-window.md:112 says never log S, RK, the pair-link fragment, or the inner nonce.
}

enum PairWindowRelayKeyError: Error, Equatable, Sendable {
    case invalidSLength(actual: Int)
}
