// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
@testable import SPLTunnel

final class PairingMaterialSpy: @unchecked Sendable {
    // why: the internal PairClient generator seam is synchronous and @Sendable; NSLock guards test counters.
    private let lock = NSLock()
    private var count = 0
    private var privateKeys: [String] = []

    var generationCount: Int {
        lock.withLock { count }
    }

    var generatedPrivateKeys: [String] {
        lock.withLock { privateKeys }
    }

    func generate(_ deviceLabel: String) throws -> PairingMaterial {
        lock.withLock {
            count += 1
            privateKeys.append("key-\(count)")
            return PairingMaterial(csrPEM: "csr-\(count)", privateKeyPEM: "key-\(count)")
        }
    }
}
