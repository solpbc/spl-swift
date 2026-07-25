// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Synchronization
@testable import SPLTunnel

final class PairingMaterialSpy: Sendable {
    private struct State {
        var count = 0
        var privateKeys: [String] = []
    }

    private let state = Mutex(State())

    var generationCount: Int {
        state.withLock { $0.count }
    }

    var generatedPrivateKeys: [String] {
        state.withLock { $0.privateKeys }
    }

    func generate(_ deviceLabel: String) throws -> PairingMaterial {
        state.withLock {
            $0.count += 1
            let count = $0.count
            let privateKey = "key-\(count)"
            $0.privateKeys.append(privateKey)
            return PairingMaterial(csrPEM: "csr-\(count)", privateKeyPEM: privateKey)
        }
    }
}
