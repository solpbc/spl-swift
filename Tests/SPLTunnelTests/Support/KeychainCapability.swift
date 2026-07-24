// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Security
@testable import SPLTunnel

struct KeychainCapabilityResult: Sendable {
    let isAvailable: Bool
    let reason: String
}

enum PlainKeychainCapability {
    static let result: KeychainCapabilityResult = run()

    static var isAvailable: Bool {
        result.isAvailable
    }

    static var reason: String {
        result.reason
    }

    private static func run() -> KeychainCapabilityResult {
        let policy = KeychainPolicy(
            service: "test.spl.keychain.capability.\(UUID().uuidString)",
            accessGroup: nil,
            useDataProtectionKeychain: false,
            accessibility: .afterFirstUnlock
        )
        let deleteStatus = SecItemDelete(policy.baseQuery() as CFDictionary)
        if let result = environmentResult(for: deleteStatus, operation: "delete") {
            return result
        }
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            return availableAfterUnexpected(status: deleteStatus, operation: "delete")
        }

        let addStatus = SecItemAdd(policy.addAttributes(data: Data([0x01])) as CFDictionary, nil)
        defer {
            SecItemDelete(policy.baseQuery() as CFDictionary)
        }
        if let result = environmentResult(for: addStatus, operation: "add") {
            return result
        }
        guard addStatus == errSecSuccess else {
            return availableAfterUnexpected(status: addStatus, operation: "add")
        }

        return KeychainCapabilityResult(
            isAvailable: true,
            reason: "plain keychain writable"
        )
    }

    private static func environmentResult(for status: OSStatus, operation: String) -> KeychainCapabilityResult? {
        switch status {
        case errSecInteractionNotAllowed, errSecMissingEntitlement:
            KeychainCapabilityResult(
                isAvailable: false,
                reason: "plain keychain unavailable during \(operation), status \(status)"
            )
        default:
            nil
        }
    }

    private static func availableAfterUnexpected(status: OSStatus, operation: String) -> KeychainCapabilityResult {
        KeychainCapabilityResult(
            isAvailable: true,
            reason: "plain keychain \(operation) probe returned unexpected status \(status); test should run"
        )
    }
}

enum DataProtectionAccessGroupKeychainCapability {
    static let result: KeychainCapabilityResult = run()

    static var isAvailable: Bool {
        result.isAvailable
    }

    static var reason: String {
        result.reason
    }

    private static func run() -> KeychainCapabilityResult {
        let policy = KeychainPolicy(
            service: "test.spl.keychain.dp.capability.\(UUID().uuidString)",
            accessGroup: "test.spl.keychain.access-group",
            useDataProtectionKeychain: true,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
        let addStatus = SecItemAdd(policy.addAttributes(data: Data([0x01])) as CFDictionary, nil)
        defer {
            SecItemDelete(policy.baseQuery() as CFDictionary)
        }
        guard addStatus != errSecMissingEntitlement else {
            return KeychainCapabilityResult(
                isAvailable: false,
                reason: "DP/access-group keychain unavailable, status \(addStatus)"
            )
        }

        return KeychainCapabilityResult(
            isAvailable: true,
            reason: "DP/access-group keychain probe status \(addStatus); test should run"
        )
    }
}
