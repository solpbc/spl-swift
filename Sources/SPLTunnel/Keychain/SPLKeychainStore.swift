// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Security

public struct KeychainPolicy: Sendable, Equatable {
    public let service: String
    public let account: String
    public let accessGroup: String?
    public let useDataProtectionKeychain: Bool
    public let accessibility: Accessibility

    public init(
        service: String,
        account: String = "spl-pairing-bundle",
        accessGroup: String?,
        useDataProtectionKeychain: Bool,
        accessibility: Accessibility
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.useDataProtectionKeychain = useDataProtectionKeychain
        self.accessibility = accessibility
    }

    public enum Accessibility: Sendable, Equatable {
        /// The SPL pairing bundle is intentionally backup-migratable (AfterFirstUnlock rather
        /// than a device-only keychain class) so restoring to a new device preserves pairing.
        case afterFirstUnlock

        /// The bundle holds a device-specific client cert + private key authenticating THIS
        /// Mac. It must never be backed up or moved by Migration Assistant; ThisDeviceOnly
        /// keeps it off backups and pinned to this device. Re-pairing on a new or restored Mac
        /// is the intended path — there is no migration (founder-decided 2026-07-02).
        case afterFirstUnlockThisDeviceOnly

        var secAttrValue: CFString {
            switch self {
            case .afterFirstUnlock:
                kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }
        }
    }
}

public enum SPLKeychainError: Error, Equatable, Sendable {
    case encodingFailed
    case decodingFailed
    case saveFailed(status: OSStatus)
    case loadFailed(status: OSStatus)
    case deleteFailed(status: OSStatus)
}

public struct SPLKeychainStore: Sendable {
    public let policy: KeychainPolicy

    public init(policy: KeychainPolicy) {
        self.policy = policy
    }

    public func save(_ pairing: StoredPairing) throws {
        let data = try Self.encode(pairing)
        let status = SecItemAdd(policy.addAttributes(data: data) as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            let updateStatus = SecItemUpdate(
                policy.baseQuery() as CFDictionary,
                policy.updateAttributes(data: data) as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw SPLKeychainError.saveFailed(status: updateStatus)
            }
        default:
            throw SPLKeychainError.saveFailed(status: status)
        }
    }

    public func load() throws -> StoredPairing? {
        var query = policy.baseQuery()
        query[kSecReturnData as String] = kCFBooleanTrue as Any
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw SPLKeychainError.loadFailed(status: errSecInternalError)
            }
            return try Self.decode(data)
        case errSecItemNotFound:
            return nil
        default:
            throw SPLKeychainError.loadFailed(status: status)
        }
    }

    public func delete() throws {
        let status = SecItemDelete(policy.baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SPLKeychainError.deleteFailed(status: status)
        }
    }

    private static func encode(_ pairing: StoredPairing) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        do {
            return try encoder.encode(pairing)
        } catch {
            throw SPLKeychainError.encodingFailed
        }
    }

    private static func decode(_ data: Data) throws -> StoredPairing {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(StoredPairing.self, from: data)
        } catch {
            throw SPLKeychainError.decodingFailed
        }
    }
}

extension KeychainPolicy {
    func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]

        if useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue as Any
        }
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        return query
    }

    func addAttributes(data: Data) -> [String: Any] {
        baseQuery().merging([
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility.secAttrValue,
        ]) { _, new in new }
    }

    func updateAttributes(data: Data) -> [String: Any] {
        // attributesToUpdate for SecItemUpdate must contain ONLY the new value — never
        // kSecClass or any query/primary key (kSecAttrService/kSecAttrAccount), which
        // return errSecParam (-50). Kept as an inspectable helper so the shape is unit-tested.
        [kSecValueData as String: data]
    }
}
