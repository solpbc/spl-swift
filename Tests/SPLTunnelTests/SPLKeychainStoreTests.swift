// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Security
import Testing
@testable import SPLTunnel

@Suite("SPLKeychainStore", .serialized)
struct SPLKeychainStoreTests {
    @Test func policyDerivesMacProductionShapeQuery() throws {
        // Production policy must derive the DP keychain and access-group query shape without production literals.
        let policy = KeychainPolicy(
            service: Self.syntheticService(),
            accessGroup: "test.spl.keychain.access-group",
            useDataProtectionKeychain: true,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
        let base = policy.baseQuery()
        Self.expectBaseQuery(
            base,
            service: policy.service,
            account: "spl-pairing-bundle",
            accessGroup: "test.spl.keychain.access-group",
            useDataProtectionKeychain: true
        )

        let data = Data([0x01, 0x02])
        let add = policy.addAttributes(data: data)
        Self.expectBaseQuery(
            add,
            service: policy.service,
            account: "spl-pairing-bundle",
            accessGroup: "test.spl.keychain.access-group",
            useDataProtectionKeychain: true,
            extraKeys: [kSecValueData as String, kSecAttrAccessible as String]
        )
        #expect(add[kSecValueData as String] as? Data == data)
        #expect(add[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }

    @Test func policyDerivesMacAdHocPlainQuery() throws {
        // Ad-hoc policy must derive the plain keychain query shape.
        let policy = KeychainPolicy(
            service: Self.syntheticService(),
            accessGroup: nil,
            useDataProtectionKeychain: false,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
        let base = policy.baseQuery()
        Self.expectBaseQuery(
            base,
            service: policy.service,
            account: "spl-pairing-bundle",
            accessGroup: nil,
            useDataProtectionKeychain: false
        )
        #expect(base[kSecUseDataProtectionKeychain as String] == nil)
        #expect(base[kSecAttrAccessGroup as String] == nil)
    }

    @Test func policyDerivesIOSMigratableQuery() throws {
        // Backup-migratable policy must derive the iOS keychain query shape.
        let policy = KeychainPolicy(
            service: Self.syntheticService(),
            accessGroup: nil,
            useDataProtectionKeychain: false,
            accessibility: .afterFirstUnlock
        )
        let add = policy.addAttributes(data: Data([0x03]))
        Self.expectBaseQuery(
            add,
            service: policy.service,
            account: "spl-pairing-bundle",
            accessGroup: nil,
            useDataProtectionKeychain: false,
            extraKeys: [kSecValueData as String, kSecAttrAccessible as String]
        )
        #expect(add[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlock as String)
    }

    @Test func updateAttributesContainOnlyValueData() throws {
        // SecItemUpdate must carry value-only attributes to avoid errSecParam.
        let data = Data([0x04, 0x05])
        let attributes = KeychainPolicy(
            service: Self.syntheticService(),
            accessGroup: nil,
            useDataProtectionKeychain: false,
            accessibility: .afterFirstUnlock
        ).updateAttributes(data: data)

        #expect(Set(attributes.keys) == [kSecValueData as String])
        #expect(attributes[kSecValueData as String] as? Data == data)
    }

    @Test(.enabled(if: PlainKeychainCapability.isAvailable, "\(PlainKeychainCapability.reason)"))
    func saveTwiceOverwritesWithoutDeleteWindow() throws {
        // Saving must preserve add-then-update overwrite semantics.
        let store = Self.store(
            service: Self.syntheticService(),
            accessGroup: nil,
            useDataProtectionKeychain: false,
            accessibility: .afterFirstUnlock
        )
        try store.delete()
        defer {
            try? store.delete()
        }

        try store.save(Self.fixture(instanceID: "first"))
        let sentinelStatus = SecItemUpdate(
            store.policy.baseQuery() as CFDictionary,
            [kSecAttrComment as String: "l5-k2-sentinel"] as CFDictionary
        )
        #expect(sentinelStatus == errSecSuccess)

        let second = Self.fixture(instanceID: "second")
        try store.save(second)
        #expect(try store.load() == second)

        var query = store.policy.baseQuery()
        query[kSecReturnAttributes as String] = kCFBooleanTrue as Any
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let copyStatus = SecItemCopyMatching(query as CFDictionary, &result)
        #expect(copyStatus == errSecSuccess)
        let attributes = try #require(result as? [String: Any])
        #expect(attributes[kSecAttrComment as String] as? String == "l5-k2-sentinel")
    }

    @Test(.enabled(if: PlainKeychainCapability.isAvailable, "\(PlainKeychainCapability.reason)"))
    func plainKeychainSaveLoadDeleteRoundTrip() throws {
        // Plain keychain round-trip must clean up its synthetic service.
        let store = Self.store(
            service: Self.syntheticService(),
            accessGroup: nil,
            useDataProtectionKeychain: false,
            accessibility: .afterFirstUnlock
        )
        try store.delete()
        defer {
            try? store.delete()
        }

        let pairing = Self.fixture(instanceID: "plain-round-trip")
        try store.save(pairing)
        #expect(try store.load() == pairing)

        try store.delete()
        #expect(try store.load() == nil)
    }

    @Test(.enabled(
        if: DataProtectionAccessGroupKeychainCapability.isAvailable,
        "\(DataProtectionAccessGroupKeychainCapability.reason)"
    ))
    func dataProtectionAccessGroupSaveLoadDeleteRoundTrip() throws {
        // DP access-group round-trip must work when the host has the required access.
        let store = Self.store(
            service: Self.syntheticService(),
            accessGroup: "test.spl.keychain.access-group",
            useDataProtectionKeychain: true,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
        try store.delete()
        defer {
            try? store.delete()
        }

        let pairing = Self.fixture(instanceID: "dp-round-trip")
        try store.save(pairing)
        #expect(try store.load() == pairing)

        try store.delete()
        #expect(try store.load() == nil)
    }

    private static func store(
        service: String,
        accessGroup: String?,
        useDataProtectionKeychain: Bool,
        accessibility: KeychainPolicy.Accessibility
    ) -> SPLKeychainStore {
        SPLKeychainStore(
            policy: KeychainPolicy(
                service: service,
                accessGroup: accessGroup,
                useDataProtectionKeychain: useDataProtectionKeychain,
                accessibility: accessibility
            )
        )
    }

    private static func syntheticService() -> String {
        "test.spl.keychain.\(UUID().uuidString)"
    }

    private static func expectBaseQuery(
        _ query: [String: Any],
        service: String,
        account: String,
        accessGroup: String?,
        useDataProtectionKeychain: Bool,
        extraKeys: Set<String> = []
    ) {
        var expectedKeys: Set<String> = [
            kSecClass as String,
            kSecAttrService as String,
            kSecAttrAccount as String,
            kSecAttrSynchronizable as String,
        ]
        if accessGroup != nil {
            expectedKeys.insert(kSecAttrAccessGroup as String)
        }
        if useDataProtectionKeychain {
            expectedKeys.insert(kSecUseDataProtectionKeychain as String)
        }
        expectedKeys.formUnion(extraKeys)

        #expect(Set(query.keys) == expectedKeys)
        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(query[kSecAttrService as String] as? String == service)
        #expect(query[kSecAttrAccount as String] as? String == account)
        #expect(Self.boolValue(query[kSecAttrSynchronizable as String]) == false)
        #expect(query[kSecAttrAccessGroup as String] as? String == accessGroup)
        #expect(Self.boolValue(query[kSecUseDataProtectionKeychain as String]) == (useDataProtectionKeychain ? true : nil))
    }

    private static func boolValue(_ value: Any?) -> Bool? {
        guard let value else {
            return nil
        }
        if let bool = value as? Bool {
            return bool
        }
        let cfValue = value as CFTypeRef
        guard CFGetTypeID(cfValue) == CFBooleanGetTypeID() else {
            return nil
        }
        return CFBooleanGetValue((cfValue as! CFBoolean))
    }

    private static func fixture(instanceID: String) -> StoredPairing {
        StoredPairing(
            instanceID: instanceID,
            homeLabel: "test home",
            relayEndpoint: "wss://relay.example.invalid",
            fingerprint: "sha256:\(String(repeating: "a", count: 64))",
            clientCertPEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
            clientKeyPEM: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            caChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
            relayEnrollment: .enrolled(deviceToken: "device-token", expiresAt: nil),
            localEndpoints: [LocalEndpoint(host: "127.0.0.1", port: 7657, scope: "loopback")],
            pairedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
    }
}
