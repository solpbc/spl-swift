// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Security
@testable import SPLTunnel

struct IdentityAssemblyCapabilityResult: Sendable {
    let isAvailable: Bool
    let reason: String
    let rawStatuses: IdentityAssemblyRawStatuses?
}

struct IdentityAssemblyRawStatuses: Sendable {
    let initialCertDelete: OSStatus
    let initialKeyDelete: OSStatus
    let certAdd: OSStatus
    let keyAdd: OSStatus
    let identityCopy: OSStatus
    let cleanupCertDelete: OSStatus
    let cleanupKeyDelete: OSStatus

    var summary: String {
        "initialCertDelete=\(initialCertDelete) initialKeyDelete=\(initialKeyDelete) certAdd=\(certAdd) keyAdd=\(keyAdd) identityCopy=\(identityCopy) cleanupCertDelete=\(cleanupCertDelete) cleanupKeyDelete=\(cleanupKeyDelete)"
    }
}

enum IdentityAssemblyCapability {
    static let result: IdentityAssemblyCapabilityResult = run()

    static var isAvailable: Bool {
        result.isAvailable
    }

    static var reason: String {
        result.reason
    }

    private static func run() -> IdentityAssemblyCapabilityResult {
        do {
            let fixture = try TestCA.make()
            _ = try InnerTLS.makeIdentity(pairing: fixture.pairing)
            return IdentityAssemblyCapabilityResult(
                isAvailable: true,
                reason: "identity-backed TLS assembly available",
                rawStatuses: nil
            )
        } catch {
            do {
                let fixture = try TestCA.make()
                let statuses = try rawKeychainStatuses(fixture: fixture)
                return IdentityAssemblyCapabilityResult(
                    isAvailable: false,
                    reason: "identity-backed TLS unavailable in this XCTest bundle; \(statuses.summary)",
                    rawStatuses: statuses
                )
            } catch {
                return IdentityAssemblyCapabilityResult(
                    isAvailable: false,
                    reason: "identity-backed TLS unavailable in this XCTest bundle; raw status probe failed: \(error)",
                    rawStatuses: nil
                )
            }
        }
    }

    private static func rawKeychainStatuses(fixture: TestCA.Bundle) throws -> IdentityAssemblyRawStatuses {
        guard let leaf = try CertChain.certificates(fromPEM: fixture.clientCertificatePEM).first else {
            throw InnerTLSError.invalidCertificate
        }
        let privateKey = try CryptoCSR.pkcs8PEMToPrivateKey(fixture.clientPrivateKeyPEM)
        let keyData = Data(privateKey.publicKey.x963Representation + privateKey.rawRepresentation)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 256,
        ]
        var keyError: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &keyError) else {
            throw InnerTLSError.invalidPrivateKey
        }

        let label = "app.solstone.swift.spl.identity.capability.\(UUID().uuidString)"
        let initialCertDelete = delete(itemClass: kSecClassCertificate, label: label)
        let initialKeyDelete = delete(itemClass: kSecClassKey, label: label)

        let certAdd = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: leaf,
            kSecAttrLabel as String: label,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)

        let keyAdd = SecItemAdd([
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: secKey,
            kSecAttrLabel as String: label,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)

        var result: CFTypeRef?
        let identityCopy = SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: kCFBooleanTrue as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ] as CFDictionary, &result)

        let cleanupCertDelete = delete(itemClass: kSecClassCertificate, label: label)
        let cleanupKeyDelete = delete(itemClass: kSecClassKey, label: label)

        return IdentityAssemblyRawStatuses(
            initialCertDelete: initialCertDelete,
            initialKeyDelete: initialKeyDelete,
            certAdd: certAdd,
            keyAdd: keyAdd,
            identityCopy: identityCopy,
            cleanupCertDelete: cleanupCertDelete,
            cleanupKeyDelete: cleanupKeyDelete
        )
    }

    private static func delete(itemClass: CFString, label: String) -> OSStatus {
        SecItemDelete([
            kSecClass as String: itemClass,
            kSecAttrLabel as String: label,
        ] as CFDictionary)
    }
}
