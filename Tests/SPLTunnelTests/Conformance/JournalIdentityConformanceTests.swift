// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Testing
@testable import SPLTunnel

@Suite("JournalIdentityConformance")
struct JournalIdentityConformanceTests {
    private let corpus: JournalIdentityCorpus

    init() throws {
        corpus = try JournalIdentityCorpus.load()
    }

    @Test func deriveJIDVectorsMatchAuthorityCorpus() throws {
        // proto/identity.md:18-22 requires parsed P-256 SPKI validation and canonical DER derivation.
        // proto/identity.md:28-31 pins the HKDF labels, UUIDv8 version, and RFC 9562 variant bits.
        // proto/identity.md:37-45 requires distinct not_p256, invalid_point, and malformed_spki refusals.
        // proto/identity.md:65-67 requires all five published jid vectors to reproduce exactly.
        #expect(corpus.vectors.count == 5)

        var derivedJIDs: [String: String] = [:]
        for vector in corpus.vectors {
            let spki = try Self.bytes(vector.spkiDERHex)
            switch vector.expected {
            case .jid(let expected):
                let actual = try CertChain.jidFromSPKI(spki)
                #expect(actual == expected, "vector \(vector.id)")
                derivedJIDs[vector.id] = actual
            case .error(let kind):
                let expected = try Self.certChainError(for: kind)
                do {
                    _ = try CertChain.jidFromSPKI(spki)
                    Issue.record("vector \(vector.id) expected \(expected)")
                } catch let actual as CertChainError {
                    #expect(actual == expected, "vector \(vector.id)")
                } catch {
                    Issue.record("vector \(vector.id) expected \(expected), got \(error)")
                }
            }
        }

        let canonical = try #require(derivedJIDs["identity.jid.canonical"])
        let compressed = try #require(derivedJIDs["identity.jid.compressed-point"])
        #expect(canonical == compressed)
    }

    private static func certChainError(for kind: String) throws -> CertChainError {
        switch kind {
        case "not_p256":
            .notP256
        case "invalid_point":
            .invalidPoint
        case "malformed_spki":
            .malformedSPKI
        default:
            throw JournalIdentityCorpusError.unrecognizedErrorKind(kind)
        }
    }

    private static func bytes(_ hex: String) throws -> [UInt8] {
        guard hex.count.isMultiple(of: 2) else {
            throw JournalIdentityCorpusError.invalidHex(hex)
        }
        return try stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 2)
            guard let byte = UInt8(hex[start..<end], radix: 16) else {
                throw JournalIdentityCorpusError.invalidHex(hex)
            }
            return byte
        }
    }
}

private struct JournalIdentityCorpus {
    let vectors: [JournalIdentityVector]

    static func load() throws -> JournalIdentityCorpus {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let root = try #require(Bundle.module.url(forResource: "Corpus", withExtension: nil))
        let bundle = root.appending(path: "bundle")
        let manifestURL = bundle.appending(path: "manifest.json")
        let manifestData = try Data(contentsOf: manifestURL)
        guard sha256(manifestData) == Constants.authorityManifestSHA256 else {
            throw JournalIdentityCorpusError.manifestDigestMismatch
        }
        let manifest = try decoder.decode(Manifest.self, from: manifestData)
        try verifyManifestConstants(manifest)
        try verifyBundleInventory(bundle, manifest: manifest)
        try verifyPayloadDigests(bundle, manifest: manifest)

        let adoptionData = try Data(contentsOf: root.appending(path: "adoption.json"))
        let adoption = try decoder.decode(Adoption.self, from: adoptionData)
        try verifyAdoption(adoption, manifest: manifest)

        let vectorsData = try Data(contentsOf: bundle.appending(path: "vectors.json"))
        let document = try decoder.decode(VectorDocument.self, from: vectorsData)
        let jidVectors = try document.vectors
            .filter { $0.operation == "derive_jid" }
            .map(JournalIdentityVector.init)
        guard jidVectors.count == 5 else {
            throw JournalIdentityCorpusError.unexpectedVectorCount(jidVectors.count)
        }
        return JournalIdentityCorpus(vectors: jidVectors)
    }

    private static func verifyManifestConstants(_ manifest: Manifest) throws {
        guard manifest.bundleSchemaIdentity == Constants.bundleSchemaIdentity,
              manifest.bundleSemver == Constants.bundleSemver else {
            throw JournalIdentityCorpusError.manifestMetadataMismatch
        }
    }

    private static func verifyBundleInventory(_ bundle: URL, manifest: Manifest) throws {
        let actual = try Set(FileManager.default.contentsOfDirectory(atPath: bundle.path))
        let expectedPaths = try validatedPaths(manifest.files)
        let expected = expectedPaths.union(["manifest.json"])
        guard actual == expected else {
            throw JournalIdentityCorpusError.inventoryMismatch(
                missing: expected.subtracting(actual).sorted(),
                unexpected: actual.subtracting(expected).sorted()
            )
        }
    }

    private static func verifyPayloadDigests(_ bundle: URL, manifest: Manifest) throws {
        for file in manifest.files {
            let data = try Data(contentsOf: bundle.appending(path: file.path))
            guard sha256(data) == file.sha256 else {
                throw JournalIdentityCorpusError.payloadDigestMismatch(file.path)
            }
        }
    }

    private static func verifyAdoption(_ adoption: Adoption, manifest: Manifest) throws {
        guard adoption.spdxLicenseIdentifier == "AGPL-3.0-only",
              adoption.adoptionSchemaVersion == Constants.adoptionSchemaVersion,
              adoption.consumerIdentifier == Constants.consumerIdentifier,
              adoption.authorityRepository == Constants.authorityRepository,
              adoption.authorityCommit == Constants.authorityCommit,
              adoption.bundleSemver == Constants.bundleSemver,
              adoption.authorityManifestPath == Constants.authorityManifestPath,
              adoption.authorityManifestSha256 == Constants.authorityManifestSHA256 else {
            throw JournalIdentityCorpusError.adoptionMetadataMismatch
        }
        let adoptionPaths = try validatedPaths(adoption.bundleFiles)
        let manifestPaths = try validatedPaths(manifest.files)
        guard adoptionPaths == manifestPaths,
              adoption.bundleFiles == manifest.files else {
            throw JournalIdentityCorpusError.adoptionFilesMismatch
        }
    }

    private static func validatedPaths(_ files: [FileDigest]) throws -> Set<String> {
        var paths: Set<String> = []
        for file in files {
            guard !file.path.contains("/"), file.path != "manifest.json", !file.path.isEmpty,
                  paths.insert(file.path).inserted else {
                throw JournalIdentityCorpusError.invalidBundlePath(file.path)
            }
        }
        return paths
    }
}

private extension JournalIdentityCorpus {
    enum Constants {
        static let authorityCommit = "ddfe13b2abce2fd40acbe2e18d0551727e7ef757"
        static let authorityManifestSHA256 = "0d78abe38a2cf23af3b98c9a496bb3c6f1c94bc7c0467eafa43726af3a3603ea"
        static let bundleSemver = "2.0.0"
        static let bundleSchemaIdentity = "spl.pair-link-definition-bundle.schema.v1"
        static let adoptionSchemaVersion = 1
        static let consumerIdentifier = "solpbc/spl-swift"
        static let authorityRepository = "https://github.com/solpbc/spl"
        static let authorityManifestPath = "proto/definition/bundle/manifest.json"
    }

    struct Manifest: Decodable {
        let bundleSchemaIdentity: String
        let bundleSemver: String
        let files: [FileDigest]
    }

    struct Adoption: Decodable {
        let spdxLicenseIdentifier: String
        let adoptionSchemaVersion: Int
        let consumerIdentifier: String
        let authorityRepository: String
        let authorityCommit: String
        let bundleSemver: String
        let authorityManifestPath: String
        let authorityManifestSha256: String
        let bundleFiles: [FileDigest]
    }

    struct FileDigest: Decodable, Equatable {
        let path: String
        let sha256: String
    }

    struct VectorDocument: Decodable {
        let vectors: [RawVector]
    }

    struct RawVector: Decodable {
        let id: String
        let operation: String
        let spkiDerHex: String?
        let expected: RawExpected?
    }

    struct RawExpected: Decodable {
        let result: String
        let jid: String?
        let error: RawError?
    }

    struct RawError: Decodable {
        let kind: String
    }
}

private struct JournalIdentityVector {
    enum Expected {
        case jid(String)
        case error(String)
    }

    let id: String
    let spkiDERHex: String
    let expected: Expected

    init(_ raw: JournalIdentityCorpus.RawVector) throws {
        guard let spkiDERHex = raw.spkiDerHex, let expected = raw.expected else {
            throw JournalIdentityCorpusError.invalidJIDVector(raw.id)
        }
        id = raw.id
        self.spkiDERHex = spkiDERHex
        switch expected.result {
        case "jid":
            guard let jid = expected.jid else {
                throw JournalIdentityCorpusError.invalidJIDVector(raw.id)
            }
            self.expected = .jid(jid)
        case "error":
            guard let kind = expected.error?.kind else {
                throw JournalIdentityCorpusError.invalidJIDVector(raw.id)
            }
            self.expected = .error(kind)
        default:
            throw JournalIdentityCorpusError.invalidJIDVector(raw.id)
        }
    }
}

private enum JournalIdentityCorpusError: Error {
    case manifestDigestMismatch
    case manifestMetadataMismatch
    case inventoryMismatch(missing: [String], unexpected: [String])
    case payloadDigestMismatch(String)
    case adoptionMetadataMismatch
    case adoptionFilesMismatch
    case invalidBundlePath(String)
    case unexpectedVectorCount(Int)
    case invalidJIDVector(String)
    case unrecognizedErrorKind(String)
    case invalidHex(String)
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
