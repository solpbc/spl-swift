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
        // proto/identity.md:18-30 requires the canonical P-256 SPKI form, with a
        // compressed point as the sole normalised input difference.
        // proto/identity.md:20,34-43 requires HKDF over canonical DER and the UUIDv8
        // version and RFC 9562 variant stamps.
        // proto/identity.md:47-53 requires one refusal outcome and forbids signalling
        // a refusal in-band as a jid.
        // proto/identity.md:69-71 requires all nine published jid vectors to reproduce
        // exactly.
        #expect(corpus.vectors.count == 9)

        var derivedJIDs: [String: String] = [:]
        for vector in corpus.vectors {
            let spki = try Self.bytes(vector.spkiDERHex)
            switch vector.expected {
            case .jid(let expected):
                let actual = try CertChain.jidFromSPKI(spki)
                #expect(actual == expected, "vector \(vector.id)")
                derivedJIDs[vector.id] = actual
            case .error:
                do {
                    _ = try CertChain.jidFromSPKI(spki)
                    Issue.record("vector \(vector.id) expected a refusal")
                } catch is CertChainError {
                } catch {
                    Issue.record("vector \(vector.id) expected a refusal, got \(error)")
                }
            }
        }

        let canonical = try #require(derivedJIDs["identity.jid.canonical"])
        let compressed = try #require(derivedJIDs["identity.jid.compressed-point"])
        #expect(canonical == compressed)
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
        guard jidVectors.count == 9 else {
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
        static let authorityCommit = "e639605b692577700648af470ee27da898c6df75"
        static let authorityManifestSHA256 = "bd3fcd1f6c7bc4eddeb35eb8981be47dc738a603e16064ad52adbda75867e7b1"
        static let bundleSemver = "5.0.0"
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
    }
}

private struct JournalIdentityVector {
    enum Expected {
        case jid(String)
        case error
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
            self.expected = .error
        default:
            throw JournalIdentityCorpusError.unrecognizedJIDResult(expected.result)
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
    case unrecognizedJIDResult(String)
    case invalidHex(String)
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
