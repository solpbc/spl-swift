// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Testing
@testable import SPLTunnel

@Suite("SPLConformance")
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
        #expect(corpus.jidVectors.count == 9)

        var derivedJIDs: [String: String] = [:]
        for vector in corpus.jidVectors {
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

    @Test func parsePairLinkVectorsMatchAuthorityCorpus() throws {
        // Every refusal is compared field by field with what the library itself reports,
        // from parsing and from its own admission check. Falsified by a library error case
        // that covers two corpus kinds, or that drops a field the corpus pins.
        let vectors = corpus.vectors.filter { $0.operation == "parse_pair_link" }
        #expect(vectors.count == 73)

        var executed = 0
        for vector in vectors {
            guard let input = vector.input,
                  case .encoded(let encoding, let value) = input,
                  let expected = vector.expected else {
                Issue.record("vector \(vector.id) is missing pair-link input or expected output")
                continue
            }

            let observed: PairLinkObservation
            do {
                observed = try Self.observePairLink(encoding: encoding, value: value)
            } catch {
                Issue.record("vector \(vector.id) input could not be built: \(error)")
                continue
            }
            executed += 1
            switch expected.result {
            case "error":
                guard case .error(let reported) = observed else {
                    Issue.record("vector \(vector.id) expected a refusal, got \(observed)")
                    continue
                }
                #expect(reported.error == expected.error, "vector \(vector.id)")
            case "direct":
                guard case .direct(let pairURL, let candidates) = observed else {
                    Issue.record("vector \(vector.id) expected direct, got \(observed)")
                    continue
                }
                #expect(pairURL.kind == .direct, "vector \(vector.id)")
                #expect(candidates == expected.candidates?.map { PairCandidate(address: $0.host, port: UInt16($0.port)) }, "vector \(vector.id)")
                #expect(Self.hex(pairURL.nonceBytes) == expected.nonceHex, "vector \(vector.id)")
                #expect(Self.hex(pairURL.caFingerprintBytes) == expected.caFpHex, "vector \(vector.id)")
            case "relay":
                guard case .relay(let pairURL) = observed else {
                    Issue.record("vector \(vector.id) expected relay, got \(observed)")
                    continue
                }
                #expect(pairURL.kind == .relay, "vector \(vector.id)")
                #expect(Self.hex(pairURL.sBytes) == expected.secretHex, "vector \(vector.id)")
                #expect(Self.hex(pairURL.caFingerprintBytes) == expected.caFpSpkiHex, "vector \(vector.id)")
                #expect(pairURL.relayOrigin?.resolved().absoluteString == expected.relayOrigin, "vector \(vector.id)")
            default:
                Issue.record("vector \(vector.id) has an unknown result \(expected.result)")
            }
        }
        #expect(executed == 73)
    }

    @Test func everyCorpusRefusalKindHasExactlyOneLibraryCase() throws {
        // Falsified by one library case reporting two corpus kinds (a split that was undone),
        // or two library cases reporting the same corpus kind.
        let pairLinkVectors = corpus.vectors.filter { $0.operation == "parse_pair_link" }
        let kinds = Set(pairLinkVectors.compactMap { $0.expected?.error?.kind })
        #expect(kinds.count == 6)
        var casesByKind: [String: Set<String>] = [:]
        for vector in pairLinkVectors {
            guard case .encoded(let encoding, let value) = vector.input else {
                continue
            }
            guard case .error(let reported) = try Self.observePairLink(encoding: encoding, value: value),
                  let libraryCase = reported.libraryCase else {
                continue
            }
            casesByKind[reported.kind, default: []].insert(libraryCase)
        }
        #expect(Set(casesByKind.keys) == kinds)
        for (kind, cases) in casesByKind {
            #expect(cases.count == 1, "corpus kind \(kind) maps to \(cases.sorted())")
        }
        let allCases = casesByKind.values.flatMap { $0 }
        #expect(allCases.count == Set(allCases).count)
    }

    @Test func decodeCrockfordVectorMatchesAuthorityCorpus() throws {
        let vector = try #require(corpus.vectors.first { $0.operation == "decode_crockford" })
        guard case .text(let input) = try #require(vector.input),
              let expected = vector.expectedHex else {
            Issue.record("decode_crockford vector is missing input or expected bytes")
            return
        }
        #expect(try Crockford32.decode(input) == Self.bytes(expected), "vector \(vector.id)")
    }

    @Test func deriveRelayKeyVectorMatchesAuthorityCorpus() throws {
        let vector = try #require(corpus.vectors.first { $0.operation == "derive_relay_key" })
        guard let secretHex = vector.secretHex,
              let expectedHex = vector.expectedHex else {
            Issue.record("derive_relay_key vector is missing input or expected bytes")
            return
        }
        let key = try PairWindowRelayKey(sBytes: Self.bytes(secretHex))
        #expect(key.secPairKeyHeaderValue == expectedHex, "vector \(vector.id)")
    }

    /// Runs the library on one vector input: the URL parser for a link, the blob parser for
    /// a blob, then the library's own admission check for a direct link. The refusal is the
    /// library's error, mapped field by field; nothing here inspects the payload.
    private static func observePairLink(encoding: String, value: String) throws -> PairLinkObservation {
        let pairURL: PairURL
        do {
            switch encoding {
            case "link":
                pairURL = try PairURL.parse(try #require(URL(string: value)))
            case "blob_hex":
                pairURL = try PairURL(payload: try bytes(value))
            default:
                throw JournalIdentityCorpusError.unknownEncoding(encoding)
            }
            if pairURL.kind == .direct {
                try pairURL.admitDirectCandidates()
                return .direct(pairURL, PairClient.coalesceCandidates(pairURL.candidates))
            }
            return .relay(pairURL)
        } catch let error as PairURLError {
            return .error(ReportedRefusal(error))
        }
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
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
    let vectors: [RawVector]
    let jidVectors: [JournalIdentityVector]

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
        let histogram = Dictionary(grouping: document.vectors, by: \.operation).mapValues(\.count)
        guard histogram == Constants.operationHistogram else {
            throw JournalIdentityCorpusError.operationHistogramMismatch(histogram)
        }
        let jidVectors = try document.vectors
            .filter { $0.operation == "derive_jid" }
            .map(JournalIdentityVector.init)
        guard jidVectors.count == 9 else {
            throw JournalIdentityCorpusError.unexpectedVectorCount(jidVectors.count)
        }
        return JournalIdentityCorpus(vectors: document.vectors, jidVectors: jidVectors)
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
              adoption.authorityManifestSha256 == Constants.authorityManifestSHA256,
              adoption.conformance.test == Constants.conformanceTest,
              adoption.conformance.boundOperations == Constants.boundOperations,
              adoption.conformance.notImplemented.isEmpty else {
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
        static let authorityCommit = "f9b0c65d6f0b234aa70d97cfc477e0b6ae35aa65"
        static let authorityManifestSHA256 = "012fc87119ad9c831a76862a594f0529eb47bd647da549ca2acf7af1e91e8fce"
        static let bundleSemver = "9.0.0"
        static let bundleSchemaIdentity = "spl.pair-link-definition-bundle.schema.v1"
        static let adoptionSchemaVersion = 1
        static let consumerIdentifier = "solpbc/spl-swift"
        static let authorityRepository = "https://github.com/solpbc/spl"
        static let authorityManifestPath = "proto/definition/bundle/manifest.json"
        static let conformanceTest = "Tests/SPLTunnelTests/Conformance/JournalIdentityConformanceTests.swift"
        static let boundOperations = ["derive_jid", "parse_pair_link", "decode_crockford", "derive_relay_key"]
        static let operationHistogram = [
            "parse_pair_link": 73,
            "derive_jid": 9,
            "decode_crockford": 1,
            "derive_relay_key": 1,
        ]
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
        let conformance: AdoptionConformance
    }

    struct AdoptionConformance: Decodable {
        let test: String
        let boundOperations: [String]
        let notImplemented: [AdoptionOmission]
    }

    struct AdoptionOmission: Decodable {
        let operation: String
        let reason: String
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
        let input: RawInput?
        let expectedHex: String?
        let secretHex: String?
    }

    struct RawExpected: Decodable {
        let result: String
        let jid: String?
        let error: RawVectorError?
        let candidates: [RawCandidate]?
        let nonceHex: String?
        let caFpHex: String?
        let caFpSpkiHex: String?
        let relayOrigin: String?
        let secretHex: String?
    }

    enum RawInput: Decodable {
        case text(String)
        case encoded(String, String)

        private enum CodingKeys: String, CodingKey {
            case encoding
            case value
        }

        init(from decoder: Decoder) throws {
            if let value = try? decoder.singleValueContainer().decode(String.self) {
                self = .text(value)
                return
            }
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self = .encoded(
                try container.decode(String.self, forKey: .encoding),
                try container.decode(String.self, forKey: .value)
            )
        }
    }

    struct RawVectorError: Decodable, Equatable {
        let kind: String
        let address: String?
        let count: Int?
        let addressType: Int?
        let tag: Int?
        let expected: Int?
        let got: Int?
    }

    struct RawCandidate: Decodable {
        let host: String
        let port: UInt16
    }
}

private enum PairLinkObservation: CustomStringConvertible {
    case direct(PairURL, [PairCandidate])
    case relay(PairURL)
    case error(ReportedRefusal)

    var description: String {
        switch self {
        case .direct(_, _): "direct"
        case .relay(_): "relay"
        case .error(let refusal): "error \(refusal)"
        }
    }
}

/// A library refusal in the corpus's terms. Each corpus kind comes from exactly one
/// `PairURLError` case; a case the corpus does not cover keeps its own name, so it can
/// never pass as a corpus kind.
private struct ReportedRefusal: CustomStringConvertible {
    let error: JournalIdentityCorpus.RawVectorError
    let libraryCase: String?

    var kind: String { error.kind }
    var description: String { "\(error)" }

    init(_ error: PairURLError) {
        func refusal(
            _ kind: String,
            address: String? = nil,
            count: Int? = nil,
            addressType: Int? = nil,
            tag: Int? = nil,
            expected: Int? = nil,
            got: Int? = nil
        ) -> JournalIdentityCorpus.RawVectorError {
            JournalIdentityCorpus.RawVectorError(
                kind: kind,
                address: address,
                count: count,
                addressType: addressType,
                tag: tag,
                expected: expected,
                got: got
            )
        }
        switch error {
        case .truncated(let expected, let got):
            self.error = refusal("truncated", expected: expected, got: got)
            libraryCase = "truncated"
        case .invalidCandidateCount(let count):
            self.error = refusal("invalid_candidate_count", count: Int(count))
            libraryCase = "invalidCandidateCount"
        case .unsupportedAddrType(let addressType):
            self.error = refusal("unsupported_address_type", addressType: Int(addressType))
            libraryCase = "unsupportedAddrType"
        case .unsupportedCAFingerprintTag(let tag):
            self.error = refusal("unknown_ca_fp_tag", tag: Int(tag))
            libraryCase = "unsupportedCAFingerprintTag"
        case .invalidRelayOrigin:
            self.error = refusal("bad_relay_origin")
            libraryCase = "invalidRelayOrigin"
        case .disallowedDirectAddress(let address):
            self.error = refusal("disallowed_direct_ipv4", address: address)
            libraryCase = "disallowedDirectAddress"
        case .wrongScheme, .wrongHost, .wrongPath, .missingFragment, .invalidBase32,
             .invalidVersion, .lengthMismatch, .malformedOuterURL:
            self.error = refusal("uncovered:\(error)")
            libraryCase = nil
        }
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
    case operationHistogramMismatch([String: Int])
    case invalidJIDVector(String)
    case unrecognizedJIDResult(String)
    case invalidHex(String)
    case unknownEncoding(String)
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
