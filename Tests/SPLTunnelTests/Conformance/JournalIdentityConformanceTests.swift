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
        let vectors = corpus.vectors.filter { $0.operation == "parse_pair_link" }
        #expect(vectors.count == 73)

        for vector in vectors {
            guard let input = vector.input,
                  case .encoded(let encoding, let value) = input,
                  let expected = vector.expected else {
                Issue.record("vector \(vector.id) is missing pair-link input or expected output")
                continue
            }

            let observed = Self.observePairLink(encoding: encoding, value: value)
            switch expected.result {
            case "error":
                guard case .error(let kind) = observed else {
                    Issue.record("vector \(vector.id) expected a refusal")
                    continue
                }
                #expect(kind == expected.error?.kind, "vector \(vector.id)")
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

    private static func observePairLink(encoding: String, value: String) -> PairLinkObservation {
        let url: URL
        let payload: [UInt8]
        switch encoding {
        case "link":
            guard let parsedURL = URL(string: value),
                  let components = URLComponents(url: parsedURL, resolvingAgainstBaseURL: false),
                  let fragment = components.percentEncodedFragment,
                  let decoded = try? Crockford32.decode(fragment) else {
                return .error("truncated")
            }
            url = parsedURL
            payload = decoded
        case "blob_hex":
            guard let decoded = try? bytes(value),
                  let link = URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(decoded))") else {
                return .error("truncated")
            }
            url = link
            payload = decoded
        default:
            return .error("truncated")
        }

        do {
            let pairURL = try PairURL.parse(url)
            if pairURL.kind == .direct {
                guard pairURL.candidates.allSatisfy({
                    TunnelAddressClassifier.isValidDirectDialAddressLiteral($0.address)
                }) else {
                    return .error("disallowed_direct_ipv4")
                }
                return .direct(pairURL, PairClient.coalesceCandidates(pairURL.candidates))
            }
            return .relay(pairURL)
        } catch let error as PairURLError {
            return .error(error.kind(for: payload))
        } catch {
            return .error("invalid_pair_link")
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
        static let authorityCommit = "bc0eec0ac4230df023abb0d88bee812358b3fe60"
        static let authorityManifestSHA256 = "5dc0c160ed9781964de2c6debe0b6e93f6b9d72e040a2b614356d1355b26dc64"
        static let bundleSemver = "8.0.1"
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

    struct RawVectorError: Decodable {
        let kind: String
    }

    struct RawCandidate: Decodable {
        let host: String
        let port: UInt16
    }
}

private enum PairLinkObservation: CustomStringConvertible {
    case direct(PairURL, [PairCandidate])
    case relay(PairURL)
    case error(String)

    var description: String {
        switch self {
        case .direct(_, _): "direct"
        case .relay(_): "relay"
        case .error(let kind): "error \(kind)"
        }
    }
}

private extension PairURLError {
    func kind(for payload: [UInt8]) -> String {
        switch self {
        case .missingFragment:
            return "truncated"
        case .invalidLength(_):
            if payload.first == 0x05, payload.count >= 3,
               !(1...4).contains(Int(payload[2])) {
                return "invalid_candidate_count"
            }
            return "truncated"
        case .unsupportedAddrType(_):
            return "unsupported_address_type"
        case .unsupportedCAFingerprintTag(_):
            return "unknown_ca_fp_tag"
        case .invalidRelayOrigin:
            return "bad_relay_origin"
        default:
            return "invalid_pair_link"
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
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
