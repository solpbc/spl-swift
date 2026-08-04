// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Security
import Testing
import SPLTunnel

@Suite("CertChain")
struct CertChainTests {
    private let cert1 = """
    -----BEGIN CERTIFICATE-----
    MIIBdTCCARugAwIBAgIUVMEtHY4txnB9yvPieVZOPQb8B/swCgYIKoZIzj0EAwIw
    EDEOMAwGA1UEAwwFdGVzdDEwHhcNMjYwNTExMDU0OTI4WhcNMzYwNTA4MDU0OTI4
    WjAQMQ4wDAYDVQQDDAV0ZXN0MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPih
    dGj0TbzBAXX6uLTt/rKpwd7t8DohOFLZ44i9KlffKSrMHvo2DufP/oUVB+V/jJy9
    0PQuCc+/j2NrTtHOh3yjUzBRMB0GA1UdDgQWBBQrAyo4k6cTcZB56UCx7ZcJPWxH
    ezAfBgNVHSMEGDAWgBQrAyo4k6cTcZB56UCx7ZcJPWxHezAPBgNVHRMBAf8EBTAD
    AQH/MAoGCCqGSM49BAMCA0gAMEUCIA0cayl/grfqS8xzPnv3+A6Wqb7NL8QvfgPu
    ZBXoDWAEAiEAgCfoRUL0QMRHSW4FKBCyqn63nZBYfgcl2q4I+kYz0y4=
    -----END CERTIFICATE-----
    """

    private let cert2 = """
    -----BEGIN CERTIFICATE-----
    MIIBdjCCARugAwIBAgIUPmc8qjlLPIA4EFu09uWC+SpZMBAwCgYIKoZIzj0EAwIw
    EDEOMAwGA1UEAwwFdGVzdDIwHhcNMjYwNTExMDU0OTI4WhcNMzYwNTA4MDU0OTI4
    WjAQMQ4wDAYDVQQDDAV0ZXN0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE34
    z7zq08sFkDWZCydwYPbUZ0p6axn7HVfFfMvoBSJI1sx0ugGzsO20gUKvQkS1f82o
    wPZALFfM/2QhFxaXibajUzBRMB0GA1UdDgQWBBS0hMPoitOyZ9HNf6Jn9N62yCtN
    yzAfBgNVHSMEGDAWgBS0hMPoitOyZ9HNf6Jn9N62yCtNyzAPBgNVHRMBAf8EBTAD
    AQH/MAoGCCqGSM49BAMCA0kAMEYCIQCp2/epKon4CeHgWUTFJT7SjTpDODpJONYu
    C+oCUlJiOQIhAPO48QBJMB7pJ3gRqUFTGg5j2lBpky934j0CPQvU/w8V
    -----END CERTIFICATE-----
    """

    private let cert1Fingerprint = "005a64c08d69da268c62971466aca5324eaba7ead27e3d4e33ddaa244535e168"
    private static let cert1CanonicalSPKIHex = "3059301306072a8648ce3d020106082a8648ce3d03010703420004f8a17468f44dbcc10175fab8b4edfeb2a9c1deedf03a213852d9e388bd2a57df292acc1efa360ee7cffe851507e57f8c9cbdd0f42e09cfbf8f636b4ed1ce877c"
    private static let canonicalJIDSPKI = bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

    @Test func parseSingleCertificate() throws {
        let certificates = try CertChain.certificates(fromPEM: cert1)
        #expect(certificates.count == 1)
    }

    @Test func parseTwoCertificateChainPreservesOrder() throws {
        let certificates = try CertChain.certificates(fromPEM: cert1 + "\n" + cert2)
        #expect(certificates.count == 2)
        #expect(CertChain.sha256Fingerprint(of: certificates[0]) == cert1Fingerprint)
        #expect(CertChain.sha256Fingerprint(of: certificates[1]) == "98cbe01d5f20637053f0ec7a33c672d3747d20c1ce52ca53e76bea7c1fdeac98")
    }

    @Test func fingerprintMatchesOpenSSLFixture() throws {
        let certificate = try #require(try CertChain.certificates(fromPEM: cert1).first)
        #expect(CertChain.sha256Fingerprint(of: certificate) == cert1Fingerprint)
    }

    @Test func canonicalP256SPKIMatchesOpenSSLFixture() throws {
        let certificate = try #require(try CertChain.certificates(fromPEM: cert1).first)
        let spki = try CertChain.canonicalP256SubjectPublicKeyInfoDER(certificate: certificate)
        #expect(Self.hex(spki) == Self.cert1CanonicalSPKIHex)
    }

    @Test func pinMatchesCertificateSHA256Prefixes() throws {
        let certificate = try #require(try CertChain.certificates(fromPEM: cert1).first)
        let digest = Self.bytes(cert1Fingerprint)
        let prefix = Array(digest.prefix(8))
        var wrongPrefix = prefix
        wrongPrefix[0] ^= 0xff

        #expect(CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .certificateSHA256, prefixBytes: prefix)
        ))
        #expect(!CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .certificateSHA256, prefixBytes: wrongPrefix)
        ))
    }

    @Test func pinMatchesSPKISHA256Prefixes() throws {
        let certificate = try #require(try CertChain.certificates(fromPEM: cert1).first)
        let spki = Self.bytes(Self.cert1CanonicalSPKIHex)
        let digest = Array(SHA256.hash(data: Data(spki)))
        let prefix = Array(digest.prefix(8))
        var wrongPrefix = prefix
        wrongPrefix[0] ^= 0xff

        #expect(CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .spkiSHA256, prefixBytes: prefix)
        ))
        #expect(!CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .spkiSHA256, prefixBytes: wrongPrefix)
        ))
    }

    @Test func pinMatchesSPKISHA256ReturnsFalseWhenPublicKeyCannotCanonicalize() throws {
        let original = try #require(try CertChain.certificates(fromPEM: cert1).first)
        var der = Array(SecCertificateCopyData(original) as Data)
        let spki = Self.bytes(Self.cert1CanonicalSPKIHex)
        let spkiRange = try #require(der.firstRange(of: spki))
        let uncompressedP256ECPointByteCount = 1 + 32 + 32
        let ecPointMarkerIndex = spkiRange.upperBound - uncompressedP256ECPointByteCount
        // The SPKI fixture ends with the uncompressed P-256 EC point
        // (0x04 || 32-byte X || 32-byte Y). Corrupt the marker to 0x05 so
        // P256.Signing.PublicKey(x963Representation:) rejects it,
        // canonicalP256SubjectPublicKeyInfoDER throws, and pinMatches fails
        // closed instead of trapping or matching. This intentionally provokes
        // a Security framework diagnostic while the corrupted key is rejected;
        // that log line is expected and is not package logging.
        der[ecPointMarkerIndex] = 0x05
        let malformed = try #require(SecCertificateCreateWithData(nil, Data(der) as CFData))

        #expect(!CertChain.pinMatches(
            certificate: malformed,
            pin: PairingCAPin(kind: .spkiSHA256, prefixBytes: [0x00])
        ))
    }

    @Test func pinMatchesRejectsEmptyAndOverlongPrefixes() throws {
        let certificate = try #require(try CertChain.certificates(fromPEM: cert1).first)
        let overlongPrefix = Array(repeating: UInt8(0), count: 33)

        #expect(!CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .certificateSHA256, prefixBytes: [])
        ))
        #expect(!CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .spkiSHA256, prefixBytes: [])
        ))
        #expect(!CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .certificateSHA256, prefixBytes: overlongPrefix)
        ))
        #expect(!CertChain.pinMatches(
            certificate: certificate,
            pin: PairingCAPin(kind: .spkiSHA256, prefixBytes: overlongPrefix)
        ))
    }

    @Test func jidFromSPKIRefusesMalformedStructureAndTrailingBytes() {
        expectThrows(.malformedSPKI) {
            _ = try CertChain.jidFromSPKI([0x01, 0x02, 0x03])
        }

        var trailing = Self.canonicalJIDSPKI
        trailing.append(0x00)
        expectThrows(.malformedSPKI) {
            _ = try CertChain.jidFromSPKI(trailing)
        }
    }

    @Test func jidFromSPKIRefusesAbsentP256Parameters() {
        let absentParameters = Self.bytes("304f300906072a8648ce3d0201034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        expectThrows(.notP256) {
            _ = try CertChain.jidFromSPKI(absentParameters)
        }
    }

    @Test func jidFromSPKIRefusesInvalidPointEncodings() {
        var nonzeroUnusedBits = Self.canonicalJIDSPKI
        nonzeroUnusedBits[25] = 0x01
        expectThrows(.invalidPoint) {
            _ = try CertChain.jidFromSPKI(nonzeroUnusedBits)
        }

        var badPrefix = Self.canonicalJIDSPKI
        badPrefix[26] = 0x05
        expectThrows(.invalidPoint) {
            _ = try CertChain.jidFromSPKI(badPrefix)
        }

        let badLength = Self.bytes("3058301306072a8648ce3d020106082a8648ce3d030107034100046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51")
        expectThrows(.invalidPoint) {
            _ = try CertChain.jidFromSPKI(badLength)
        }
    }

    @Test func invalidPEMThrows() {
        expectThrows(.emptyChain) {
            _ = try CertChain.certificates(fromPEM: "")
        }
        expectThrows(.invalidPEM) {
            _ = try CertChain.certificates(fromPEM: """
            -----BEGIN CERTIFICATE-----
            not base64
            -----END CERTIFICATE-----
            """)
        }
        expectThrows(.invalidCertificate) {
            let bytes = Data([0x01, 0x02, 0x03]).base64EncodedString()
            _ = try CertChain.certificates(fromPEM: """
            -----BEGIN CERTIFICATE-----
            \(bytes)
            -----END CERTIFICATE-----
            """)
        }
    }

    private func expectThrows(_ expected: CertChainError, _ operation: () throws -> Void) {
        do {
            try operation()
            Issue.record("Expected \(expected)")
        } catch let error as CertChainError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }

    private static func bytes(_ hex: String) -> [UInt8] {
        stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        }
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
