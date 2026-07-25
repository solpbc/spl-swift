// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public enum PairLinkKind: Sendable, Equatable, Hashable {
    case direct
    case relay
}

public struct PairCandidate: Sendable, Equatable, Hashable {
    public let address: String
    public let port: UInt16

    public init(address: String, port: UInt16) {
        self.address = address
        self.port = port
    }
}

public struct PairURL: Sendable, Equatable, Hashable {
    private static let directVersion: UInt8 = 0x04
    private static let multiVersion: UInt8 = 0x05
    private static let relayVersion: UInt8 = 0x06

    let version: UInt8
    public let kind: PairLinkKind
    public let candidates: [PairCandidate]
    public let nonceBytes: [UInt8]
    public let sBytes: [UInt8]
    public let caPin: PairingCAPin
    public let relayOrigin: RelayOrigin?

    public var caFingerprintBytes: [UInt8] {
        caPin.prefixBytes
    }

    public static func parse(_ url: URL) throws -> PairURL {
        try PairURL(url: url)
    }

    public init(string: String) throws {
        guard let url = URL(string: string) else {
            throw PairURLError.malformedOuterURL
        }
        try self.init(url: url)
    }

    public init(url: URL) throws {
        guard url.scheme?.lowercased() == "https" else {
            throw PairURLError.wrongScheme(url.scheme)
        }
        guard url.host?.lowercased() == "go.solstone.app" else {
            throw PairURLError.wrongHost(url.host)
        }
        guard url.path == "/p" else {
            throw PairURLError.wrongPath(url.path)
        }
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let fragment = components.percentEncodedFragment,
              !fragment.isEmpty else {
            throw PairURLError.missingFragment
        }

        let bytes: [UInt8]
        do {
            bytes = try Crockford32.decode(fragment)
        } catch let error as Crockford32Error {
            throw PairURLError.invalidBase32(error)
        }

        guard !bytes.isEmpty else {
            throw PairURLError.invalidLength(bytes.count)
        }

        switch bytes[0] {
        case Self.directVersion:
            try self.init(directBytes: bytes)
        case Self.multiVersion:
            try self.init(multiBytes: bytes)
        case Self.relayVersion:
            try self.init(relayBytes: bytes)
        default:
            throw PairURLError.invalidVersion(bytes[0])
        }
    }

    private init(directBytes bytes: [UInt8]) throws {
        guard bytes.count >= 2 else {
            throw PairURLError.invalidLength(bytes.count)
        }
        guard bytes[1] == 0x01 else {
            throw PairURLError.unsupportedAddrType(bytes[1])
        }
        guard bytes.count == 40 else {
            throw PairURLError.invalidLength(bytes.count)
        }

        let addressBytes = Array(bytes[2..<6])
        let port = UInt16(bytes[6]) << 8 | UInt16(bytes[7])
        let address = addressBytes.map(String.init).joined(separator: ".")

        version = bytes[0]
        kind = .direct
        candidates = [PairCandidate(address: address, port: port)]
        nonceBytes = Array(bytes[8..<24])
        sBytes = []
        caPin = PairingCAPin(kind: .certificateSHA256, prefixBytes: Array(bytes[24..<40]))
        relayOrigin = nil
    }

    private init(multiBytes bytes: [UInt8]) throws {
        guard bytes.count >= 3 else {
            throw PairURLError.invalidLength(bytes.count)
        }
        guard bytes[1] == 0x01 else {
            throw PairURLError.unsupportedAddrType(bytes[1])
        }
        let count = Int(bytes[2])
        guard 1...4 ~= count else {
            throw PairURLError.invalidLength(bytes.count)
        }
        guard bytes.count == 5 + 4 * count + 32 else {
            throw PairURLError.invalidLength(bytes.count)
        }

        let port = UInt16(bytes[3]) << 8 | UInt16(bytes[4])
        var parsedCandidates: [PairCandidate] = []
        parsedCandidates.reserveCapacity(count)
        for index in 0..<count {
            let start = 5 + 4 * index
            let address = bytes[start..<(start + 4)].map(String.init).joined(separator: ".")
            parsedCandidates.append(PairCandidate(address: address, port: port))
        }

        let nonceStart = 5 + 4 * count
        let fingerprintStart = nonceStart + 16

        version = bytes[0]
        kind = .direct
        candidates = parsedCandidates
        nonceBytes = Array(bytes[nonceStart..<fingerprintStart])
        sBytes = []
        caPin = PairingCAPin(kind: .certificateSHA256, prefixBytes: Array(bytes[fingerprintStart..<bytes.endIndex]))
        relayOrigin = nil
    }

    private init(relayBytes bytes: [UInt8]) throws {
        guard bytes.count >= 27 else {
            throw PairURLError.invalidLength(bytes.count)
        }
        guard bytes[9] == 0x01 else {
            throw PairURLError.unsupportedCAFingerprintTag(bytes[9])
        }

        let parsedRelayOrigin: RelayOrigin
        let selectorLength = Int(bytes[26])
        if selectorLength == 0 {
            guard bytes.count == 27 else {
                throw PairURLError.invalidLength(bytes.count)
            }
            parsedRelayOrigin = .wellKnown
        } else {
            guard bytes.count == 27 + selectorLength else {
                throw PairURLError.invalidLength(bytes.count)
            }
            let originBytes = bytes[27..<(27 + selectorLength)]
            guard let origin = String(bytes: originBytes, encoding: .utf8),
                  let url = URL(string: origin),
                  let relayEndpoint = try? RelayEndpoint(url) else {
                throw PairURLError.invalidRelayOrigin
            }
            parsedRelayOrigin = .custom(relayEndpoint.url)
        }

        version = bytes[0]
        kind = .relay
        candidates = []
        nonceBytes = []
        sBytes = Array(bytes[1..<9])
        caPin = PairingCAPin(kind: .spkiSHA256, prefixBytes: Array(bytes[10..<26]))
        relayOrigin = parsedRelayOrigin
    }
}

public enum PairURLError: Error, Equatable, Sendable {
    case wrongScheme(String?)
    case wrongHost(String?)
    case wrongPath(String)
    case missingFragment
    case invalidBase32(Crockford32Error)
    case invalidVersion(UInt8)
    case unsupportedAddrType(UInt8)
    case unsupportedCAFingerprintTag(UInt8)
    case invalidRelayOrigin
    case invalidLength(Int)
    case malformedOuterURL
}
