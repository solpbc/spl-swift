// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Security
import SPLMark
import Testing
@testable import SPLTunnel

/// A direct link pins whichever CA it names, so a forged link pins the forger. These run the real
/// certless exchange against a real TLS peer holding its own CA, under a valid pin to that CA.
@Suite(
    "direct pairing binds the id to the pinned CA",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct DirectPairBindingTests {
    private static let clientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")
    private static let relayEndpoint = URL(string: "https://direct-binding-relay.test")!

    @Test func aPeerClaimingAnotherJournalsIDAndServingItsMarkIsRefused() async throws {
        let victim = try TestCA.make()
        let forger = try TestCA.make()
        let victimID = try TestCA.journalID(of: victim)
        let victimMark = try markFromJournalID(victimID)

        await #expect(throws: PairError.directInstanceMismatch) {
            try await Self.pair(peer: forger, responseBody: Self.body(
                peer: forger,
                instanceID: victimID,
                caChain: [forger.caCertificatePEM],
                servedMark: victimMark
            ))
        }

        // What would have been asked about, had the id been believed: not the forger's own mark.
        let forgerMark = try markFromJournalID(try TestCA.journalID(of: forger))
        #expect(forgerMark != victimMark)
    }

    @Test func aPeerNamingAnotherCAsChainForThatCAsIDIsRefused() async throws {
        // The forger answers with a chain and id that agree with each other but not with the
        // certificate the pin accepted, so what gets stored would not be what was pinned.
        let victim = try TestCA.make()
        let forger = try TestCA.make()

        await #expect(throws: PairError.directInstanceMismatch) {
            try await Self.pair(peer: forger, responseBody: Self.body(
                peer: forger,
                instanceID: try TestCA.journalID(of: victim),
                caChain: [victim.caCertificatePEM],
                servedMark: nil
            ))
        }
    }

    @Test func aGenuinePeerPairsAndItsStoredCAGivesItsMark() async throws {
        let journal = try TestCA.make()
        let journalID = try TestCA.journalID(of: journal)

        let pairing = try await Self.pair(peer: journal, responseBody: Self.body(
            peer: journal,
            instanceID: journalID,
            caChain: [journal.caCertificatePEM],
            servedMark: nil
        ))

        #expect(pairing.instanceID == journalID)
        #expect(try CertChain.journalID(ofCAChainPEM: pairing.caChainPEM) == journalID)
    }

    @discardableResult
    private static func pair(peer: TestCA.Bundle, responseBody: Data) async throws -> StoredPairing {
        let server = PairingMuxServer(
            bundle: peer,
            response: PairingHTTPServerResponse(status: 200, body: responseBody)
        )
        try await server.start()
        let port = await server.port
        do {
            let pairing = try await PairClient(clientInfo: clientInfo).pair(
                pairURL: try directPairURL(peer: peer, port: port),
                deviceLabel: "test phone",
                relayEndpoint: relayEndpoint
            )
            await server.stop()
            return pairing
        } catch {
            await server.stop()
            throw error
        }
    }

    private static func body(
        peer: TestCA.Bundle,
        instanceID: String,
        caChain: [String],
        servedMark: MarkRenderSpec?
    ) throws -> Data {
        var body: [String: Any] = [
            "instance_id": instanceID,
            "home_label": "test home",
            "client_cert": peer.clientCertificatePEM,
            "ca_chain": caChain,
            "home_attestation": "attestation",
            "local_endpoints": [],
        ]
        if let servedMark {
            body["mark"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(servedMark))
        }
        return try JSONSerialization.data(withJSONObject: body)
    }

    private static func directPairURL(peer: TestCA.Bundle, port: Int) throws -> PairURL {
        let certificate = try #require(try CertChain.certificates(fromPEM: peer.caCertificatePEM).first)
        let fingerprint = Array(SHA256.hash(data: SecCertificateCopyData(certificate) as Data).prefix(16))
        let nonce = [UInt8](repeating: 0x42, count: 16)
        let bytes: [UInt8] = [0x05, 0x01, 0x01, UInt8(port >> 8), UInt8(port & 0xff), 127, 0, 0, 1] + nonce + fingerprint
        return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
    }
}
