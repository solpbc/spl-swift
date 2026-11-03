// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Testing
@testable import SPLMark
import SPLTunnel

/// The vectors are spl-core's own output; scripts/mark-vectors generates them.
private struct MarkVectors: Decodable {
    struct JournalIDVector: Decodable {
        let journal_id: String
        let mark: MarkRenderSpec
    }

    struct SPKIVector: Decodable {
        let spki_hex: String
        let journal_id: String
        let mark: MarkRenderSpec
    }

    struct Tables: Decodable {
        let glyphs_sha256: String
        let colors_sha256: String
        let words_sha256: String
    }

    let from_spki: [SPKIVector]
    let from_journal_id: [JournalIDVector]
    let refused_journal_ids: [String]
    let tables: Tables

    static func load() throws -> MarkVectors {
        let url = try #require(Bundle.module.url(forResource: "mark-vectors", withExtension: "json"))
        return try JSONDecoder().decode(MarkVectors.self, from: Data(contentsOf: url))
    }
}

private func digestOfLines(_ lines: [String]) -> String {
    let digest = SHA256.hash(data: Data(lines.map { $0 + "\n" }.joined().utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}

@Suite("journal mark derivation", .serialized)
struct MarkDerivationTests {
    @Test func everyVectorMatchesSPLCore() throws {
        let vectors = try MarkVectors.load()
        #expect(!vectors.from_journal_id.isEmpty)
        for vector in vectors.from_journal_id {
            #expect(try markFromJournalID(vector.journal_id) == vector.mark, "\(vector.journal_id)")
        }
    }

    @Test func aPinnedKeyGivesTheJournalIDAndMarkSPLCoreGives() throws {
        let vectors = try MarkVectors.load()
        #expect(!vectors.from_spki.isEmpty)
        for vector in vectors.from_spki {
            let spki = stride(from: 0, to: vector.spki_hex.count, by: 2).map { offset -> UInt8 in
                let start = vector.spki_hex.index(vector.spki_hex.startIndex, offsetBy: offset)
                return UInt8(vector.spki_hex[start...vector.spki_hex.index(after: start)], radix: 16)!
            }
            let journalID = try CertChain.jidFromSPKI(spki)
            #expect(journalID == vector.journal_id)
            #expect(try markFromJournalID(journalID) == vector.mark)
        }
    }

    @Test func refusesWhatSPLCoreRefuses() throws {
        let vectors = try MarkVectors.load()
        #expect(!vectors.refused_journal_ids.isEmpty)
        for journalID in vectors.refused_journal_ids {
            #expect(throws: MarkError.invalidJournalID, "\(journalID)") {
                try markFromJournalID(journalID)
            }
        }
    }

    @Test func everyTableEntryMatchesSPLCoreInOrder() throws {
        let vectors = try MarkVectors.load()
        let tables = try MarkDerivationTables.loaded()
        #expect(digestOfLines(tables.glyphs.map { "\($0.name)\t\($0.svg)" }) == vectors.tables.glyphs_sha256)
        #expect(digestOfLines(tables.colors.map { "\($0.name)\t\($0.hex)" }) == vectors.tables.colors_sha256)
        #expect(digestOfLines(tables.words) == vectors.tables.words_sha256)
    }

    @Test func theAsyncFormDerivesTheSameMark() async throws {
        let vector = try #require(try MarkVectors.load().from_journal_id.first)
        #expect(try await deriveMark(fromJournalID: vector.journal_id) == vector.mark)
    }
}
