// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import CArgon2
import Foundation

/// One chip's tint: a locked palette name and its hex value.
public struct MarkColor: Codable, Equatable, Sendable {
    public let name: String
    public let hex: String
}

/// One chip: a glyph, its tint and its rotation in degrees, `0` or `45`.
public struct MarkIconSpec: Codable, Equatable, Sendable {
    public let name: String
    public let svg: String
    public let color: MarkColor
    public let rot: Int
}

/// What a client draws: two chips and two words, the shape a journal serves for its own screens.
public struct MarkRenderSpec: Codable, Equatable, Sendable {
    public let icon1: MarkIconSpec
    public let icon2: MarkIconSpec
    public let words: [String]
}

public enum MarkError: Error, Equatable, Sendable {
    /// The journal ID isn't a hyphenated 36-character UUID.
    case invalidJournalID
    /// Argon2id failed, which on these fixed parameters means it couldn't get its memory.
    case hashFailed(code: Int32)
    /// A locked table doesn't have its fixed size.
    case invalidTables
}

/// Derives a journal's mark from its journal ID: Argon2id over the ID's 16 bytes, then the locked
/// tables. Byte-identical to `spl_core::mark::mark_from_jid`, proved by the vectors in this
/// package's tests.
///
/// This costs 64 MiB and three passes by design. Call it off the main thread, once per journal, and
/// keep the result. ``deriveMark(fromJournalID:)`` does the first of those.
public func markFromJournalID(_ journalID: String) throws -> MarkRenderSpec {
    let tables = try MarkDerivationTables.loaded()
    let digest = try markDigest(parseJournalID(journalID))
    let words: [UInt32] = (0..<7).map { index in
        digest[(index * 4)..<(index * 4 + 4)].reduce(UInt32(0)) { word, byte in word << 8 | UInt32(byte) }
    }

    let icon1 = pick(words[0], count: tables.glyphs.count)
    let icon2 = pickDistinct(words[1], count: tables.glyphs.count, excluded: icon1)
    let color1 = pick(words[2], count: tables.colors.count)
    let color2 = pickDistinct(words[3], count: tables.colors.count, excluded: color1)
    let word1 = pick(words[4], count: tables.words.count)
    let word2 = pickDistinct(words[5], count: tables.words.count, excluded: word1)

    func icon(_ glyph: Int, _ color: Int, rotated: Bool) -> MarkIconSpec {
        MarkIconSpec(
            name: tables.glyphs[glyph].name,
            svg: tables.glyphs[glyph].svg,
            color: MarkColor(name: tables.colors[color].name, hex: tables.colors[color].hex),
            rot: rotated ? 45 : 0
        )
    }
    return MarkRenderSpec(
        icon1: icon(icon1, color1, rotated: words[6] & 1 != 0),
        icon2: icon(icon2, color2, rotated: words[6] >> 1 & 1 != 0),
        words: [tables.words[word1], tables.words[word2]]
    )
}

/// ``markFromJournalID(_:)`` off the caller's actor.
public func deriveMark(fromJournalID journalID: String) async throws -> MarkRenderSpec {
    try await Task.detached(priority: .userInitiated) {
        try markFromJournalID(journalID)
    }.value
}

private func pick(_ word: UInt32, count: Int) -> Int {
    Int(word) % count
}

private func pickDistinct(_ word: UInt32, count: Int, excluded: Int) -> Int {
    let index = Int(word) % (count - 1)
    return index >= excluded ? index + 1 : index
}

private func parseJournalID(_ journalID: String) throws -> [UInt8] {
    let characters = Array(journalID.utf8)
    guard characters.count == 36,
          [8, 13, 18, 23].allSatisfy({ characters[$0] == UInt8(ascii: "-") }) else {
        throw MarkError.invalidJournalID
    }
    let digits = characters.filter { $0 != UInt8(ascii: "-") }
    guard digits.count == 32 else {
        throw MarkError.invalidJournalID
    }
    return try stride(from: 0, to: 32, by: 2).map { index in
        try nibble(digits[index]) << 4 | nibble(digits[index + 1])
    }
}

private func nibble(_ byte: UInt8) throws -> UInt8 {
    switch byte {
    case UInt8(ascii: "0")...UInt8(ascii: "9"): byte - UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
    default: throw MarkError.invalidJournalID
    }
}

private func markDigest(_ journalIDBytes: [UInt8]) throws -> [UInt8] {
    let salt = Array("solstone-journal-mark-v1".utf8)
    var digest = [UInt8](repeating: 0, count: 32)
    let code = argon2id_hash_raw(3, 65_536, 1, journalIDBytes, journalIDBytes.count, salt, salt.count, &digest, digest.count)
    guard code == Int32(ARGON2_OK.rawValue) else {
        throw MarkError.hashFailed(code: code)
    }
    return digest
}

struct MarkDerivationTables: Sendable {
    let glyphs: [(name: String, svg: String)]
    let colors: [(name: String, hex: String)]
    let words: [String]

    private static let shared = MarkDerivationTables(
        glyphs: MarkTables.glyphs,
        colors: MarkTables.colors,
        words: MarkTables.wordList.split(separator: "\n").map(String.init)
    )

    static func loaded() throws -> MarkDerivationTables {
        guard shared.glyphs.count == 60, shared.colors.count == 16, shared.words.count == 7776 else {
            throw MarkError.invalidTables
        }
        return shared
    }
}
