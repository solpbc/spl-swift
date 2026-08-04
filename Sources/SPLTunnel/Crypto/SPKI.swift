// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

struct SubjectPublicKeyInfo {
    let algorithmOID: [UInt64]
    let parameterOID: [UInt64]?
    let unusedBitCount: UInt8
    let publicKeyBytes: [UInt8]

    static func parse(_ der: [UInt8]) throws -> SubjectPublicKeyInfo {
        var reader = DERReader(bytes: der)
        let outer = try reader.readElement(expectedTag: 0x30)
        guard reader.isAtEnd else {
            throw SubjectPublicKeyInfoError.malformed
        }

        var body = DERReader(bytes: outer.value)
        let algorithm = try body.readElement(expectedTag: 0x30)
        let bitString = try body.readElement(expectedTag: 0x03)
        guard body.isAtEnd, !bitString.value.isEmpty else {
            throw SubjectPublicKeyInfoError.malformed
        }

        var algorithmReader = DERReader(bytes: algorithm.value)
        let algorithmOID = try algorithmReader.readObjectIdentifier()
        var parameterOID: [UInt64]?
        if !algorithmReader.isAtEnd {
            let parameter = try algorithmReader.readElement()
            guard algorithmReader.isAtEnd else {
                throw SubjectPublicKeyInfoError.malformed
            }
            if parameter.tag == 0x06 {
                parameterOID = try DERReader.objectIdentifier(from: parameter.value)
            }
        }

        return SubjectPublicKeyInfo(
            algorithmOID: algorithmOID,
            parameterOID: parameterOID,
            unusedBitCount: bitString.value[0],
            publicKeyBytes: Array(bitString.value.dropFirst())
        )
    }
}

enum SubjectPublicKeyInfoError: Error {
    case malformed
}

private struct DERElement {
    let tag: UInt8
    let value: [UInt8]
}

private struct DERReader {
    private let bytes: [UInt8]
    private var index = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    var isAtEnd: Bool {
        index == bytes.count
    }

    mutating func readElement(expectedTag: UInt8? = nil) throws -> DERElement {
        let tag = try readByte()
        guard tag & 0x1f != 0x1f, expectedTag == nil || tag == expectedTag else {
            throw SubjectPublicKeyInfoError.malformed
        }
        let length = try readLength()
        guard length <= bytes.count - index else {
            throw SubjectPublicKeyInfoError.malformed
        }
        let value = Array(bytes[index..<(index + length)])
        index += length
        return DERElement(tag: tag, value: value)
    }

    mutating func readObjectIdentifier() throws -> [UInt64] {
        let element = try readElement(expectedTag: 0x06)
        return try Self.objectIdentifier(from: element.value)
    }

    static func objectIdentifier(from bytes: [UInt8]) throws -> [UInt64] {
        guard !bytes.isEmpty else {
            throw SubjectPublicKeyInfoError.malformed
        }

        var index = 0
        let firstSubidentifier = try readBase128(from: bytes, index: &index)
        var arcs: [UInt64]
        switch firstSubidentifier {
        case 0...39:
            arcs = [0, firstSubidentifier]
        case 40...79:
            arcs = [1, firstSubidentifier - 40]
        default:
            arcs = [2, firstSubidentifier - 80]
        }

        while index < bytes.count {
            arcs.append(try readBase128(from: bytes, index: &index))
        }
        return arcs
    }

    private static func readBase128(from bytes: [UInt8], index: inout Int) throws -> UInt64 {
        let start = index
        var value: UInt64 = 0
        while true {
            guard index < bytes.count else {
                throw SubjectPublicKeyInfoError.malformed
            }
            let byte = bytes[index]
            index += 1
            guard value <= (UInt64.max - UInt64(byte & 0x7f)) / 128 else {
                throw SubjectPublicKeyInfoError.malformed
            }
            value = value * 128 + UInt64(byte & 0x7f)
            if byte & 0x80 == 0 {
                break
            }
        }
        guard index - start == 1 || bytes[start] != 0x80 else {
            throw SubjectPublicKeyInfoError.malformed
        }
        return value
    }

    private mutating func readByte() throws -> UInt8 {
        guard index < bytes.count else {
            throw SubjectPublicKeyInfoError.malformed
        }
        defer { index += 1 }
        return bytes[index]
    }

    private mutating func readLength() throws -> Int {
        let first = try readByte()
        if first < 0x80 {
            return Int(first)
        }

        let count = Int(first & 0x7f)
        guard count > 0, count <= MemoryLayout<Int>.size, count <= bytes.count - index else {
            throw SubjectPublicKeyInfoError.malformed
        }
        guard bytes[index] != 0 else {
            throw SubjectPublicKeyInfoError.malformed
        }

        var length = 0
        for _ in 0..<count {
            let byte = try readByte()
            guard length <= (Int.max - Int(byte)) / 256 else {
                throw SubjectPublicKeyInfoError.malformed
            }
            length = length * 256 + Int(byte)
        }
        guard length >= 0x80 else {
            throw SubjectPublicKeyInfoError.malformed
        }
        return length
    }
}
