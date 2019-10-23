//
//  ASN1DERParsing.swift
//  JOSESwift
//
//  Created by Daniel Egger on 06.02.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation

internal enum ASN1DERParsingError: Error {
    case incorrectTypeTag(actualTag: UInt8, expectedTag: UInt8)
    case incorrectLengthFieldLength
    case incorrectValueLength
    case incorrectTLVLength
}

/// Possible ASN.1 types.
/// See [here](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648640(v=vs.85).aspx)
/// for more information.
internal enum ASN1Type {
    case sequence
    case integer

    var tag: UInt8 {
        switch self {
        case .sequence:
            return 0x30
        case .integer:
            return 0x02
        }
    }
}

internal struct TLVTriplet {
    let tag: UInt8
    let length: [UInt8]
    let value: [UInt8]
}

// MARK: Array Extension for Parsing
// Inspired by: https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift

internal extension Array where Element == UInt8 {

    /// Reads the value of the specified ASN.1 type from the front of the bytes array.
    /// The bytes array is expected to be a DER encoding of an ASN.1 type.
    /// The specified type's TLV triplet is expected to be at the front of the bytes array.
    /// The bytes array may contain trailing bytes after the TLV triplet that are ignored during parsing.
    ///
    /// - Parameter type: The ASN.1 type to read.
    ///                   More information about the expected DER encoding of the specified ASN.1 type can be found
    ///                   [here](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648640(v=vs.85).aspx).
    /// - Returns: The value of the specified ASN.1 type. More formally, the value field of the type's TLV triplet.
    /// - Throws: An `ASN1DERParsingError` indicating any parsing errors.
    func read(_ type: ASN1Type) throws -> [UInt8] {
        let triplet = try self.nextTLVTriplet()

        guard triplet.tag == type.tag else {
            throw ASN1DERParsingError.incorrectTypeTag(actualTag: triplet.tag, expectedTag: type.tag)
        }

        return triplet.value
    }

    /// Removes the specified ASN.1 type from the bytes array.
    /// The bytes array is expected to be a DER encoding of a ASN.1 type.
    /// The specified type's TLV triplet is expected to be at the front of the bytes array.
    ///
    /// - Parameter type: The ASN.1 type to be removed from the bytes array.
    ///                   More information about the expected DER encoding of the specified ASN.1 type can be found
    ///                   [here](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648640(v=vs.85).aspx).
    /// - Returns: The remaining bytes of the bytes array that may contain further ASN.1 types.
    /// - Throws: An `ASN1DERParsingError` indicating any parsing errors.
    func skip(_ type: ASN1Type) throws -> [UInt8] {
        let triplet = try self.nextTLVTriplet()

        guard triplet.tag == type.tag else {
            throw ASN1DERParsingError.incorrectTypeTag(actualTag: triplet.tag, expectedTag: type.tag)
        }

        // TLV triplet = 1 tag byte + some length bytes + some value bytes
        let skippedTripletLength = (1 + triplet.length.count + triplet.value.count)

        return Array(self.dropFirst(skippedTripletLength))
    }

    /// Reads a TLV (tag, length, value) triplet of a DER encoded ASN.1 type from the bytes array.
    /// More information on the DER Transfer Syntax encoding ASN.1 types can be found
    /// [here](https://msdn.microsoft.com/en-us/library/windows/desktop/bb540801(v=vs.85).aspx).
    ///
    /// - Returns: A triplet containing the ASN.1 type's tag, length, and value field.
    func nextTLVTriplet() throws -> TLVTriplet {
        var pointer = 0

        // DER encoding of an ASN.1 type: [ TAG | LENGTH | VALUE ].

        // At least the tag and one length byte must be present.
        guard self.count >= 2 else {
            throw ASN1DERParsingError.incorrectTLVLength
        }

        let tag = readTag(from: self, pointer: &pointer)

        let lengthField = try readLengthField(from: self, pointer: &pointer)

        let valueFieldLength = try length(encodedBy: lengthField)

        let valueField = try readValueField(ofLength: valueFieldLength, from: self, pointer: &pointer)

        return TLVTriplet(tag: tag, length: lengthField, value: valueField)
    }

}

// MARK: Freestanding Helper Functions

private func readTag(from encodedTriplet: [UInt8], pointer: inout Int) -> UInt8 {
    let tag = encodedTriplet[pointer]

    // ---------------------------------------- //
    //     tag   length field   value field     //
    //   [ 0xN | ............ | ........... ]   //
    //      ^                                   //
    //      |                                   //
    //    pointer                               //
    // ---------------------------------------- //

    pointer.advance()

    return tag
}

private func readLengthField(from encodedTriplet: [UInt8], pointer: inout Int) throws -> [UInt8] {
    if encodedTriplet[pointer] < 128 {
        let lengthField = [ encodedTriplet[pointer] ]
        pointer.advance()

        return lengthField
    }

    // -------------------------------------------------- //
    //     tag        length field        value field     //
    //   [ ... | 0x8N 0x00 0x01 ... 0xN | ........... ]   //
    //            ^    |             |                    //
    //            |    -------v-------                    //
    //            |    lengthFieldCount                   //
    //            |                                       //
    //         pointer                                    //
    // -------------------------------------------------- //

    let lengthFieldCount = Int(encodedTriplet[pointer] - 128)

    // Ensure we have enough bytes left.
    guard (pointer + lengthFieldCount) < encodedTriplet.count else {
        throw ASN1DERParsingError.incorrectLengthFieldLength
    }

    let lengthField = Array(encodedTriplet[pointer...(pointer + lengthFieldCount)])

    pointer.advance()
    pointer.advance(by: lengthFieldCount)

    return lengthField
}

private func readValueField(ofLength length: Int, from encodedTriplet: [UInt8], pointer: inout Int) throws -> [UInt8] {
    let endPointer = (pointer + length)

    // --------------------------------------------------------------- //
    //     tag   length field           value field                    //
    //   [ ... | ............ | 0x01 0x02 0x03 0x04 ... 0xN ]          //
    //                           ^                             ^       //
    //                           |                             |       //
    //                        pointer                      endPointer  //
    // --------------------------------------------------------------- //

    // Ensure we have enough bytes left.
    guard endPointer <= encodedTriplet.count else {
        throw ASN1DERParsingError.incorrectValueLength
    }

    return Array(encodedTriplet[pointer..<endPointer])
}

private func length(encodedBy lengthField: [UInt8]) throws -> Int {
    // If the value field contains < 128 bytes, the length field requires only one byte (00000010 = length two).
    // If the value field contains >= 128 bytes, the highest bit of the length field is 1 and the remaining bits
    // identify the number of bytes needed to encode the length (10000010 - 10000000 = 10 = two length bytes follow).

    // Length is directly encoded by the only byte in the length field.
    if lengthField.count == 1 {
        return Int(lengthField[0])
    }

    // Length is encoded by all but the first byte in the length field.
    // The first byte in the length field encodes the number of remaining bytes used to encode the length.
    var length: UInt64 = 0
    for byte in lengthField.dropFirst() {
        length = (length << 8)
        length += UInt64(byte)
    }

    return Int(length)
}

private extension Int {
    mutating func advance(by n: Int = 1) {
        self = self.advanced(by: n)
    }
}
