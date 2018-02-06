//
//  ASN1DERParsing.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 06.02.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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

internal extension Array where Element == UInt8 {

    /// Reads the value of the specified ASN.1 type from the front of the bytes array.
    /// The bytes array is expected to be a DER encoding of a ASN.1 type.
    /// The specified type's TLV triplet is expected to be at the front of the bytes array.
    /// The bytes array may contain trailing bytes after the TLV triplet that are ignored during parsing.
    ///
    /// - Parameter type: The ASN.1 type to read.
    ///                   More information about the expected DER encoding of the specified ASN.1 type can be found
    ///                   [here](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648640(v=vs.85).aspx).
    /// - Returns: The value of the specified ASN.1 type. More formally, the value field of the types TLV triplet.
    /// - Throws: An `ASN1DERParsingError` indicating any parsing errors.
    func read(_ type: ASN1Type) throws -> [UInt8] {
        let triplet = self.nextTLVTriplet()

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
        let triplet = self.nextTLVTriplet()

        guard triplet.tag == type.tag else {
            throw ASN1DERParsingError.incorrectTypeTag(actualTag: triplet.tag, expectedTag: type.tag)
        }

        // TLV triplet = 1 byte tag + some bytes length + some bytes value
        let skippedTripletLength = (1 + triplet.length.count + triplet.value.count)

        return Array(self.dropFirst(skippedTripletLength))
    }


    /// Reads a TLV (type, length value) triplet of a DER encoded ASN.1 type from the bytes array.
    /// More information on the DER Transfer Syntax encoding ASN.1 types can be found
    /// [here](https://msdn.microsoft.com/en-us/library/windows/desktop/bb540801(v=vs.85).aspx).
    ///
    /// - Returns: A triplet containing the ASN.1 type's tag, length, and value field.
    func nextTLVTriplet() -> (tag: UInt8, length: [UInt8], value: [UInt8]) {
        var pointer = 0

        // DER Transfer Syntax of an ASN.1 value: [ TAG | LENGTH | VALUE ]

        // Read tag
        let tagByte = self[0]
        pointer += 1

        // Read length
        // See https://msdn.microsoft.com/en-us/library/windows/desktop/bb648641(v=vs.85).aspx
        var length: UInt64 = 0
        var lengthBytes: [UInt8]
        if self[pointer] < 128 {
            // Only one length byte present
            length = UInt64(self[pointer])
            lengthBytes = [self[pointer]]
            pointer += 1
        } else {
            // More than one length byte present
            let countLengthBytes = Int(self[pointer] - 128)
            for i in 1...countLengthBytes {
                length = (length << 8)
                length = length + UInt64(self[pointer + i])
            }

            lengthBytes = Array(self[pointer...(pointer + countLengthBytes)])

            // Move over *number of length byte* and *length bytes* to *value bytes*
            pointer += (1 + countLengthBytes)
        }

        // Read value
        let valueBytes = Array(self[pointer..<(pointer + Int(length))])

        return (
            tag: tagByte,
            length: lengthBytes,
            value: valueBytes
        )
    }

}
