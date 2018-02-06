//
//  DataASN1DER.swift
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

extension Data: RSAPublicKeyConvertible {
    public var rsaPublicKeyComponents: RSAPublicKeyComponents? {
        let publicKeyBytes = [UInt8](self)

        let sequence = publicKeyBytes.read(.sequence)!
        var modulus = sequence.read(.integer)!
        if modulus.first == 0x00 {
            modulus = Array(modulus.dropFirst())
        }
        let exponent = sequence.skip(.integer)!.read(.integer)!

        return (Data(bytes: modulus), Data(bytes: exponent))
    }
}

fileprivate extension Array where Element == UInt8 {
    func read(_ type: ASN1Type) -> [UInt8]? {
        let triplet = self.nextTLVTriplet()

        guard triplet.tag == type.tag else {
            return nil
        }

        return triplet.value
    }

    func skip(_ type: ASN1Type) -> [UInt8]? {
        let triplet = self.nextTLVTriplet()

        guard triplet.tag == type.tag else {
            return nil
        }

        return Array(self.dropFirst(1 + triplet.length.count + triplet.value.count))
    }

    func nextTLVTriplet() -> (tag: UInt8, length: [UInt8], value: [UInt8]) {
        var pointer = 0

        // DER format: [ TAG | LENGTH | VALUE ]

        // Read tag
        let tagByte = self[0]

        // Skip tag
        pointer += 1

        // Read length
        var length: UInt64
        var lengthBytes: [UInt8]
        if self[pointer] < 128 {
            // Ony one length byte
            length = UInt64(self[pointer])
            lengthBytes = [self[pointer]]

            // Skip length byte
            pointer += 1
        } else {
            // More than one length byte
            let countLengthBytes = Int(self[pointer] - 128)

            // Read length
            length = 0
            for i in 1...countLengthBytes {
                length = (length << 8)
                length = length + UInt64(self[pointer + i])
            }

            lengthBytes = Array(self[pointer...(pointer + countLengthBytes)])

            // Skip over length count byte and length bytes
            pointer += (1 + countLengthBytes)
        }

        // Read value
        var valueBytes = Array(self[pointer..<(pointer + Int(length))])

        return (
            tag: tagByte,
            length: lengthBytes,
            value: valueBytes
        )
    }
}
