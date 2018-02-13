//
//  ASN1DEREncoding.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 08.02.18.
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

internal extension Array where Element == UInt8 {

    func encode(as type: ASN1Type) -> [UInt8] {
        var tlv: [UInt8] = []
        tlv.append(type.tag)
        tlv.append(contentsOf: lengthField(of: self))
        tlv.append(contentsOf: self)

        return tlv
    }

}

private func lengthField(of valueField: [UInt8]) -> [UInt8] {
    var count = valueField.count

    if count < 128 {
        return [ UInt8(count) ]
    }

    // The number of bytes needed to encode count.
    let lengthBytesCount = Int((log2(Double(count)) / 8) + 1)

    // The first byte in the length field encoding the number of remaining bytes.
    let firstLengthFieldByte = UInt8(128 + lengthBytesCount)

    var lengthField: [UInt8] = []
    for _ in 0..<lengthBytesCount {
        // Take the last 8 bits of count.
        let lengthByte = UInt8(count & 0xff)
        // Add them to the length field.
        lengthField.insert(lengthByte, at: 0)
        // Delete the last 8 bits of count.
        count = count >> 8
    }

    // Include the first byte.
    lengthField.insert(firstLengthFieldByte, at: 0)

    return lengthField
}