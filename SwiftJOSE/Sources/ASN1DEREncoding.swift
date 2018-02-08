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

    func encode(as type: ASN1Type) throws -> [UInt8] {
        var builder: [UInt8] = []
        builder.append(type.tag)
        builder.append(contentsOf: try self.lengthField())
        builder.append(contentsOf: self)

        return builder
    }

    private func lengthField() throws -> [UInt8] {
        let count = self.count

        if count < 128 {
            return [ UInt8(count) ]
        }

        let i = Int(log2(Double(count)) / 8 + 1)
        var len = count
        var result: [UInt8] = [UInt8(i + 0x80)]

        for _ in 0..<i {
            result.insert(UInt8(len & 0xFF), at: 1)
            len = len >> 8
        }

        return result
    }

}
