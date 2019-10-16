//
//  Data+Base64URL.swift
//  JOSESwift
//
//  Created by Daniel Egger on 22/09/2017.
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

extension Data {
    /// Creates a new data buffer from a base64url encoded string.
    ///
    /// - Parameter base64URLString: The base64url encoded string to parse.
    /// - Returns: `nil` if the input is not recognized as valid base64url.
    public init?(base64URLEncoded base64URLString: String) {
        var s = base64URLString
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let mod = s.count % 4
        switch mod {
        case 0: break
        case 2: s.append("==")
        case 3: s.append("=")
        default: return nil
        }

        self.init(base64Encoded: s)
    }

    /// Creates a new data buffer from base64url, UTF-8 encoded data.
    ///
    /// - Parameter base64URLData: The base64url, UTF-8 encoded data.
    /// - Returns: `nil` if the input is not recognized as valid base64url.
    public init?(base64URLEncoded base64URLData: Data) {
        guard let s = String(data: base64URLData, encoding: .utf8) else {
            return nil
        }

        self.init(base64URLEncoded: s)
    }

    /// Returns a base64url encoded string.
    ///
    /// - Returns: The base64url encoded string.
    public func base64URLEncodedString() -> String {
        let s = self.base64EncodedString()
        return s
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    /// Returns base64url encoded data.
    ///
    /// - Returns: The base64url encoded data.
    public func base64URLEncodedData() -> Data {
        // UTF-8 can represent [all Unicode characters](https://en.wikipedia.org/wiki/UTF-8), so this 
        // forced unwrap is safe. See also [this](https://stackoverflow.com/a/46152738/5233456) SO answer.
        // swiftlint:disable:next force_unwrapping
        return self.base64URLEncodedString().data(using: .utf8)!
    }

    /// Returns the byte length of a data object as octet hexadecimal data.
    ///
    /// - Returns: The data byte length as octet hexadecimal data.
    func getByteLengthAsOctetHexData() -> Data {
        let dataLength = UInt64(self.count * 8)
        let dataLengthInHex = String(dataLength, radix: 16, uppercase: false)

        var dataLengthBytes = [UInt8](repeatElement(0x00, count: 8))

        var dataIndex = dataLengthBytes.count-1
        for index in stride(from: 0, to: dataLengthInHex.count, by: 2) {
            var offset = 2
            var hexStringChunk = ""

            if dataLengthInHex.count-index == 1 {
                offset = 1
            }

            let endIndex = dataLengthInHex.index(dataLengthInHex.endIndex, offsetBy: -index)
            let startIndex = dataLengthInHex.index(endIndex, offsetBy: -offset)
            let range = Range(uncheckedBounds: (lower: startIndex, upper: endIndex))
            hexStringChunk = String(dataLengthInHex[range])

            if let hexByte = UInt8(hexStringChunk, radix: 16) {
                dataLengthBytes[dataIndex] = hexByte
            }

            dataIndex -= 1
        }

        return Data(dataLengthBytes)
    }
}

extension Data: DataConvertible {
    public init(_ data: Data) {
        self = data
    }

    public func data() -> Data {
        return self
    }
}
