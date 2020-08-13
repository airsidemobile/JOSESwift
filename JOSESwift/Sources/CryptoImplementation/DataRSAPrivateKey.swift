//
//  DataRSAPublicKey.swift
//  JOSESwift
//
//  Created by Daniel Egger on 06.02.18.
//  Modified by Luke Reichold on 08.12.20
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

extension Data: ExpressibleAsRSAPrivateKeyComponents {
    public static func representing(rsaPrivateKeyComponents components: RSAPrivateKeyComponents) throws -> Data {
        let modulusBytes = [UInt8](components.modulus).prefixingZeroByte()
        let exponentBytes = [UInt8](components.exponent)
        let privateExponentBytes = [UInt8](components.privateExponent).prefixingZeroByte()

        let prime1Bytes = [UInt8](components.prime1).prefixingZeroByte()
        let prime2Bytes = [UInt8](components.prime2).prefixingZeroByte()
        let exponent1Bytes = [UInt8](components.exponent1).prefixingZeroByte()
        let exponent2Bytes = [UInt8](components.exponent2).prefixingZeroByte()
        let coefficientBytes = [UInt8](components.coefficient).prefixingZeroByte()

        let zeroBytes = [UInt8]([0x00])
        let leadingZeroEncoded = zeroBytes.encode(as: .integer)

        let modulusEncoded = modulusBytes.encode(as: .integer)
        let exponentEncoded = exponentBytes.encode(as: .integer)
        let privateExponentEncoded = privateExponentBytes.encode(as: .integer)

        let prime1Encoded = prime1Bytes.encode(as: .integer)
        let prime2Encoded = prime2Bytes.encode(as: .integer)
        let exponent1Encoded = exponent1Bytes.encode(as: .integer)
        let exponent2Encoded = exponent2Bytes.encode(as: .integer)
        let coefficientEncoded = coefficientBytes.encode(as: .integer)

        let sequenceEncoded = (leadingZeroEncoded + modulusEncoded + exponentEncoded + privateExponentEncoded + prime1Encoded + prime2Encoded + exponent1Encoded + exponent2Encoded + coefficientEncoded).encode(as: .sequence)

        return Data(sequenceEncoded)
    }

    public func rsaPrivateKeyComponents() throws -> RSAPrivateKeyComponents {
        let publicKeyBytes = [UInt8](self)

        let sequence = try publicKeyBytes.read(.sequence)
        let modulus = try sequence.getNthInteger(1)
        let exponent = try sequence.getNthInteger(2)
        let privateExponent = try sequence.getNthInteger(3)

        let prime1 = try sequence.getNthInteger(4)
        let prime2 = try sequence.getNthInteger(5)
        let exponent1 = try sequence.getNthInteger(6)
        let exponent2 = try sequence.getNthInteger(7)
        let coefficient = try sequence.getNthInteger(8)

        return (
            Data(modulus),
            Data(exponent),
            Data(privateExponent),
            Data(prime1),
            Data(prime2),
            Data(exponent1),
            Data(exponent2),
            Data(coefficient)
        )
    }
}

internal extension Array where Element == UInt8 {
    func getNthInteger(_ n: Int) throws -> [UInt8] {
        var seq = self
        for _ in 0 ..< n {
            seq = try seq.skip(.integer)
        }
        var val = try seq.read(.integer)

        if val.first == 0x00 {
            val = Array(val.dropFirst())
        }
        return val
    }
}

extension Array where Element == UInt8 {
    func prefixingZeroByte() -> [UInt8] {
        if let prefix = self.first, prefix.isMsbSet() {
            return [0x00] + self
        }
        return self
    }
}

extension UInt8 {
    func isMsbSet() -> Bool {
        self & (1 << 7) != 0
    }
}

