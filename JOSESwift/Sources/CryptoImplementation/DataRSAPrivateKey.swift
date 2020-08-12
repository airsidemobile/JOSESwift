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
        var modulusBytes = [UInt8](components.modulus)
        let exponentBytes = [UInt8](components.exponent)
        let privateExponentBytes = [UInt8](components.privateExponent)

        // Ensure the modulus is prefixed with 0x00.
        if let prefix = modulusBytes.first, prefix != 0x00 {
            modulusBytes.insert(0x00, at: 0)
        }

        let modulusEncoded = modulusBytes.encode(as: .integer)
        let exponentEncoded = exponentBytes.encode(as: .integer)
        let privateExponentEncoded = privateExponentBytes.encode(as: .integer)

        let sequenceEncoded = (modulusEncoded + exponentEncoded + privateExponentEncoded).encode(as: .sequence)

        return Data(sequenceEncoded)
    }

    // TODO: this will be wrong
    public func rsaPrivateKeyComponents() throws -> RSAPrivateKeyComponents {
        let publicKeyBytes = [UInt8](self)

        let sequence = try publicKeyBytes.read(.sequence)
        var modulus = try sequence.read(.integer)
        let exponent = try sequence.skip(.integer).read(.integer)
        let privateExponent = try sequence.skip(.integer).skip(.integer).read(.integer)

        // Remove potential leading zero byte.
        // See https://tools.ietf.org/html/rfc7518#section-6.3.1.1.
        if modulus.first == 0x00 {
            modulus = Array(modulus.dropFirst())
        }

        return (
            Data(modulus),
            Data(exponent),
            Data(privateExponent)
        )
    }
}
