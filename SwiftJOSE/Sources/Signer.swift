//
//  Signer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
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

protocol SignerProtocol {
    var algorithm: SignatureAlgorithm { get }

    /// Signs input data.
    ///
    /// - Parameter signingInput: The input to sign.
    /// - Returns: The signature.
    /// - Throws: `JWSError` if any error occurs while signing.
    func sign(_ signingInput: Data) throws -> Data
}

public struct Signer<KeyType> {
    let signer: SignerProtocol

    public init?(signingAlgorithm: SignatureAlgorithm, privateKey: KeyType) {
        switch signingAlgorithm {
        case .RS512:
            if type(of: privateKey) is RSASigner.KeyType.Type {
                let key = privateKey as! RSASigner.KeyType
                self.signer = RSASigner(algorithm: signingAlgorithm, privateKey: key)
            } else {
                return nil
            }
        }
    }

    internal func sign(header: JWSHeader, payload: Payload) throws -> Data {
        guard let alg = header.algorithm, alg == signer.algorithm else {
            throw JWSError.algorithmMismatch
        }

        guard let signingInput = [header, payload].asJOSESigningInput() else {
            throw JWSError.cannotComputeSigningInput
        }

        return try signer.sign(signingInput)
    }
}

extension Array where Element == DataConvertible {
    func asJOSESigningInput() -> Data? {
        let encoded = self.map { component in
            return component.data().base64URLEncodedString()
        }

        return encoded.joined(separator: ".").data(using: .ascii)
    }
}
