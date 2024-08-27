//
//  Signer.swift
//  JOSESwift
//
//  Created by Daniel Egger on 18/08/2017.
//  Modified by Jarrod Moldrich on 02.07.18.
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

    /// Constructs a signer used to sign a JWS.
    ///
    /// - Parameters:
    ///   - signingAlgorithm: The desired `SignatureAlgorithm`.
    ///   - key: The key used to compute the JWS's signature or message authentication code (MAC).
    ///     Currently supported key types are: `SecKey` and `Data`.
    ///     - For _digital signature algorithms_ it is the sender's private key (`SecKey`)
    ///       with which the JWS should be signed.
    ///     - For _MAC algorithms_ it is the secret symmetric key (`Data`)
    ///       shared between the sender and the recipient.
    /// - Returns: A fully initialized `Signer` or `nil` if provided key is of the wrong type.
    public init?(signingAlgorithm: SignatureAlgorithm, key: KeyType) {
        switch signingAlgorithm {
        case .HS256, .HS384, .HS512:
            guard type(of: key) is HMACSigner.KeyType.Type else {
                return nil
            }
            // swiftlint:disable:next force_cast
            self.signer = HMACSigner(algorithm: signingAlgorithm, key: key as! HMACSigner.KeyType)
        case .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
            guard type(of: key) is RSASigner.KeyType.Type else {
                return nil
            }
            // swiftlint:disable:next force_cast
            self.signer = RSASigner(algorithm: signingAlgorithm, privateKey: key as! RSASigner.KeyType)
        case .ES256, .ES384, .ES512:
            guard type(of: key) is ECSigner.KeyType.Type else {
                return nil
            }
            // swiftlint:disable:next force_cast
            self.signer = ECSigner(algorithm: signingAlgorithm, privateKey: key as! ECSigner.KeyType)
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

// MARK: - Deprecated API

extension Signer {
    @available(*, deprecated, message: "Use `init?(signingAlgorithm: SignatureAlgorithm, key: KeyType)` instead")
    public init?(signingAlgorithm: SignatureAlgorithm, privateKey: KeyType) {
        self.init(signingAlgorithm: signingAlgorithm, key: privateKey)
    }
}
