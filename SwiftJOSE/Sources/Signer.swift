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

public enum SigningError: Error {
    case algorithmNotSupported
    case signingFailed(description: String)
    case verificationFailed(descritpion: String)
    case algorithmMismatch
    case cannotComputeSigningInput
}

public enum SigningAlgorithm: String {
    case RS512 = "RS512"

    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RS512:
            return .rsaSignatureMessagePKCS1v15SHA512
        }
    }
}

protocol SignerProtocol {
    var algorithm: SigningAlgorithm { get }
    
    /// Initializes a `Signer` with a specified key.
    init(algorithm: SigningAlgorithm, privateKey: SecKey)

    /**
     Signs input data.
     - Parameters:
        - signingInput: The input to sign.
     
     - Throws:
        - `SigningError.algorithmNotSupported`: If the provided algorithm is not supported for signing.
        - `SigningError.signingFailes(description: String)`: If the signing failed with a specific error description.
     
     - Returns: The signature.
     */
    func sign(_ signingInput: Data) throws -> Data
}

public struct Signer {
    let signer: SignerProtocol
    
    public init(signingAlgorithm: SigningAlgorithm, privateKey: SecKey) {
        self.signer = CryptoFactory.signer(for: signingAlgorithm, with: privateKey)
    }
    
    func sign(header: JWSHeader, payload: Payload) throws -> Data {
        guard let alg = header.algorithm, alg == signer.algorithm else {
            throw SigningError.algorithmMismatch
        }
        
        guard let signingInput = [header, payload].asJOSESigningInput() else {
            throw SigningError.cannotComputeSigningInput
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
