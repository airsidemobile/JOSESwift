//
//  Signer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
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
    init(privateKey: SecKey, algorithm: SigningAlgorithm)

    /**
     Signs input data with a given algorithm and the corresponding key.
     - Parameters:
        - signingInput: The input to sign.
        - algorithm: The algorithm to sign the input.
     
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
        self.signer = RSASigner(privateKey: privateKey, algorithm: signingAlgorithm) // Todo: factory; don't hard code RSA
    }
    
    func sign(header: JWSHeader, payload: Payload) throws -> Data {
        guard let alg = header.algorithm, alg == signer.algorithm else {
            throw SigningError.algorithmMismatch
        }
        
        let encoded = [header, payload].map { (component: DataConvertible) in
            return component.data().base64URLEncodedString()
        }
        
        guard let signingInput = encoded.joined(separator: ".").data(using: .ascii) else {
            throw SigningError.cannotComputeSigningInput
        }
        
        return try signer.sign(signingInput)
    }
}
