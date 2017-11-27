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

public protocol Signer {
    /// Initializes a `Signer` with a specified key.
    init(key: SecKey)

    /**
     Signs input data with a given algorithm and the corresponding key.
     - Parameters:
        - signingInput: The input to sign.
        - algorithm: The algorithm to sign the input.
     
     - Returns: The signature.
     */
    func sign(_ signingInput: Data, using algorithm: SigningAlgorithm) throws -> Data
}
