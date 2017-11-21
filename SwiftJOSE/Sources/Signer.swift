//
//  Signer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//

import Foundation

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
    init(key: SecKey)
    func sign(_ signingInput: Data, using algorithm: SigningAlgorithm) -> Data?
}
