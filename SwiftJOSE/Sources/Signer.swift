//
//  Signer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
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
    init(key: SecKey)
    func sign(_ signingInput: Data, using algorithm: SigningAlgorithm) throws -> Data
}
