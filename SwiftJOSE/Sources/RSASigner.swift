//
//  RSASigner.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

fileprivate extension Algorithm {
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RS512:
            return .rsaSignatureMessagePKCS1v15SHA512
        default:
            return nil
        }
    }
    
    var isSupported: Bool {
        switch self {
        case .RS512:
            return true
        default:
            return false
        }
    }
}

public struct RSASigner: Signer {
    let key: SecKey
    
    public init(key: SecKey) {
        self.key = key
    }
    
    public func sign(_ signingInput: Data, using algorithm: Algorithm) -> Data? {
        //TODO: Add error handling for signing error
        guard algorithm.isSupported, SecKeyIsAlgorithmSupported(key, .sign, algorithm.secKeyAlgorithm!) else {
            return nil
        }
        
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm.secKeyAlgorithm!, signingInput as CFData, &signingError) else {
            //TODO: throw signing error
            print("\(signingError!)")
            return nil
        }
        
        return signature as Data
    }
}
