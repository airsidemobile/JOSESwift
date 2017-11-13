//
//  RSASigner.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSASigner: Signer {
    let key: SecKey
    
    public init(key: SecKey) {
        self.key = key
    }
    
    public func sign(_ signingInput: Data, using algorithm: Algorithm) -> Data? {
        guard let algorithm = algorithm.secKeyAlgorithm else {
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
