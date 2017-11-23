//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSAEncrypter: AsymmetricEncrypter {
    let publicKey: SecKey
    
    init(publicKey: SecKey) {
        self.publicKey = publicKey
    }
    
    func encrypt(_ plaintext: Data, using algorithm: AsymmetricEncryptionAlgorithm) -> Data? {
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            //TODO: Error handling
            return nil
        }
        
        guard (plaintext.count < (SecKeyGetBlockSize(publicKey) - 11)) else {
            //TODO: Think of adding this to the `AsymmetricEncryptionAlgorithm` enum
            //TODO: Error handling
            return nil
        }
        
        var encryptionError: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, algorithm, plaintext as CFData, &encryptionError) else {
            //TODO: Error handling
            return nil
        }
        
        return cipherText as Data
    }
}
