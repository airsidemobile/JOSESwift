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
    
    func encrypt(_ plaintext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data {
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .encrypt, secKeyAlgorithm) else {
            throw EncryptionError.keyEncryptionAlgorithmNotSupported
        }

        guard algorithm.isPlainTextLengthSatisfied(plaintext, for: publicKey) else {
            throw EncryptionError.plainTextLengthNotSatisfied
        }
        
        var encryptionError: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, secKeyAlgorithm, plaintext as CFData, &encryptionError) else {
            throw EncryptionError.encryptingFailed(description: encryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }
        
        return cipherText as Data
    }
}
