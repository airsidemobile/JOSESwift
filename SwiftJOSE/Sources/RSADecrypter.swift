//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSADecrypter: AsymmetricDecrypter {
    let privateKey: SecKey
    
    func decrypt(_ ciphertext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data {
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .decrypt, secKeyAlgorithm) else {
            throw EncryptionError.keyEncryptionAlgorithmNotSupported
        }
        
        guard algorithm.isCipherTextLenghtSatisfied(ciphertext, for: privateKey) else {
            throw EncryptionError.cipherTextLenghtNotSatisfied
        }
        
        var decryptionError: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, secKeyAlgorithm, ciphertext as CFData, &decryptionError) else {
            throw EncryptionError.encryptingFailed(description: decryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }
        
        return plainText as Data
    }
}
