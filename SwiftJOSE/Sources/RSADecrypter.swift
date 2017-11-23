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
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw EncryptionError.keyEncryptionAlgorithmNotSupported
        }
        
        guard ciphertext.count == SecKeyGetBlockSize(privateKey) else {
            throw EncryptionError.plainTextLengthNotSatisfied
        }
        
        var decryptionError: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, algorithm, ciphertext as CFData, &decryptionError) else {
            throw EncryptionError.encryptingFailed(description: decryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }
        
        return plainText as Data
    }
}
