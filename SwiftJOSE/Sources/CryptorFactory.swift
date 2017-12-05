//
//  CryptorFactory.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 05.12.17.
//

import Foundation

struct CryptorFactory {
    
    static func encrypter(for algorithm: AsymmetricEncryptionAlgorithm, with publicKey: SecKey) -> AsymmetricEncrypter {
        switch algorithm {
        case .RSAPKCS:
            return RSAEncrypter(algorithm: algorithm, publicKey: publicKey)
        }
    }
    
    static func encrypter(for algorithm: SymmetricEncryptionAlgorithm) -> SymmetricEncrypter {
        switch algorithm {
        case .AESGCM256:
            return AESEncrypter(algorithm: algorithm)
        }
    }
    
    static func decrypter(for algorithm: AsymmetricEncryptionAlgorithm, with privateKey: SecKey) -> AsymmetricDecrypter {
        switch algorithm {
        case .RSAPKCS:
            return RSADecrypter(algorithm: algorithm, privateKey: privateKey)
        }
    }
    
    static func decrypter(for algotithm: SymmetricEncryptionAlgorithm) -> SymmetricDecrypter {
        switch algotithm {
        case .AESGCM256:
            return AESDecrypter(algorithm: algotithm)
        }
    }
    
}
