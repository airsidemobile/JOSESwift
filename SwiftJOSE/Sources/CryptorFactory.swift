//
//  CryptorFactory.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 05.12.17.
//

import Foundation

/**
  Factory deciding which cryptor to use for which algorithm.
  If we had different cryptor versions e.g. for different platforms,
  we could decide on which version to use here.
 */
struct CryptorFactory {
    
    /**
     Returns an asymmetric encrypter suitable for a given algorithm, initialized with a given public key.
     - Parameters:
        - algorithm: The asymmetric algorithm to use.
        - publicKey: The public key to initialize the asymmetric encrypter with.
     
     - Returns: The asymmetric encrypter suitable for the given algorithm, initialized with the given public key.
    */
    static func encrypter(for algorithm: AsymmetricEncryptionAlgorithm, with publicKey: SecKey) -> AsymmetricEncrypter {
        switch algorithm {
        case .RSAPKCS:
            return RSAEncrypter(algorithm: algorithm, publicKey: publicKey)
        }
    }
    
    /**
     Returns an symmetric encrypter suitable for a given algorithm.
     - Parameters:
     - algorithm: The symmetric algorithm to use.
     
     - Returns: The symmetric encrypter suitable for the given algorithm.
     */
    static func encrypter(for algorithm: SymmetricEncryptionAlgorithm) -> SymmetricEncrypter {
        switch algorithm {
        case .AES256CBCHS512:
            return AESEncrypter(algorithm: algorithm)
        }
    }
    
    /**
     Returns an asymmetric decrypter suitable for a given algorithm, initialized with a given private key.
     - Parameters:
     - algorithm: The asymmetric algorithm to use.
     - publicKey: The private key to initialize the asymmetric decrypter with.
     
     - Returns: The asymmetric decrypter suitable for the given algorithm, initialized with the given private key.
     */
    static func decrypter(for algorithm: AsymmetricEncryptionAlgorithm, with privateKey: SecKey) -> AsymmetricDecrypter {
        switch algorithm {
        case .RSAPKCS:
            return RSADecrypter(algorithm: algorithm, privateKey: privateKey)
        }
    }
    
    /**
     Returns an symmetric decrypter suitable for a given algorithm.
     - Parameters:
     - algorithm: The symmetric algorithm to use.
     
     - Returns: The symmetric decrypter suitable for the given algorithm.
     */
    static func decrypter(for algotithm: SymmetricEncryptionAlgorithm) -> SymmetricDecrypter {
        switch algotithm {
        case .AES256CBCHS512:
            return AESDecrypter(algorithm: algotithm)
        }
    }
    
}
