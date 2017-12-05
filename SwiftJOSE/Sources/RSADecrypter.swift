//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
//

import Foundation

/// An `AsymmetricDecrypter` to decrypt cipher text with a `RSA` algorithm.
public struct RSADecrypter: AsymmetricDecrypter {
    let privateKey: SecKey

    func decrypt(_ ciphertext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data {
        // Check if AsymmetricEncryptionAlgorithm supports a secKeyAlgorithm and if the algorithm is supported to decrypt with a given private key.
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .decrypt, secKeyAlgorithm) else {
            throw EncryptionError.encryptionAlgorithmNotSupported
        }

        // Check if the cipher text length does not exceed the maximum.
        // e.g. for RSAPKCS the cipher text has the same length as the private key's modulus.
        guard algorithm.isCipherTextLenghtSatisfied(ciphertext, for: privateKey) else {
            throw EncryptionError.cipherTextLenghtNotSatisfied
        }

        // Decrypt the cipher text with a given SecKeyAlgorithm and a private key, return cipher text if no error occured.
        var decryptionError: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, secKeyAlgorithm, ciphertext as CFData, &decryptionError) else {
            throw EncryptionError.decryptingFailed(description: decryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }

        return plainText as Data
    }
}
