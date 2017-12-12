//
//  Decrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 17/10/2017.
//

import Foundation

internal protocol AsymmetricDecrypter {
    /// Initializes an `AsymmetricDecrypter` with a specified private key.
    init(algorithm: AsymmetricEncryptionAlgorithm, privateKey: SecKey)
    
    var algorithm: AsymmetricEncryptionAlgorithm { get }
    
    /**
     Decrypts a cipher text using a given `AsymmetricEncryptionAlgorithm` and the corresponding private key.
     - Parameters:
        - ciphertext: The encrypted cipher text to decrypt.
        - algorithm: The algorithm used to decrypt the cipher text.
     
     - Throws:
        - `EncryptionError.encryptionAlgorithmNotSupported`: If the provided algorithm is not supported for decryption.
        - `EncryptionError.cipherTextLenghtNotSatisfied`: If the cipher text length exceeds the allowed maximum.
        - `EncryptionError.decryptingFailed(descritpion: String)`: If the decryption failed with a specific error.
     
     - Returns: The plain text (decrypted cipher text).
     */
    func decrypt(_ ciphertext: Data) throws -> Data
}

internal protocol SymmetricDecrypter {
    init(algorithm: SymmetricEncryptionAlgorithm)
    
    var algorithm: SymmetricEncryptionAlgorithm { get }

    /**
     Decrypts a cipher text contained in the `SymmetricDecryptionContext` using a given symmetric key.
     - Parameters:
        - context: The `SymmetricDecryptionContext` containing the ciphertext, the initialization vector, additional authenticated data and the authentication tag.
        - symmetricKey: The key which contains the HMAC and encryption key.
     
     - Throws:
        - `EncryptionError.decryptingFailed(descritpion: String)`: If the decryption failed with a specific error.
     
     - Returns: The plain text (decrypted cipher text).
     */
    func decrypt(_ context: SymmetricDecryptionContext, with symmetricKey: Data) throws -> Data
}

public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

public struct SymmetricDecryptionContext {
    let ciphertext: Data
    let initializationVector: Data
    let additionalAuthenticatedData: Data
    let authenticationTag: Data
}

public struct Decrypter {
    let asymmetric: AsymmetricDecrypter
    let symmetric: SymmetricDecrypter

    public init(keyDecryptionAlgorithm: AsymmetricEncryptionAlgorithm, keyDecryptionKey kdk: SecKey, contentDecryptionAlgorithm: SymmetricEncryptionAlgorithm) throws {
        self.asymmetric = CryptoFactory.decrypter(for: keyDecryptionAlgorithm, with: kdk)
        self.symmetric = CryptoFactory.decrypter(for: contentDecryptionAlgorithm)
    }

    func decrypt(_ context: DecryptionContext) throws -> Data {
        guard let alg = context.header.algorithm, alg == asymmetric.algorithm else {
            throw EncryptionError.keyEncryptionAlgorithmMismatch
        }
        
        guard let enc = context.header.encryptionAlgorithm, enc == symmetric.algorithm else {
            throw EncryptionError.contentEncryptionAlgorithmMismatch
        }

        let cek = try asymmetric.decrypt(context.encryptedKey)

        let symmetricContext = SymmetricDecryptionContext(
            ciphertext: context.ciphertext,
            initializationVector: context.initializationVector,
            additionalAuthenticatedData: context.header.data(),
            authenticationTag: context.authenticationTag
        )

        return try symmetric.decrypt(symmetricContext, with: cek)
    }
}
