//
//  Decrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 17/10/2017.
//

import Foundation

internal protocol AsymmetricDecrypter {
    /// Initializes an `AsymmetricDecrypter` with a specified private key.
    init(privateKey: SecKey)
    
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
    func decrypt(_ ciphertext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data
}

internal protocol SymmetricDecrypter {
    func decrypt(_ ciphertext: Data, iv: Data, aad: Data, authTag: Data, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> Data
}

public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

public struct Decrypter {
    let asymmetric: AsymmetricDecrypter
    let symmetric: SymmetricDecrypter
    
    public init(keyDecryptionAlgorithm: AsymmetricEncryptionAlgorithm, keyDecryptionKey kdk: SecKey, contentDecryptionAlgorithm: SymmetricEncryptionAlgorithm) throws {
        // Todo: Find out which available encrypter supports the specified algorithm and throw error if necessary.
        // See https://mohemian.atlassian.net/browse/JOSE-58.
        self.asymmetric = RSADecrypter(privateKey: kdk)
        self.symmetric = AESDecrypter()
    }
    
    func decrypt(_ context: DecryptionContext) throws -> Data {
        // Todo: This check might be redundant since it's already done in the `JWE.decrypt` step.
        // See https://mohemian.atlassian.net/browse/JOSE-58.
        guard let alg = context.header.algorithm, let enc = context.header.encryptionAlgorithm else {
            throw EncryptionError.encryptionAlgorithmNotSupported
        }
        
        let cek = try asymmetric.decrypt(context.encryptedKey, using: alg)
        
        return try symmetric.decrypt(
            context.ciphertext,
            iv: context.initializationVector,
            aad: context.header.data(),
            authTag: context.authenticationTag,
            with: cek,
            using: enc
        )
    }
}
