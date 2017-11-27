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
        - `EncryptionError.keyEncryptionAlgorithmNotSupported`: If the provided algorithm is not supported for key decryption.
        - `EncryptionError.cipherTextLenghtNotSatisfied`: If the cipher text length exceeds the allowed maximum.
        - `EncryptionError.decryptingFailed(descritpion: String)`: If the decryption failed with a specific error.
     
     - Returns: The plain text (decrypted cipher text).
     */
    func decrypt(_ ciphertext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data
}

internal protocol SymmetricDecrypter {
    init(symmetricKey: Data)
    func decrypt(_ ciphertext: Data, initializationVector: Data, additionalAuthenticatedData: Data, authenticationTag: Data) throws -> Data
}

public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

public struct Decrypter {
    let asymmetricDecrypter: AsymmetricDecrypter
    
    public init(keyDecryptionAlgorithm: AsymmetricEncryptionAlgorithm, keyDecryptionKey kdk: SecKey) throws {
        // Todo: Find out which available encrypter supports the specified algorithm and throw error if necessary. See https://mohemian.atlassian.net/browse/JOSE-58.
        self.asymmetricDecrypter = RSADecrypter(privateKey: kdk)
    }
    
    func decrypt(_ context: DecryptionContext) throws -> Data {
        let cdk = try asymmetricDecrypter.decrypt(context.encryptedKey, using: context.header.algorithm!)
        
        // Todo: Find out which available decrypter supports the specified algorithm and throw error if necessary. See https://mohemian.atlassian.net/browse/JOSE-58.
        return try AESDecrypter(symmetricKey: cdk).decrypt(
            context.ciphertext,
            initializationVector: context.initializationVector,
            additionalAuthenticatedData: context.header.data().base64URLEncodedData(),
            authenticationTag: context.authenticationTag
        )
    }
}
