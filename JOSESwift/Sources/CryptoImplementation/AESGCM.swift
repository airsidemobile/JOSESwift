//
//  AESGCM.swift
//  JOSESwift
//

import Foundation
import CryptoKit

enum AESGCM {
    typealias KeyType = Data

    /// Encrypts a plain text using a given `AES.GCM` algorithm.
    ///
    /// - Parameters:
    ///   - plaintext: The plain text to encrypt.
    ///   - encryptionKey: The symmetric key.
    ///   - initializationVector: The initial block.
    ///   - additionalAuthenticatedData: The additional data block that is to be authenticated.
    /// - Returns: The encryption context containing ciphertext, the authentication tag and the `IV`
    /// - Throws: an error if any error occurs during encryption.
    static func encrypt(
        plaintext: Data,
        encryptionKey: KeyType,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws -> ContentEncryptionContext {
        let key = CryptoKit.SymmetricKey(data: encryptionKey)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: initializationVector)
        let encrypted = try CryptoKit.AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: additionalAuthenticatedData)
        return ContentEncryptionContext(
            ciphertext: encrypted.ciphertext,
            authenticationTag: encrypted.tag,
            initializationVector: initializationVector
        )
    }

    /// Decrypts a cipher text using a given `AES.GCM` algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The encrypted cipher text to decrypt.
    ///   - decryptionKey: The symmetric key.
    ///   - initializationVector: The initial block.
    ///   - authenticationTag: The authentication tag.
    ///   - additionalAuthenticatedData: The additional data block that is to be authenticated.
    /// - Returns: The plain text (decrypted cipher text).
    /// - Throws: The call throws an error if decryption or authentication fails
    static func decrypt(
        cipherText: Data,
        decryptionKey: Data,
        initializationVector: Data,
        authenticationTag: Data,
        additionalAuthenticatedData: Data
    ) throws -> Data {
        let key = CryptoKit.SymmetricKey(data: decryptionKey)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: initializationVector)
        let encrypted = try CryptoKit.AES.GCM.SealedBox(nonce: nonce, ciphertext: cipherText, tag: authenticationTag)
        let decrypted = try CryptoKit.AES.GCM.open(encrypted, using: key, authenticating: additionalAuthenticatedData)
        return decrypted
        }
    }
