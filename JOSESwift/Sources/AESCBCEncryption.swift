//
//  AESCBCEncryption.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

struct AESCBCEncryption: ContentEncryptionImplementation {
    typealias KeyType = AES.KeyType

    let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    let contentEncryptionKey: KeyType

    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, contentEncryptionKey: KeyType) {
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.contentEncryptionKey = contentEncryptionKey
    }

    func encrypt(header: JWEHeader, payload: Payload, with contentEncryptionKey: Data) throws -> ContentEncryptionContext {
        let additionalAuthenticatedData = header.data().base64URLEncodedData()
        let plaintext = payload.data()

        // Generate random intitialization vector.
        let iv = try SecureRandom.generate(count: contentEncryptionAlgorithm.initializationVectorLength)

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey

        // Encrypt the plaintext with a symmetric encryption key, a symmetric encryption algorithm and an initialization vector.
        let cipherText = try AES.encrypt(plaintext: plaintext, with: encryptionKey, using: contentEncryptionAlgorithm, and: iv)

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(iv)
        concatData.append(cipherText)
        concatData.append(additionalAuthenticatedData.getByteLengthAsOctetHexData())

        // Calculate the HMAC with the concatenated input data, the HMAC key and the HMAC algorithm.
        let hmacOutput = try HMAC.calculate(from: concatData, with: hmacKey, using: contentEncryptionAlgorithm.hmacAlgorithm)
        let authenticationTag = contentEncryptionAlgorithm.authenticationTag(for: hmacOutput)

        return ContentEncryptionContext(
            ciphertext: cipherText,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }
}
