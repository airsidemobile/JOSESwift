//
//  MultiDecryptor.swift
//  JOSESwift
//
//  Created by Prem Eide on 05/12/2025.
//

import Foundation

public struct MultiDecryptor: JWEDecrypter {
    private let jwk: JWK
    
    public init(jwk: JWK) {
        self.jwk = jwk
    }
    
    public func decrypt(_ context: DecryptionContext) throws -> Data {
        let recipients = try getRecipients(from: context)
        let expectedKid = try jwk.thumbprint()
        
        guard let recipient = recipients.first(where: { $0.unprotectedHeader?.keyID == expectedKid }) else {
            throw MultiDecryptorError.recipientNotFound
        }
        guard let recipientHeader = recipient.unprotectedHeader else {
            throw MultiDecryptorError.missingRecipientHeader
        }
        
        let joinedHeader = try context.header.join(recipientHeader)
        
        let newContext = DecryptionContext(
            header: joinedHeader,
            encryptedKey: recipient.encryptedKey,
            initializationVector: context.initializationVector,
            ciphertext: context.ciphertext,
            authenticationTag: context.authenticationTag,
            aad: context.aad
        )
        
        guard let keyAlg = recipientHeader.alg else {
            throw MultiDecryptorError.missingKeyManagementAlgorithm
        }
        guard let contentAlg = joinedHeader.contentEncryptionAlgorithm else {
            throw MultiDecryptorError.missingContentEncryptionAlgorithm
        }
        
        guard let decrypter = Decrypter(
            keyManagementAlgorithm: keyAlg,
            contentEncryptionAlgorithm: contentAlg,
            decryptionKey: jwk
        ) else {
            throw MultiDecryptorError.couldNotCreateDecrypter
        }
        return try decrypter.decrypt(newContext)
    }
    
    private func getRecipients(from context: DecryptionContext) throws -> [Recipient] {
        let recipientsData = try context.encryptedKey.decode()
        let jsonObject = try JWEObjectJSON.parseJSONObject(recipientsData)
        return try JWEObjectJSON.parseRecipients(from: jsonObject)
    }
}

internal enum MultiDecryptorError: Error {
    case recipientNotFound
    case missingRecipientHeader
    case missingKeyManagementAlgorithm
    case missingContentEncryptionAlgorithm
    case couldNotCreateDecrypter
}
