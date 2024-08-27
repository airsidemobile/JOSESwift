//
//  ECKeyEncryption.swift
//  JOSESwift
//
//  Created by Mikael Rucinsky on 07.12.20.
//

import Foundation

/// recipient using an asymmetric ECDH encryption algorithm. The resulting ciphertext is the JWE encrypted key.
enum ECKeyEncryption {
    typealias KeyType = EC.KeyType
    typealias PrivateKey = EC.PrivateKey
    typealias PublicKey = EC.PublicKey

    struct EncryptionMode {
        private let keyManagementAlgorithm: KeyManagementAlgorithm
        private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
        private let recipientPublicKey: PublicKey
        private let agreementPartyUInfo: Data
        private let agreementPartyVInfo: Data
        private let options: [String: Any]

        init(
            keyManagementAlgorithm: KeyManagementAlgorithm,
            contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
            recipientPublicKey: PublicKey,
            agreementPartyUInfo: Data,
            agreementPartyVInfo: Data,
            options: [String: Any] = [:]
        ) {
            self.keyManagementAlgorithm = keyManagementAlgorithm
            self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
            self.recipientPublicKey = recipientPublicKey
            self.agreementPartyUInfo = agreementPartyUInfo
            self.agreementPartyVInfo = agreementPartyVInfo
            self.options = options
        }
    }

    struct DecryptionMode {
        private let keyManagementAlgorithm: KeyManagementAlgorithm
        private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
        private let recipientPrivateKey: PrivateKey

        init(
            keyManagementAlgorithm: KeyManagementAlgorithm,
            contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
            recipientPrivateKey: PrivateKey
        ) {
            self.keyManagementAlgorithm = keyManagementAlgorithm
            self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
            self.recipientPrivateKey = recipientPrivateKey
        }
    }
}

extension ECKeyEncryption.EncryptionMode: EncryptionKeyManagementMode {
    var algorithm: KeyManagementAlgorithm {
        keyManagementAlgorithm
    }

    func determineContentEncryptionKey(with jweHeader: JWEHeader) throws -> EncryptionKeyManagementModeContext {
        let ecEncryption = try EC.encryptionContextFor(recipientPublicKey,
                                           algorithm: keyManagementAlgorithm,
                                           encryption: contentEncryptionAlgorithm,
                                           header: jweHeader,
                                           options: options)

        guard let updatedJweHeader = JWEHeader(ecEncryption.jweHeaderData) else {
            throw ECError.wrapKeyFail

        }

        return .init(
            contentEncryptionKey: ecEncryption.contentEncryptionKey,
            encryptedKey: ecEncryption.encryptedKey,
            jweHeader: updatedJweHeader
        )
    }
}

extension ECKeyEncryption.DecryptionMode: DecryptionKeyManagementMode {
    var algorithm: KeyManagementAlgorithm {
        keyManagementAlgorithm
    }

    func determineContentEncryptionKey(from encryptedKey: Data, with header: JWEHeader) throws -> Data {

        let randomContentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)

        let decryptedKey = try EC.decrypt(encryptedKey,
                                           privateKey: recipientPrivateKey,
                                           algorithm: keyManagementAlgorithm,
                                           encryption: contentEncryptionAlgorithm,
                                           header: header)

        guard decryptedKey.count == contentEncryptionAlgorithm.keyLength else { return randomContentEncryptionKey }

        return decryptedKey
    }
}
