//
//  AESKeyWrappingMode.swift
//  JOSESwift
//
//  Created by Daniel Egger on 17.02.20.
//

import Foundation

/// A key management mode in which the content encryption key value is encrypted to the intended recipient using a
/// symmetric key wrapping algorithm.
struct AESKeyWrappingMode {
    typealias KeyType = AES.KeyType

    private let keyManagementAlgorithm: KeyManagementAlgorithm
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let sharedSymmetricKey: KeyType

    init(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        sharedSymmetricKey: KeyType
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.sharedSymmetricKey = sharedSymmetricKey
    }
}

extension AESKeyWrappingMode: EncryptionKeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data) {
        let contentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)

        let encryptedKey = try AES.keyWrap(
            rawKey: contentEncryptionKey,
            keyEncryptionKey: sharedSymmetricKey,
            algorithm: keyManagementAlgorithm
        )

        return (contentEncryptionKey, encryptedKey)
    }
}

extension AESKeyWrappingMode: DecryptionKeyManagementMode {
    func determineContentEncryptionKey(from encryptedKey: Data) throws -> Data {
        let contentEncryptionKey = try AES.keyUnwrap(
            wrappedKey: encryptedKey,
            keyEncryptionKey: sharedSymmetricKey,
            algorithm: keyManagementAlgorithm
        )

        guard contentEncryptionKey.count == contentEncryptionAlgorithm.keyLength else {
            throw AESError.keyLengthNotSatisfied
        }

        return contentEncryptionKey
    }
}
