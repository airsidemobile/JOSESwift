//
//  KeyManaggementMode.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

protocol KeyManagementModeImplementation {
    func determineContentEncryptionKey() throws -> (plaintextKey: Data, encryptedKey: Data)
}

enum KeyManagementMode {
    static func makeImplementation<KeyType>(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        encryptionKey: KeyType
    ) -> KeyManagementModeImplementation? {
        switch keyManagementAlgorithm {
        case .RSA1_5, .RSAOAEP, .RSAOAEP256:
            guard type(of: encryptionKey) is RSAKeyEncryption.KeyType.Type else { return nil }
            let recipientPublicKey = encryptionKey as! RSAKeyEncryption.KeyType

            return RSAKeyEncryption(
                keyManagementAlgorithm: keyManagementAlgorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPublicKey: recipientPublicKey
            )
        case .direct:
            guard type(of: encryptionKey) is DirectEncryption.KeyType.Type else { return nil }
            let sharedSymmetricKey = encryptionKey as! DirectEncryption.KeyType

            return DirectEncryption(sharedSymmetricKey: sharedSymmetricKey)
        }
    }
}
