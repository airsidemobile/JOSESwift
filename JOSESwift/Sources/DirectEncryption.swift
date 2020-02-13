//
//  DirectEncrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

/// A key management mode in which the content encryption key value used is a given secret symmetric key value shared
/// between the parties. For direct encryption the JWE encrypted key is the empty octet sequence.
struct DirectEncryption {
    typealias KeyType = Data

    let sharedSymmetricKey: KeyType

    init(sharedSymmetricKey: KeyType) {
        self.sharedSymmetricKey = sharedSymmetricKey
    }
}

extension DirectEncryption: KeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data) {
        return (sharedSymmetricKey, KeyType())
    }
}
