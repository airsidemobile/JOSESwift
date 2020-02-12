//
//  DirectEncrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

/// A key management mode in which the content encryption key value used is the secret
/// symmetric key value shared between the parties.
struct DirectEncryption: KeyManagementModeImplementation {
    typealias KeyType = Data

    let sharedSymmetricKey: KeyType

    init(sharedSymmetricKey: KeyType) {
        // Todo: Check if algorithm is correct
        self.sharedSymmetricKey = sharedSymmetricKey
    }

    func determineContentEncryptionKey() throws -> (plaintextKey: Data, encryptedKey: Data) {
        return (sharedSymmetricKey, KeyType())
    }
}
