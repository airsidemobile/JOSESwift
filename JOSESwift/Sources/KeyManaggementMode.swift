//
//  KeyManaggementMode.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

protocol KeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data)
}

extension KeyManagementAlgorithm {
    private enum KeyManagementModeError: Error {
        case wrongKeyTypeForAlgorithm(algorithm: KeyManagementAlgorithm)
    }

    func makeKeyManagementMode<KeyType>(
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        encryptionKey: KeyType
    ) throws -> KeyManagementMode {
        switch self {
        case .RSA1_5, .RSAOAEP, .RSAOAEP256:
            guard let recipientPublicKey = cast(encryptionKey, to: RSAEncrypter.KeyType.self) else {
                throw KeyManagementModeError.wrongKeyTypeForAlgorithm(algorithm: self)
            }

            return RSAKeyEncryption(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPublicKey: recipientPublicKey
            )
        case .direct:
            guard let sharedSymmetricKey = cast(encryptionKey, to: DirectEncryption.KeyType.self) else {
                throw KeyManagementModeError.wrongKeyTypeForAlgorithm(algorithm: self)
            }

            return DirectEncryption(sharedSymmetricKey: sharedSymmetricKey)
        }
    }
}

private func cast<GivenType, ExpectedType>(
    _ something: GivenType,
    to expectedType: ExpectedType.Type
) -> ExpectedType? {
    // A conditional downcast to the CoreFoundation type SecKey will always succeed.
    // Therfore we perform runtime type checking to guarantee that the given encryption key's type
    // matches the type that the respective key management mode expects.
    return (type(of: something) is ExpectedType.Type) ? (something as! ExpectedType) : nil
}
