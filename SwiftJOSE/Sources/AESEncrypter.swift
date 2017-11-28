//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation

public struct AESEncrypter: SymmetricEncrypter {
    let symmetricKey: SecKey
    
    func encrypt(_ plaintext: Data, aad: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> SymmetricEncryptionContext {
        // Todo: Throw error if necessary.
        return SymmetricEncryptionContext(
            ciphertext: "ciphertext".data(using: .utf8)!,
            authenticationTag: "authTag".data(using: .utf8)!,
            initializationVector: "iv".data(using: .utf8)!
        )
    }
}
