//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation

public struct AESEncrypter: SymmetricEncrypter {
    func encrypt(_ plaintext: Data, aad: Data, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> SymmetricEncryptionContext {
        // Todo: Generate IV using a trusted cryptography library.
        let iv = "iv".data(using: .utf8)!
        
        // Todo: Throw error if necessary.
        return SymmetricEncryptionContext(
            ciphertext: "ciphertext".data(using: .utf8)!,
            authenticationTag: "authTag".data(using: .utf8)!,
            initializationVector: iv
        )
    }
}
