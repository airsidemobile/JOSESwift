//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation

public struct AESEncrypter: SymmetricEncrypter {
    let symmetricKey: SecKey
    
    func encrypt(_ plaintext: Data, with aad: Data) throws -> EncryptionContext {
        // Todo: Throw error if necessary.
        return EncryptionContext(
            ciphertext: "ciphertext".data(using: .utf8)!,
            authenticationTag: "authTag".data(using: .utf8)!,
            initializationVector: "iv".data(using: .utf8)!
        )
    }
}
