//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation

public struct AESEncrypter: SymmetricEncrypter {
    func generateCEK(for algorithm: SymmetricEncryptionAlgorithm) -> Data {
        // Todo: Generate CEK using a trusted cryptography library.
        // See: https://mohemian.atlassian.net/browse/JOSE-62.
        return Data(count: 64)
    }
    
    func generateIV(for algorithm: SymmetricEncryptionAlgorithm) -> Data {
        // Todo: Generate IV using a trusted cryptography library.
        // See: https://mohemian.atlassian.net/browse/JOSE-62.
        return "iv".data(using: .utf8)!
    }
    
    func encrypt(_ plaintext: Data, aad: Data, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> SymmetricEncryptionContext {
        
        let iv = generateIV(for: algorithm)
        
        // Todo: Throw error if necessary.
        return SymmetricEncryptionContext(
            ciphertext: "ciphertext".data(using: .utf8)!,
            authenticationTag: "authTag".data(using: .utf8)!,
            initializationVector: iv
        )
    }
}
