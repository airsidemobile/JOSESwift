//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct AESEncrypter: SymmetricEncrypter {
    let sharedKey: Data
    
    func encrypt(_ plaintext: Data, withAdditionalAuthenticatedData aad: Data) -> EncryptionResult {
        return EncryptionResult(
            ciphertext: "ciphertext".data(using: .utf8)!,
            authenticationTag: "authTag".data(using: .utf8)!,
            initializationVector: "iv".data(using: .utf8)!
        )
    }
}
