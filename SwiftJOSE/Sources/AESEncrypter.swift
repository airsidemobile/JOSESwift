//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct AESEncrypter: SymmetricEncrypter {
    let symmetricKey: SecKey
    
    func encrypt(_ plaintext: Data, with aad: Data) -> EncryptionContext {
        return EncryptionContext(
            ciphertext: "ciphertext".data(using: .utf8)!,
            authenticationTag: "authTag".data(using: .utf8)!,
            initializationVector: "iv".data(using: .utf8)!
        )
    }
}
