//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct AESEncrypter: Encrypter {
    let kek: String
    
    init(publicKey kek: String) {
        self.kek = kek
    }
    
    func encrypt(plaintext: Data, withHeader header: JWEHeader) -> JWECryptoParts {
        return JWECryptoParts(
            encryptedKey: "encryptedkey".data(using: .utf8)!,
            initializationVector: "iv".data(using: .utf8)!,
            ciphertext: "ciphertext".data(using: .utf8)!,
            authenticationTag: "authtag".data(using: .utf8)!
        )
    }
}
