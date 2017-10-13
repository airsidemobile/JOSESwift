//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

struct JWECryptoParts {
    let encryptedKey: String
    let initializationVector: String
    let ciphertext: String
    let authenticationTag: String
}

protocol Encrypter {
    init(publicKey kek: String)
    func encrypt(plaintext: Data, withHeader header: JWEHeader) -> JWECryptoParts
}
