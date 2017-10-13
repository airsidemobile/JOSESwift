//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

struct JWECryptoParts {
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

protocol Encrypter {
    init(publicKey kek: String)
    func encrypt(plaintext: Data, withHeader header: JWEHeader) -> JWECryptoParts
}
