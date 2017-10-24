//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

// Dummy container to store cryptographic values that are related to
// and/or computed in the encryption process and not part of the skeleton.
public struct JWECryptoParts {
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

public protocol Encrypter {
    init(publicKey kek: String)
    func encrypt(plaintext: Data, withHeader header: JWEHeader) -> JWECryptoParts
}
