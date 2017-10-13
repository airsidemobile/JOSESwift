//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

protocol JWECryptoParts {
    var encryptedKey: Data { get }
    var initializationVector: Data { get }
    var ciphertext: Data { get }
    var authenticationTag: Data { get }
}

protocol Encrypter {
    init()
    func encrypt(plaintext: Data, withHeader header: JWEHeader) -> JWECryptoParts
}
