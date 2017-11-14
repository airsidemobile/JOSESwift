//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

internal protocol AsymmetricEncrypter {
    init(publicKey: Data)
    func encrypt(_ plaintext: Data) -> Data
}

internal protocol SymmetricEncrypter {
    init(symmetricKey: Data)
    func encrypt(_ plaintext: Data, with aad: Data) -> EncryptionContext
}

public struct EncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct Encrypter {
    let symmetricEncrypter: SymmetricEncrypter
    let encryptedKey: Data
    
    public init(keyEncryptionAlgorithm: Algorithm, keyEncryptionKey kek: Data, contentEncyptionAlgorithm: Algorithm, contentEncryptionKey cek: Data) {
        // Todo: Find out which available encrypters support the specified algorithms. See https://mohemian.atlassian.net/browse/JOSE-58.
        self.symmetricEncrypter = AESEncrypter(symmetricKey: cek)
        self.encryptedKey = RSAEncrypter(publicKey: kek).encrypt(cek)
    }
    
    func encrypt(header: JWEHeader, payload: JWEPayload) -> EncryptionContext {
        return symmetricEncrypter.encrypt(payload.data(), with: header.data().base64URLEncodedData())
    }
}
