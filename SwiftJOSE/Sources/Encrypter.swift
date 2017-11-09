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
    init(sharedKey: Data)
    func encrypt(_ plaintext: Data, withAdditionalAuthenticatedData aad: Data) -> EncryptionResult
}

public struct EncryptionResult {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct Encrypter {
    let symmetricEncrypter: SymmetricEncrypter
    let encryptedKey: Data
    
    public init(keyEncryptionAlgorithm: Algorithm, keyEncryptionKey kek: Data, contentEncyptionAlgorithm: Algorithm, contentEncryptionKey cek: Data) {
        // Todo: Find out which encrypter supports which algorithm. See [JOSE-51](https://mohemian.atlassian.net/browse/JOSE-51)
        self.symmetricEncrypter = AESEncrypter(sharedKey: cek)
        self.encryptedKey = RSAEncrypter(publicKey: kek).encrypt(cek)
    }
    
    func encrypt(header: JWEHeader, payload: JWEPayload) -> EncryptionResult {
        return symmetricEncrypter.encrypt(payload.data(), withAdditionalAuthenticatedData: header.data().base64URLEncodedData())
    }
}
