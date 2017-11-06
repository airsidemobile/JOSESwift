//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSAEncrypter: Encrypter {
    let kek: String
    
    public init(publicKey kek: String) {
        self.kek = kek
    }
    
    public func encrypt(plaintext: Data, withHeader header: JWEHeader) -> (ciphertext: Data, additionalInformation: JWEAdditionalCryptoInformation) {
        let additionalInformation = JWEAdditionalCryptoInformation(
            encryptedKey: "encryptedkey".data(using: .utf8)!,
            initializationVector: "iv".data(using: .utf8)!,
            authenticationTag: "authtag".data(using: .utf8)!
        )
        return ("ciphertext".data(using: .utf8)!, additionalInformation)
    }
}
