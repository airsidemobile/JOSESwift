//
//  JWE.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 12/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWE {
    let header: JWEHeader
    let payload: Payload
    let encryptedKey: String
    let initializationVector: String
    let ciphertext: String
    let authenticationTag: String
    
    init(header: JWEHeader, payload: Payload, encrypter: Encrypter) {
        self.header = header
        self.payload = payload
        
        let cryptoParts = encrypter.encrypt(plaintext: payload.data(), withHeader: header)
        self.encryptedKey = cryptoParts.encryptedKey
        self.initializationVector = cryptoParts.initializationVector
        self.ciphertext = cryptoParts.ciphertext
        self.authenticationTag = cryptoParts.authenticationTag
    }
}
