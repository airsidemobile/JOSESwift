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
    let payload: JWEPayload
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
     
    public var compactSerialized: String {
        return JOSESerializer().compact(self)
    }
    
    public init(header: JWEHeader, payload: JWEPayload, encrypter: Encrypter) {
        self.header = header
        self.payload = payload
        
        let cryptoParts = encrypter.encrypt(plaintext: payload.data(), withHeader: header)
        self.encryptedKey = cryptoParts.encryptedKey
        self.initializationVector = cryptoParts.initializationVector
        self.ciphertext = cryptoParts.ciphertext
        self.authenticationTag = cryptoParts.authenticationTag
    }
}

extension JWE: CompactSerializable {
    public func serialize(to serializer: inout CompactSerializer) {
        serializer.serialize(header)
        serializer.serialize(encryptedKey)
        serializer.serialize(initializationVector)
        serializer.serialize(ciphertext)
        serializer.serialize(authenticationTag)
    }
}
