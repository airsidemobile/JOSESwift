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
    
    public init(compactSerialization: String) {
        self = JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: compactSerialization)
    }
    
    private init(header: JWEHeader, payload: JWEPayload, encryptedKey: Data, initializationVector: Data, authenticationTag: Data, ciphertext: Data) {
        self.header = header
        self.payload = payload
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.authenticationTag = authenticationTag
        self.ciphertext = ciphertext
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

extension JWE: CompactDeserializable {
    public init (from deserializer: CompactDeserializer) {
        let header = JWEHeader(from: deserializer)
        let encryptedKey = deserializer.deserialize(Data.self, at: 1)
        let initializationVector = deserializer.deserialize(Data.self, at: 2)
        let ciphertext = deserializer.deserialize(Data.self, at: 3)
        let authenticationTag = deserializer.deserialize(Data.self, at: 4)
        
        // TODO: Decrypt
        let payload = JWEPayload("deserialized payload".data(using: .utf8)!)
        self.init(header: header, payload: payload, encryptedKey: encryptedKey, initializationVector: initializationVector, authenticationTag: authenticationTag, ciphertext: ciphertext)
    }
}
