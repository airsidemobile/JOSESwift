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
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
     
    public var compactSerialized: String {
        return JOSESerializer().compact(self)
    }
    
    public init(header: JWEHeader, payload: JWEPayload, encrypter: Encrypter) {
        self.header = header
        
        let cryptoParts = encrypter.encrypt(plaintext: payload.data(), withHeader: header)
        self.encryptedKey = cryptoParts.encryptedKey
        self.initializationVector = cryptoParts.initializationVector
        self.ciphertext = cryptoParts.ciphertext
        self.authenticationTag = cryptoParts.authenticationTag
    }
    
    public init(compactSerialization: String) {
        self = JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: compactSerialization)
    }
    
    private init(header: JWEHeader, encryptedKey: Data, initializationVector: Data, ciphertext: Data, authenticationTag: Data) {
        self.header = header
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
    }
    
    public func decrypt(with decrypter: Decrypter) -> JWEPayload? {
        let plaintext = decrypter.decrypt(ciphertext: ciphertext, withHeader: header, encryptedKey: encryptedKey, initializationVector: initializationVector, authenticationTag: authenticationTag)!
        return JWEPayload(plaintext)
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
        self.init(header: header, encryptedKey: encryptedKey, initializationVector: initializationVector, ciphertext: ciphertext, authenticationTag: authenticationTag)
    }
}

// For testing only
extension JWE: CustomStringConvertible {
    public var description: String {
        let header = self.header.parameters.description
        let encryptedKey = String(data: self.encryptedKey, encoding: .utf8)!
        let initializationVector = String(data: self.initializationVector, encoding: .utf8)!
        let ciphertext = String(data: self.ciphertext, encoding: .utf8)!
        let authenticationTag = String(data: self.authenticationTag, encoding: .utf8)!
        return "\(header) . \(encryptedKey) . \(initializationVector) . \(ciphertext) . \(authenticationTag)"
    }
}
