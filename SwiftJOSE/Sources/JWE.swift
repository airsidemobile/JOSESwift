//
//  JWE.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 12/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

/// A JWE consisting of five parameters as specified in [RFC-7516](https://tools.ietf.org/html/rfc7516).
/// The JWE is fully initialized with those five (immutable) parameters.
/// All representations of the JWE or it's parts like it's compact serialization or the plaintext can be derived from those five parameters.
/// Therefore (and to keep immutability) it does not cache such representations.
/// As discussed, it is the responsibility of the framework user to cache e.g. the plaintext. Of course this will have to be communicated clearly.
public struct JWE {
    /// The JWE's JOSE Header.
    let header: JWEHeader
    
    /// The encrypted content encryption key (CEK).
    let encryptedKey: Data
    
    /// The initialization value used when encrypting the plaintext.
    let initializationVector: Data
    
    /// The ciphertext resulting from authenticated encryption of the plaintext.
    let ciphertext: Data
    
    /// The output of an authenticated encryption with associated data that ensures the integrity of the ciphertext and the additional associeated data.
    let authenticationTag: Data
 
    /// The Compact Serialization of this JWE.
    public var compactSerialized: String {
        return JOSESerializer().compact(self)
    }
    
    /// Initializes a JWE with a given header, payload and encrypter.
    /// Note that we could also provide default headers and encrypters for some usecases to make the usage of the framework even easier.
    /// See [JOSE-43](https://mohemian.atlassian.net/browse/JOSE-43).
    public init(header: JWEHeader, payload: JWEPayload, encrypter: Encrypter) {
        self.header = header
        let encryption = encrypter.encrypt(header: header, payload: payload)
        self.encryptedKey = encrypter.encryptedKey
        self.ciphertext = encryption.ciphertext
        self.initializationVector = encryption.initializationVector
        self.authenticationTag = encryption.authenticationTag
    }
    
    /// Initializes a JWE from a given compact serialization.
    public init(compactSerialization: String) {
        self = JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: compactSerialization)
    }
    
    /// Initializes a JWE by providing all of it's five parts. Onyl used during deserialization.
    private init(header: JWEHeader, encryptedKey: Data, initializationVector: Data, ciphertext: Data, authenticationTag: Data) {
        self.header = header
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
    }
    
    /// Decrypt the JWE's ciphertext and return the corresponding plaintext.
    /// As mentioned it is the responsibility of the user to chache this plaintext.
    public func decrypt(with decrypter: Decrypter) -> JWEPayload? {
        let plaintext = decrypter.decrypt(
            DecryptionInput(
                header: header,
                encryptedKey: encryptedKey,
                initializationVector: initializationVector,
                ciphertext: ciphertext,
                authenticationTag: authenticationTag
            )
        )
        return JWEPayload(plaintext!)
    }
}

/// Serialize the JWE to a given compact serializer.
extension JWE: CompactSerializable {
    public func serialize(to serializer: inout CompactSerializer) {
        serializer.serialize(header)
        serializer.serialize(encryptedKey)
        serializer.serialize(initializationVector)
        serializer.serialize(ciphertext)
        serializer.serialize(authenticationTag)
    }
}

/// Deserialize the JWE from a given compact deserializer.
extension JWE: CompactDeserializable {
    public init (from deserializer: CompactDeserializer) {
        let header = JWEHeader(from: deserializer)
        let encryptedKey = deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweEncryptedKeyIndex)
        let initializationVector = deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweInitializationVectorIndex)
        let ciphertext = deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweCiphertextIndex)
        let authenticationTag = deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweAuthenticationTagIndex)
        self.init(header: header, encryptedKey: encryptedKey, initializationVector: initializationVector, ciphertext: ciphertext, authenticationTag: authenticationTag)
    }
}

/// For testing only.
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
