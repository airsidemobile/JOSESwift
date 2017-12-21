//
//  JWE.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 12/10/2017.
//

import Foundation

/// A JWE consisting of five parameters as specified in [RFC-7516](https://tools.ietf.org/html/rfc7516).
/// The JWE is fully initialized with those five (immutable) parameters.
/// All representations of the JWE or it's parts like it's compact serialization or the plaintext can be derived from those five parameters.
/// Therefore (and to keep immutability) it does not cache such representations.
/// As discussed, it is the responsibility of the framework user to cache e.g. the plaintext. Of course this will have to be communicated clearly.
public struct JWE {
    /// The JWE's JOSE Header.
    public let header: JWEHeader

    /// The encrypted content encryption key (CEK).
    public let encryptedKey: Data

    /// The initialization value used when encrypting the plaintext.
    public let initializationVector: Data

    /// The ciphertext resulting from authenticated encryption of the plaintext.
    public let ciphertext: Data

    /// The output of an authenticated encryption with associated data that ensures the integrity of the ciphertext and the additional associeated data.
    public let authenticationTag: Data

    /// The compact serialization of this JWE object as string.
    public var compactSerializedString: String {
        return JOSESerializer().serialize(compact: self)
    }
    
    /// The compact serialization of this JWE object as data.
    public var compactSerializedData: Data {
        // Force unwrapping is ok here, since `serialize` returns a string generated from data.
        // swiftlint:disable:next force_unwrap
        return JOSESerializer().serialize(compact: self).data(using: .utf8)!
    }

    /// Initializes a JWE with a given header, payload and encrypter.
    /// Note that we could also provide default headers and encrypters for some usecases to make the usage of the framework even easier.
    /// Note that we can infer the header `alg` and `enc` fields from the encrypter.
    /// See [JOSE-43](https://mohemian.atlassian.net/browse/JOSE-43).
    public init?(header: JWEHeader, payload: Payload, encrypter: Encrypter) {
        self.header = header

        guard let encryptionContext = try? encrypter.encrypt(header: header, payload: payload) else {
            return nil
        }

        self.encryptedKey = encryptionContext.encryptedKey
        self.ciphertext = encryptionContext.ciphertext
        self.initializationVector = encryptionContext.initializationVector
        self.authenticationTag = encryptionContext.authenticationTag
    }
    
    /// Constructs a JWE object from a given compact serialization string.
    ///
    /// - Parameter compactSerialization: A compact serialized JWS object as string as received e.g. from the server.
    /// - Throws:
    ///     - `DeserializationError.invalidCompactSerializationComponentCount(count: Int)`: If the component count of the compact serialization is wrong.
    ///     - `DeserializationError.componentNotValidBase64URL(component: String)`: If the component is not a valid base64URL string.
    ///     - `DeserializationError.componentCouldNotBeInitializedFromData(data: Data)`: If a component cannot be initialized from its data object.
    public init(compactSerialization: String) throws {
        self = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: compactSerialization)
    }

    /// Constructs a JWE object from a given compact serialization data object.
    ///
    /// - Parameter compactSerialization: A compact serialized JWS object as data object as received e.g. from the server.
    /// - Throws:
    ///     - `DeserializationError.wrongDataEncoding(data: Data)`: If the compact serialization data object is not convertible to string.
    ///     - `DeserializationError.invalidCompactSerializationComponentCount(count: Int)`: If the component count of the compact serialization is wrong.
    ///     - `DeserializationError.componentNotValidBase64URL(component: String)`: If the component is not a valid base64URL string.
    ///     - `DeserializationError.componentCouldNotBeInitializedFromData(data: Data)`: If a component cannot be initialized from its data object.
    public init(compactSerialization: Data) throws {
        guard let compactSerializationString = String(data: compactSerialization, encoding: .utf8) else {
            throw DeserializationError.wrongDataEncoding(data: compactSerialization)
        }
        
        self = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: compactSerializationString)
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
    /// Note that we can infer the algorithms and the shared key from the JWE. Ultimately the user only needs to provide a private key here.
    /// See [JOSE-43](https://mohemian.atlassian.net/browse/JOSE-43).
    public func decrypt(with kdk: SecKey) -> Payload? {
        let context = DecryptionContext(
            header: header,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag
        )

        guard let alg = header.algorithm, let enc = header.encryptionAlgorithm else {
            return nil
        }

        let decrypter = Decrypter(keyDecryptionAlgorithm: alg, keyDecryptionKey: kdk, contentDecryptionAlgorithm: enc)

        guard let plaintext = try? decrypter.decrypt(context) else {
            return nil
        }

        return Payload(plaintext)
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
    public static var componentCount: Int {
        return 5
    }

    public init (from deserializer: CompactDeserializer) throws {
        let header = try deserializer.deserialize(JWEHeader.self, at: ComponentCompactSerializedIndex.jweHeaderIndex)
        let encryptedKey = try deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweEncryptedKeyIndex)
        let initializationVector = try deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweInitializationVectorIndex)
        let ciphertext = try deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweCiphertextIndex)
        let authenticationTag = try deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jweAuthenticationTagIndex)
        self.init(header: header, encryptedKey: encryptedKey, initializationVector: initializationVector, ciphertext: ciphertext, authenticationTag: authenticationTag)
    }
}

/// For testing only.
extension JWE: CustomStringConvertible {
    public var description: String {
        let header = self.header.parameters.description
        let encryptedKey = String(data: self.encryptedKey, encoding: .utf8) ?? "encryptedKey"
        let initializationVector = String(data: self.initializationVector, encoding: .utf8) ?? "iv"
        let ciphertext = String(data: self.ciphertext, encoding: .utf8) ?? "ciphertext"
        let authenticationTag = String(data: self.authenticationTag, encoding: .utf8) ?? "authTag"
        return "\(header) . \(encryptedKey) . \(initializationVector) . \(ciphertext) . \(authenticationTag)"
    }
}
