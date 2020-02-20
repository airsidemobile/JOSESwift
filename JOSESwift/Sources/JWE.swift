//
//  JWE.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12/10/2017.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation

internal enum JWEError: Error {
    case keyManagementAlgorithmMismatch
    case contentEncryptionAlgorithmMismatch
    case keyLengthNotSatisfied
    case hmacNotAuthenticated
}

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
        // swiftlint:disable:next force_unwrapping
        return JOSESerializer().serialize(compact: self).data(using: .utf8)!
    }

    /// Constructs a JWS object from a given header, payload, and signer.
    ///
    /// - Parameters:
    ///   - header: A fully initialized `JWEHeader`.
    ///   - payload: A fully initialized `Payload`.
    ///   - encrypter: The `Encrypter` used to encrypt the JWE from the header and payload.
    /// - Throws: `JOSESwiftError` if any error occurs while encrypting.
    public init<KeyType>(header: JWEHeader, payload: Payload, encrypter: Encrypter<KeyType>) throws {
        self.header = header

        var encryptionContext: Encrypter<KeyType>.EncryptionContext
        do {
            encryptionContext = try encrypter.encrypt(header: header, payload: payload.compressed(using: header.compressionAlgorithm))
        } catch JOSESwiftError.compressionFailed {
            throw JOSESwiftError.compressionFailed
        } catch JOSESwiftError.compressionAlgorithmNotSupported {
            throw JOSESwiftError.compressionAlgorithmNotSupported
        } catch {
            throw JOSESwiftError.encryptingFailed(description: error.localizedDescription)
        }

        self.encryptedKey = encryptionContext.encryptedKey
        self.ciphertext = encryptionContext.ciphertext
        self.initializationVector = encryptionContext.initializationVector
        self.authenticationTag = encryptionContext.authenticationTag
    }

    /// Constructs a JWE object from a given compact serialization string.
    ///
    /// - Parameters:
    ///     - compactSerialization: A compact serialized JWS object as string as received e.g. from the server.
    /// - Throws:
    ///     - `JOSESwiftError.invalidCompactSerializationComponentCount(count: Int)`:
    ///         If the component count of the compact serialization is wrong.
    ///     - `JOSESwiftError.componentNotValidBase64URL(component: String)`:
    ///         If the component is not a valid base64URL string.
    ///     - `JOSESwiftError.componentCouldNotBeInitializedFromData(data: Data)`:
    ///         If a component cannot be initialized from its data object.
    public init(compactSerialization: String) throws {
        self = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: compactSerialization)
    }

    /// Constructs a JWE object from a given compact serialization data object.
    ///
    /// - Parameters:
    ///     - compactSerialization: A compact serialized JWS object as data object as received e.g. from the server.
    /// - Throws:
    ///     - `JOSESwiftError.wrongDataEncoding(data: Data)`:
    ///         If the compact serialization data object is not convertible to string.
    ///     - `JOSESwiftError.invalidCompactSerializationComponentCount(count: Int)`:
    ///         If the component count of the compact serialization is wrong.
    ///     - `JOSESwiftError.componentNotValidBase64URL(component: String)`:
    ///         If the component is not a valid base64URL string.
    ///     - `JOSESwiftError.componentCouldNotBeInitializedFromData(data: Data)`:
    ///         If a component cannot be initialized from its data object.
    public init(compactSerialization: Data) throws {
        guard let compactSerializationString = String(data: compactSerialization, encoding: .utf8) else {
            throw JOSESwiftError.wrongDataEncoding(data: compactSerialization)
        }

        self = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: compactSerializationString)
    }

    /// Initializes a JWE by providing all of it's five parts. Only used during deserialization.
    fileprivate init(header: JWEHeader, encryptedKey: Data, initializationVector: Data, ciphertext: Data, authenticationTag: Data) {
        self.header = header
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
    }

    /// Decrypt the JWE's ciphertext and return the corresponding plaintext.
    /// It is the responsibility of the user to cache this plaintext.
    ///
    /// - Parameter kdk: The private key to decrypt the JWE with.
    /// - Returns: The decrypted payload of the JWE.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    @available(*, deprecated, message: "Use `decrypt(using decrypter:)` instead")
    public func decrypt<KeyType>(with key: KeyType) throws -> Payload {
        let context = Decrypter.DecryptionContext(
            protectedHeader: header,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag
        )

        guard let alg = header.algorithm, let enc = header.encryptionAlgorithm else {
            throw JOSESwiftError.decryptingFailed(description: "Invalid header parameter.")
        }

        guard let decrypter = Decrypter(keyDecryptionAlgorithm: alg, decryptionKey: key, contentDecryptionAlgorithm: enc) else {
            throw JOSESwiftError.decryptingFailed(description: "Wrong key type.")
        }

        do {
            let decryptedData = try decrypter.decrypt(context)
            let compressor = try CompressorFactory.makeCompressor(algorithm: header.compressionAlgorithm)
            return Payload(try compressor.decompress(data: decryptedData))
        } catch JOSESwiftError.decompressionFailed {
            throw JOSESwiftError.decompressionFailed
        } catch JOSESwiftError.compressionAlgorithmNotSupported {
            throw JOSESwiftError.compressionAlgorithmNotSupported
        } catch {
            throw JOSESwiftError.decryptingFailed(description: error.localizedDescription)
        }
    }

    /// Decrypt the JWE's ciphertext and return the corresponding plaintext.
    /// It is the responsibility of the user to cache this plaintext.
    ///
    /// - Parameter decrypter: The decrypter to decrypt the JWE with.
    /// - Returns: The decrypted payload of the JWE.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public func decrypt(using decrypter: Decrypter) throws -> Payload {
        let context = Decrypter.DecryptionContext(
            protectedHeader: header,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag
        )

        guard
            decrypter.keyManagementAlgorithm == header.keyManagementAlgorithm,
            decrypter.contentEncryptionAlgorithm == header.contentEncryptionAlgorithm
        else {
            throw JOSESwiftError.decryptingFailed(description: "JWE header algorithms do not match encrypter algorithms.")
        }

        do {
            let compressor = try CompressorFactory.makeCompressor(algorithm: header.compressionAlgorithm)
            let decryptedData = try decrypter.decrypt(context)
            return Payload(try compressor.decompress(data: decryptedData))
        } catch JOSESwiftError.decompressionFailed {
            throw JOSESwiftError.decompressionFailed
        } catch JOSESwiftError.compressionAlgorithmNotSupported {
            throw JOSESwiftError.compressionAlgorithmNotSupported
        } catch {
            throw JOSESwiftError.decryptingFailed(description: error.localizedDescription)
        }
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
