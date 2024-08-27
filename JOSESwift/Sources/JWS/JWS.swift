//
//  JWS.swift
//  JOSESwift
//
//  Created by Daniel Egger on 18/08/2017.
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

internal enum JWSError: Error {
    case algorithmMismatch
    case cannotComputeSigningInput
}

/// A JWS object consisting of a header, payload and signature. The three components of a JWS object
/// cannot be changed once the object is initialized.
public struct JWS {
    public let header: JWSHeader
    public let payload: Payload
    public let signature: Data

    /// The compact serialization of this JWS object as string.
    public var compactSerializedString: String {
        return JOSESerializer().serialize(compact: self)
    }

    /// The compact serialization of this JWS object as data.
    public var compactSerializedData: Data {
        // Force unwrapping is ok here, since `serialize` returns a string generated from data.
        // swiftlint:disable:next force_unwrapping
        return JOSESerializer().serialize(compact: self).data(using: .utf8)!
    }

    /// Constructs a JWS object from a given header, payload, and signer.
    ///
    /// - Parameters:
    ///   - header: A fully initialized `JWSHeader`.
    ///   - payload: A fully initialized `Payload`.
    ///   - signer: The `Signer` used to compute the JWS signature from the header and payload.
    /// - Throws: `JOSESwiftError` if any error occurs while signing. 
    public init<KeyType>(header: JWSHeader, payload: Payload, signer: Signer<KeyType>) throws {
        self.header = header
        self.payload = payload

        do {
            self.signature = try signer.sign(header: header, payload: payload)
        } catch {
            if let ecError = error as? ECError {
                switch ecError {
                case .localAuthenticationFailed(errorCode: let errorCode):
                    throw JOSESwiftError.localAuthenticationFailed(errorCode: errorCode)
                default:
                    break
                }
            }
            throw JOSESwiftError.signingFailed(description: error.localizedDescription)
        }

    }

    /// Constructs a JWS object from a given compact serialization string.
    ///
    /// - Parameters:
    ///   - compactSerialization: A compact serialized JWS object in string format as received e.g. from the server.
    /// - Throws:
    ///   - `JOSESwiftError.invalidCompactSerializationComponentCount(count: Int)`:
    ///     If the component count of the compact serialization is wrong.
    ///   - `JOSESwiftError.componentNotValidBase64URL(component: String)`:
    ///     If the component is not a valid base64URL string.
    ///   - `JOSESwiftError.componentCouldNotBeInitializedFromData(data: Data)`:
    ///     If a component cannot be initialized from its data object.
    public init(compactSerialization: String) throws {
        self = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: compactSerialization)
    }

    /// Constructs a JWS object from a given compact serialization data.
    ///
    /// - Parameters:
    ///   - compactSerialization: A compact serialized JWS object as data object as received e.g. from the server.
    /// - Throws:
    ///   - `JOSESwiftError.wrongDataEncoding(data: Data)`:
    ///     If the compact serialization data object is not convertible to string.
    ///   - `JOSESwiftError.invalidCompactSerializationComponentCount(count: Int)`:
    ///     If the component count of the compact serialization is wrong.
    ///   - `JOSESwiftError.componentNotValidBase64URL(component: String)`:
    ///     If the component is not a valid base64URL string.
    ///   - `JOSESwiftError.componentCouldNotBeInitializedFromData(data: Data)`:
    ///     If a component cannot be initialized from its data object.
    public init(compactSerialization: Data) throws {
        guard let compactSerializationString = String(data: compactSerialization, encoding: .utf8) else {
            throw JOSESwiftError.wrongDataEncoding(data: compactSerialization)
        }

        self = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: compactSerializationString)
    }

    fileprivate init(header: JWSHeader, payload: Payload, signature: Data) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }

    /// Checks whether the JWS's signature is valid using a given public key.
    ///
    /// - Parameter publicKey: The public key whose corresponding private key signed the JWS.
    /// - Returns: `true` if the JWS's signature is valid for the given key and the JWS's header and payload.
    ///            `false` if the signature is not valid or if the singature could not be verified.
    @available(*, deprecated, message: "Use `isValid(for verifier:)` instead")
    public func isValid<KeyType>(for publicKey: KeyType) -> Bool {
        guard let alg = header.algorithm else {
            return false
        }

        guard let verifier = Verifier(verifyingAlgorithm: alg, publicKey: publicKey) else {
            return false
        }

        do {
            return try verifier.verify(header: header, and: payload, against: signature)
        } catch {
            return false
        }
    }

    /// Checks whether the JWS's signature is valid using a given public key.
    ///
    /// - Parameter publicKey: The public key whose corresponding private key signed the JWS.
    /// - Returns: The JWS on which this function was called if the signature is valid.
    /// - Throws: A `JOSESwiftError` if the signature is invalid or if errors occured during signature validation.
    @available(*, deprecated, message: "Use `validate(using verifier:)` instead")
    public func validate<KeyType>(with publicKey: KeyType) throws -> JWS {
        guard let alg = header.algorithm else {
            throw JOSESwiftError.verifyingFailed(description: "Invalid header parameter.")
        }

        guard let verifier = Verifier(verifyingAlgorithm: alg, publicKey: publicKey) else {
            throw JOSESwiftError.verifyingFailed(description: "Wrong key type.")
        }

        do {
            guard try verifier.verify(header: header, and: payload, against: signature) else {
                throw JOSESwiftError.signatureInvalid
            }
        } catch {
            throw JOSESwiftError.verifyingFailed(description: error.localizedDescription)
        }

        return self
    }

    /// Checks whether the JWS's signature is valid using a given verifier.
    ///
    /// - Parameter verifier: The verifier containing the public key whose corresponding private key signed the JWS.
    /// - Returns: The JWS on which this function was called if the signature is valid.
    /// - Throws: A `JOSESwiftError` if the signature is invalid or if errors occured during signature validation.
    public func validate(using verifier: Verifier) throws -> JWS {
        guard verifier.verifier.algorithm == header.algorithm else {
            throw JOSESwiftError.verifyingFailed(description: "JWS header algorithm does not match verifier algorithm.")
        }

        do {
            guard try verifier.verify(header: header, and: payload, against: signature) else {
                throw JOSESwiftError.signatureInvalid
            }
        } catch {
            throw JOSESwiftError.verifyingFailed(description: error.localizedDescription)
        }

        return self
    }

    /// Checks whether the JWS's signature is valid using a given verifier.
    ///
    /// - Parameter verifier: The verifier containing the public key whose corresponding private key signed the JWS.
    /// - Returns: `true` if the JWS's signature is valid for the given verifier and the JWS's header and payload.
    ///            `false` if the signature is not valid or if the singature could not be verified.
    public func isValid(for verifier: Verifier) -> Bool {
        guard verifier.verifier.algorithm == header.algorithm else {
            return false
        }

        do {
            return try verifier.verify(header: header, and: payload, against: signature)
        } catch {
            return false
        }
    }

}

extension JWS: CompactSerializable {
    public func serialize(to serializer: inout CompactSerializer) {
        serializer.serialize(header)
        serializer.serialize(payload)
        serializer.serialize(signature)
    }
}

extension JWS: CompactDeserializable {
    public static var componentCount: Int {
        return 3
    }

    public init(from deserializer: CompactDeserializer) throws {
        let header = try deserializer.deserialize(JWSHeader.self, at: ComponentCompactSerializedIndex.jwsHeaderIndex)
        let payload = try deserializer.deserialize(Payload.self, at: ComponentCompactSerializedIndex.jwsPayloadIndex)
        let signature = try deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jwsSignatureIndex)
        self.init(header: header, payload: payload, signature: signature)
    }
}
