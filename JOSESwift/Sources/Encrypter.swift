//
//  Encrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 13/10/2017.
//  Refactored by Marius Tamulis on 2019-03-12.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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

// Symmetric and Asymmetric key encrypter.
internal protocol KeyEncrypter {
    var algorithm: KeyAlgorithm { get }
    var key: Any? { get }

    /// Encrypts JWE content key (CEK) using one of supported `KeyAlgorithm`s and the corresponding asymmetric or symmetric key.
    ///
    /// - Parameter plaintext: The plain text to encrypt.
    /// - Returns: The cipher text (encrypted plaintext).
    /// - Throws: `JWEError` if any error occured during encryption.
    func encrypt(_ plaintext: Data) throws -> Data
}

// Symmetric content encrypter with HMAC.
internal protocol ContentEncrypter {
    var algorithm: ContentAlgorithm { get }

    // TODO: Perhaps remove.
    var contentKey: Any? { get }

    /// Encrypts a plain text using the corresponding symmetric key and additional authenticated data.
    ///
    /// - Parameters:
    ///   - plaintext: The plain text to encrypt.
    ///   - symmetricKey: The key which contains the HMAC and encryption key.
    ///   - additionalAuthenticatedData: The data used for integrity protection.
    /// - Returns: The a `SymmetricEncryptionContext` containing the ciphertext, the authentication tag and the initialization vector.
    /// - Throws: `JWEError` if any error occured during encryption.
    func encrypt(_ plaintext: Data, with symmetricKey: Data, additionalAuthenticatedData: Data) throws -> SymmetricEncryptionContext
}

public struct EncryptionContext {
    let encryptedKey: Data
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct SymmetricEncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct Encrypter {
    var keyEncrypter: KeyEncrypter
    var contentEncrypter: ContentEncrypter

    /// Constructs an encrypter used to encrypt a JWE.
    ///
    /// - Returns: A fully initialized `Encrypter` or `nil` if provided key is of the wrong type.
    public init?<KeyType>(keyEncryptionAlgorithm alg: AsymmetricKeyAlgorithm, encryptionKey key: KeyType, contentEncyptionAlgorithm enc: SymmetricContentAlgorithm) {
        self.init(alg, key, enc)
    }

    /// Constructs an encrypter used to encrypt a JWE.
    ///
    /// - Returns: A fully initialized `Encrypter` or `nil` if provided key is of the wrong type.
    public init?<KeyType>(keyEncryptionAlgorithm alg: SymmetricKeyAlgorithm, encryptionKey key: KeyType, contentEncyptionAlgorithm enc: SymmetricContentAlgorithm) {
        self.init(alg, key, enc)
    }

    /// Constructs an encrypter used to encrypt a JWE.
    ///
    /// - Returns: A fully initialized `Encrypter` or `nil` if provided key is of the wrong type.
    public init?<KeyType>(keyEncryptionAlgorithm alg: KeyAlgorithm, encryptionKey key: KeyType, contentEncyptionAlgorithm enc: ContentAlgorithm) {
        switch enc {
        case let enc as SymmetricContentAlgorithm:
            switch alg {
            case let asymAlg as AsymmetricKeyAlgorithm:
                self.init(asymAlg, key, enc)
            case let symAlg as SymmetricKeyAlgorithm:
                self.init(symAlg, key, enc)
            default:
                return nil
            }
        default:
            return nil
        }
    }

    /// Constructs an encrypter used to encrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyEncryptionAlgorithm: The algorithm used to encrypt the shared content encryption key.
    ///   - key: The key used to perform the encryption. If the `keyEncryptionAlgorithm` is `.direct`, the
    ///          `encryptionKey` is the shared symmetric content encryption key. Otherwise the `encryptionKey` is the
    ///           public key of the receiver. See [RFC-7516](https://tools.ietf.org/html/rfc7516#section-5.1) for
    ///           details.
    ///   - contentEncyptionAlgorithm: The algorithm used to encrypt the JWE's payload.
    /// - Returns: A fully initialized `Encrypter` or `nil` if provided key is of the wrong type.
    internal init?<KeyAlgType: KeyAlgorithm, KeyType, ContentAlgType: ContentAlgorithm>(_ alg: KeyAlgType, _ key: KeyType, _ enc: ContentAlgType) {
        // TODO: This switch won't scale. We need to refactor it. (#141)
        switch alg {
        case let alg as AsymmetricKeyAlgorithm:
            switch alg {
            case .RSA1_5, .RSAOAEP, .RSAOAEP256:
                guard type(of: key) is RSAEncrypter.KeyType.Type else {
                    return nil
                }

                // swiftlint:disable:next force_cast
                keyEncrypter = RSAEncrypter(algorithm: alg, publicKey: (key as! RSAEncrypter.KeyType))
            case .direct:
                guard type(of: key) is AESContentEncrypter.KeyType.Type else {
                    return nil
                }

                keyEncrypter = RSAEncrypter(algorithm: alg)
            }
        case let alg as SymmetricKeyAlgorithm:
            guard type(of: key) is AESKeyEncrypter.KeyType.Type else {
                return nil
            }

            // swiftlint:disable:next force_cast
            keyEncrypter = AESKeyEncrypter(algorithm: alg, symmetricKey: (key as! AESKeyEncrypter.KeyType))
        default:
            return nil
        }

        switch enc {
        case let enc as SymmetricContentAlgorithm:
            if alg.equals(AsymmetricKeyAlgorithm.direct) {
                // swiftlint:disable:next force_cast
                contentEncrypter = AESContentEncrypter(algorithm: enc, contentKey: (key as! AESContentEncrypter.KeyType))
            } else {
                contentEncrypter = AESContentEncrypter(algorithm: enc)
            }
        default:
            return nil
        }
    }

    /// Constructs an encrypter used to encrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyEncryptionAlgorithm: The algorithm used to encrypt the shared content encryption key.
    ///   - kek: The public key of the receiver used to encrypt the shared content encryption key.
    ///          Currently supported key types are: `SecKey`.
    ///   - contentEncyptionAlgorithm: The algorithm used to encrypt the JWE's payload.
    /// - Returns: A fully initialized `Encrypter` or `nil` if provided key is of the wrong type.
    @available(*, deprecated, message: "Use `init?(keyEncryptionAlgorithm:encryptionKey:contentEncyptionAlgorithm:)` instead")
    public init?<KeyType>(keyEncryptionAlgorithm alg: KeyAlgorithm, keyEncryptionKey kek: KeyType, contentEncyptionAlgorithm enc: ContentAlgorithm) {
        self.init(keyEncryptionAlgorithm: alg, encryptionKey: kek, contentEncyptionAlgorithm: enc)
    }

    internal func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        guard let alg = header.algorithm, !(alg is UnsupportedAlgorithm) else {
            throw JWEError.keyEncryptionAlgorithmMismatch
        }

        guard let enc = header.encryptionAlgorithm, !(enc is UnsupportedAlgorithm) else { // , !(alg is UnsupportedAlgorithm)
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        let cek = try (contentEncrypter.contentKey as? Data) ?? SecureRandom.generate(count: enc.keyLength)

        let encryptedKey = try keyEncrypter.encrypt(cek)
        let symmetricContext = try contentEncrypter.encrypt(
            payload.data(),
            with: cek,
            additionalAuthenticatedData: header.data().base64URLEncodedData()
        )

        return EncryptionContext(
            encryptedKey: encryptedKey,
            ciphertext: symmetricContext.ciphertext,
            authenticationTag: symmetricContext.authenticationTag,
            initializationVector: symmetricContext.initializationVector
        )
    }
}
