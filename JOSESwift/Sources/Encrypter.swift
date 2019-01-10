//
//  Encrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 13/10/2017.
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

internal protocol AsymmetricEncrypter {
    /// The algorithm used to encrypt plaintext.
    var algorithm: AsymmetricKeyAlgorithm { get }

    /// Encrypts a plain text using a given `AsymmetricKeyAlgorithm` and the corresponding public key.
    ///
    /// - Parameter plaintext: The plain text to encrypt.
    /// - Returns: The cipher text (encrypted plain text).
    /// - Throws: `JWEError` if any error occured during encryption.
    func encrypt(_ plaintext: Data) throws -> Data
}

internal protocol SymmetricEncrypter {
    /// The algorithm used to encrypt plaintext.
    var algorithm: SymmetricKeyAlgorithm { get }
    var symmetricKey: Data? { get }

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

public struct Encrypter<KeyType> {
    let asymmetric: AsymmetricEncrypter
    let symmetric: SymmetricEncrypter

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
    public init?(keyEncryptionAlgorithm: AsymmetricKeyAlgorithm, encryptionKey key: KeyType, contentEncyptionAlgorithm: SymmetricKeyAlgorithm) {
        switch (keyEncryptionAlgorithm, contentEncyptionAlgorithm) {
        case (.RSA1_5, .A256CBCHS512), (.RSAOAEP256, .A256CBCHS512):
            guard type(of: key) is RSAEncrypter.KeyType.Type else {
                return nil
            }
            // swiftlint:disable:next force_cast
            self.asymmetric = RSAEncrypter(algorithm: keyEncryptionAlgorithm, publicKey: (key as! RSAEncrypter.KeyType))
            self.symmetric = AESEncrypter(algorithm: contentEncyptionAlgorithm)
        case (.direct, .A256CBCHS512):
            guard type(of: key) is AESEncrypter.KeyType.Type else {
                return nil
            }

            self.asymmetric = RSAEncrypter(algorithm: keyEncryptionAlgorithm)
            // swiftlint:disable:next force_cast
            self.symmetric = AESEncrypter(algorithm: contentEncyptionAlgorithm, symmetricKey: (key as! AESEncrypter.KeyType))
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
    public init?(keyEncryptionAlgorithm: AsymmetricKeyAlgorithm, keyEncryptionKey kek: KeyType, contentEncyptionAlgorithm: SymmetricKeyAlgorithm) {
        self.init(keyEncryptionAlgorithm: keyEncryptionAlgorithm, encryptionKey: kek, contentEncyptionAlgorithm: contentEncyptionAlgorithm)
    }

    internal func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        guard let alg = header.algorithm, alg == asymmetric.algorithm else {
            throw JWEError.keyEncryptionAlgorithmMismatch
        }
        guard let enc = header.encryptionAlgorithm, enc == symmetric.algorithm else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        let cek = try symmetric.symmetricKey ?? SecureRandom.generate(count: enc.keyLength)

        let encryptedKey = try asymmetric.encrypt(cek)
        let symmetricContext = try symmetric.encrypt(
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
