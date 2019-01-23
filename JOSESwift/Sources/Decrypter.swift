//
//  Decrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 17/10/2017.
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

internal protocol AsymmetricDecrypter {
    var algorithm: AsymmetricKeyAlgorithm { get }

    /// Decrypts a cipher text using a given `AsymmetricKeyAlgorithm` and the corresponding private key.
    ///
    /// - Parameter ciphertext: The encrypted cipher text to decrypt.
    /// - Returns: The plain text (decrypted cipher text).
    /// - Throws: `EncryptionError` if any error occured during decryption.
    func decrypt(_ ciphertext: Data) throws -> Data
}

internal protocol SymmetricDecrypter {
    var algorithm: SymmetricKeyAlgorithm { get }
    var symmetricKey: Data? { get }

    /// Decrypts a cipher text contained in the `SymmetricDecryptionContext` using a given symmetric key.
    ///
    /// - Parameters:
    ///   - context: The `SymmetricDecryptionContext` containing the ciphertext, the initialization vector, additional authenticated data and the authentication tag.
    ///   - symmetricKey: The key which contains the HMAC and encryption key.
    /// - Returns: The plain text (decrypted cipher text).
    /// - Throws: `EncryptionError` if any error occurs during decryption.
    func decrypt(_ context: SymmetricDecryptionContext, with symmetricKey: Data) throws -> Data
}

public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

public struct SymmetricDecryptionContext {
    let ciphertext: Data
    let initializationVector: Data
    let additionalAuthenticatedData: Data
    let authenticationTag: Data
}

public struct Decrypter {
    let asymmetric: AsymmetricDecrypter
    let symmetric: SymmetricDecrypter

    /// Constructs a decrypter used to decrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyDecryptionAlgorithm: The algorithm used to decrypt the shared content encryption key.
    ///   - key: The key used to perform the decryption. If the `keyDecryptionAlgorithm` is `.direct`, the
    ///          `decryptionKey` is the shared symmetric content encryption key. Otherwise the `decryptionKey` is the
    ///           private key of the receiver. See [RFC-7516](https://tools.ietf.org/html/rfc7516#section-5.2) for
    ///           details.
    ///   - contentDecryptionAlgorithm: The algorithm used to decrypt the JWE's payload.
    /// - Returns: A fully initialized `Decrypter` or `nil` if provided key is of the wrong type.
    public init?<KeyType>(keyDecryptionAlgorithm: AsymmetricKeyAlgorithm, decryptionKey key: KeyType, contentDecryptionAlgorithm: SymmetricKeyAlgorithm) {
        switch (keyDecryptionAlgorithm, contentDecryptionAlgorithm) {
        case (.RSA1_5, .A256CBCHS512), (.RSAOAEP256, .A256CBCHS512):
            guard type(of: key) is RSADecrypter.KeyType.Type else {
                return nil
            }
            // swiftlint:disable:next force_cast
            self.asymmetric = RSADecrypter(algorithm: keyDecryptionAlgorithm, privateKey: (key as! RSADecrypter.KeyType))
            self.symmetric = AESDecrypter(algorithm: contentDecryptionAlgorithm)
        case (.direct, .A256CBCHS512):
            guard type(of: key) is AESDecrypter.KeyType.Type else {
                return nil
            }

            self.asymmetric = RSADecrypter(algorithm: keyDecryptionAlgorithm)
            // swiftlint:disable:next force_cast
            self.symmetric = AESDecrypter(algorithm: contentDecryptionAlgorithm, symmetricKey: (key as! AESDecrypter.KeyType))
        }
    }

    /// Constructs a decrypter used to decrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyDecryptionAlgorithm: The algorithm used to decrypt the shared content encryption key.
    ///   - kdk: The private key used to decrypt the shared content encryption key.
    ///          Currently supported key types are: `SecKey`.
    ///   - contentDecryptionAlgorithm: The algorithm used to decrypt the JWE's payload.
    /// - Returns: A fully initialized `Decrypter` or `nil` if provided key is of the wrong type.
    @available(*, deprecated, message: "Use `init?(keyDecryptionAlgorithm:decryptionKey:contentDecyptionAlgorithm:)` instead")
    public init?<KeyType>(keyDecryptionAlgorithm: AsymmetricKeyAlgorithm, keyDecryptionKey kdk: KeyType, contentDecryptionAlgorithm: SymmetricKeyAlgorithm) {
        self.init(keyDecryptionAlgorithm: keyDecryptionAlgorithm, decryptionKey: kdk, contentDecryptionAlgorithm: contentDecryptionAlgorithm)
    }

    internal func decrypt(_ context: DecryptionContext) throws -> Data {
        guard let alg = context.header.algorithm, alg == asymmetric.algorithm else {
            throw JWEError.keyEncryptionAlgorithmMismatch
        }

        guard let enc = context.header.encryptionAlgorithm, enc == symmetric.algorithm else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        var cek: Data

        if (alg == .direct) {
            guard context.encryptedKey == Data() else {
                throw JOSESwiftError.decryptingFailed(
                    description: "Direct encryption does not expect an encrypted key."
                )
            }
            guard let symmetricKey = symmetric.symmetricKey else {
                throw JOSESwiftError.decryptingFailed(
                    description: "Did not supply a shared symmetric key for decryption."
                )
            }

            cek = symmetricKey
        } else {
            // Generate random CEK to prevent MMA (Million Message Attack).
            // For detailed information, please refer to this RFC(https://tools.ietf.org/html/rfc3218#section-2.3.2)
            // and http://www.ietf.org/mail-archive/web/jose/current/msg01832.html
            let randomCEK = try SecureRandom.generate(count: enc.keyLength)

            if let decryptedCEK = try? asymmetric.decrypt(context.encryptedKey) {
                cek = decryptedCEK
            } else {
                cek = randomCEK
            }
        }

        let symmetricContext = SymmetricDecryptionContext(
            ciphertext: context.ciphertext,
            initializationVector: context.initializationVector,
            additionalAuthenticatedData: context.header.data().base64URLEncodedData(),
            authenticationTag: context.authenticationTag
        )

        return try symmetric.decrypt(symmetricContext, with: cek)
    }
}
