//
//  Decrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 17/10/2017.
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

// Symmetric and Asymmetric key decrypter.
internal protocol KeyDecrypter {
    var algorithm: KeyAlgorithm { get }
    var key: Any? { get }

    /// Decrypts JWE content key (CEK) using one of supported `KeyAlgorithm`s and the corresponding asymmetric or symmetric key.
    ///
    /// - Parameter ciphertext: The encrypted cipher text to decrypt.
    /// - Returns: The plain text (decrypted cipher text).
    /// - Throws: `EncryptionError` if any error occured during decryption.
    func decrypt(_ ciphertext: Data) throws -> Data
}

// Symmetric content decrypter with HMAC.
internal protocol ContentDecrypter {
    var algorithm: ContentAlgorithm { get }
    var contentKey: Any? { get }

    /// Decrypts a cipher text contained in the `ContentDecryptionContext` using a given symmetric key.
    ///
    /// - Parameters:
    ///   - context: The `ContentDecryptionContext` containing the ciphertext, the initialization vector, additional authenticated data and the authentication tag.
    ///   - contentKey: The key which contains the HMAC and encryption key.
    /// - Returns: The plain text (decrypted cipher text).
    /// - Throws: `EncryptionError` if any error occurs during decryption.
    func decrypt(_ context: ContentDecryptionContext, with contentKey: Any?) throws -> Data
}

// Generic decryption context.
public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

// Content decryption context (symmetric).
public struct ContentDecryptionContext {
    let ciphertext: Data
    let initializationVector: Data
    let additionalAuthenticatedData: Data
    let authenticationTag: Data
}

public struct Decrypter {
    var keyDecrypter: KeyDecrypter
    var contentDecrypter: ContentDecrypter

    /// Constructs a decrypter used to decrypt a JWE.
    ///
    /// - Returns: A fully initialized `Decrypter` or `nil` if provided key is of the wrong type.
    public init?(keyDecryptionAlgorithm alg: AsymmetricKeyAlgorithm, decryptionKey key: Any, contentDecryptionAlgorithm enc: SymmetricContentAlgorithm) {
        self.init(alg, key, enc)
    }

    /// Constructs a decrypter used to decrypt a JWE.
    ///
    /// - Returns: A fully initialized `Decrypter` or `nil` if provided key is of the wrong type.
    public init?(keyDecryptionAlgorithm alg: SymmetricKeyAlgorithm, decryptionKey key: Any, contentDecryptionAlgorithm enc: SymmetricContentAlgorithm) {
        self.init(alg, key, enc)
    }

    /// Constructs a decrypter used to decrypt a JWE.
    ///
    /// - Returns: A fully initialized `Decrypter` or `nil` if provided key is of the wrong type.
    public init?(keyDecryptionAlgorithm alg: KeyAlgorithm, decryptionKey key: Any, contentDecryptionAlgorithm enc: ContentAlgorithm) {
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
    internal init?(_ alg: KeyAlgorithm, _ key: Any, _ enc: ContentAlgorithm) {
        // TODO: This switch won't scale. We need to refactor it. (#141)
        switch alg {
        case let alg as AsymmetricKeyAlgorithm:
            switch alg {
            case .RSA1_5, .RSAOAEP, .RSAOAEP256:
                guard type(of: key) is RSADecrypter.KeyType.Type else {
                    return nil
                }

                // swiftlint:disable:next force_cast
                self.keyDecrypter = RSADecrypter(algorithm: alg, privateKey: (key as! RSADecrypter.KeyType))
            case .direct:
                guard type(of: key) is AESKeyDecrypter.KeyType.Type else {
                    return nil
                }

                self.keyDecrypter = RSADecrypter(algorithm: alg)
            }
        case let alg as SymmetricKeyAlgorithm:
            guard let key = key as? AESKeyDecrypter.KeyType else {
                return nil
            }

            self.keyDecrypter = AESKeyDecrypter(algorithm: alg, symmetricKey: key)
        default:
            return nil
        }

        switch enc {
        case let enc as SymmetricContentAlgorithm:
            if alg.equals(AsymmetricKeyAlgorithm.direct) {
                self.contentDecrypter = AESContentDecrypter(algorithm: enc, contentKey: (key as! AESContentDecrypter.KeyType))
            } else {
                self.contentDecrypter = AESContentDecrypter(algorithm: enc)
            }
        default:
            return nil
        }
    }

    internal func decrypt(_ context: DecryptionContext) throws -> Data {
        guard let alg = context.header.algorithm, alg.equals(keyDecrypter.algorithm), !(alg is UnsupportedAlgorithm)  else {
            throw JWEError.keyEncryptionAlgorithmMismatch
        }

        guard let enc = context.header.encryptionAlgorithm, enc.equals(contentDecrypter.algorithm), !(enc is UnsupportedAlgorithm)  else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        var cek: Any

        if (alg.equals(AsymmetricKeyAlgorithm.direct)) {
            guard context.encryptedKey == Data() else {
                throw JOSESwiftError.decryptingFailed(
                    description: "Direct encryption does not expect an encrypted key."
                )
            }
            guard let contentKey = contentDecrypter.contentKey else {
                throw JOSESwiftError.decryptingFailed(
                    description: "Did not supply a shared symmetric key for decryption."
                )
            }

            cek = contentKey
        } else {
            // Generate a random CEK to substitue in case we fail to decrypt the CEK.
            // This is to prevent the MMA (Million Message Attack) against RSA.
            // For detailed information, please refer to RFC-3218 (https://tools.ietf.org/html/rfc3218#section-2.3.2),
            // RFC-5246 (https://tools.ietf.org/html/rfc5246#appendix-F.1.1.2),
            // and http://www.ietf.org/mail-archive/web/jose/current/msg01832.html.
            let randomCEK = try SecureRandom.generate(count: enc.keyLength)

            if let decryptedCEK = try? keyDecrypter.decrypt(context.encryptedKey) {
                cek = decryptedCEK
            } else {
                cek = randomCEK
            }
        }

        let contentContext = ContentDecryptionContext(
            ciphertext: context.ciphertext,
            initializationVector: context.initializationVector,
            additionalAuthenticatedData: context.header.data().base64URLEncodedData(),
            authenticationTag: context.authenticationTag
        )

        return try contentDecrypter.decrypt(contentContext, with: cek)
    }
}
