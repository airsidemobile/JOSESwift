//
//  AESEncrypter.swift
//  SwiftJOSE
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

/// An `AsymmetricEncrypter` to encrypt plain text with a `RSA` algorithm.
public struct RSAEncrypter: AsymmetricEncrypter {
    let algorithm: AsymmetricEncryptionAlgorithm
    let publicKey: SecKey

    func encrypt(_ plaintext: Data) throws -> Data {
        // Check if AsymmetricEncryptionAlgorithm supports a secKeyAlgorithm and if the algorithm is supported to encrypt with a given public key.
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .encrypt, secKeyAlgorithm) else {
            throw EncryptionError.encryptionAlgorithmNotSupported
        }

        // Check if the plain text length does not exceed the maximum.
        // e.g. for RSAPKCS the plaintext must be 11 bytes smaller than the public key's modulus.
        guard algorithm.isPlainTextLengthSatisfied(plaintext, for: publicKey) else {
            throw EncryptionError.plainTextLengthNotSatisfied
        }

        // Encrypt the plain text with a given SecKeyAlgorithm and a public key, return cipher text if no error occured.
        var encryptionError: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, secKeyAlgorithm, plaintext as CFData, &encryptionError) else {
            throw EncryptionError.encryptingFailed(description: encryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }

        return cipherText as Data
    }
}
