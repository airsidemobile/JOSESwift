//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
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

/// An `AsymmetricDecrypter` to decrypt cipher text with a `RSA` algorithm.
public struct RSADecrypter: AsymmetricDecrypter {
    let algorithm: AsymmetricEncryptionAlgorithm
    let privateKey: SecKey

    func decrypt(_ ciphertext: Data) throws -> Data {
        // Check if AsymmetricEncryptionAlgorithm supports a secKeyAlgorithm and if the algorithm is supported to decrypt with a given private key.
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .decrypt, secKeyAlgorithm) else {
            throw EncryptionError.encryptionAlgorithmNotSupported
        }

        // Check if the cipher text length does not exceed the maximum.
        // e.g. for RSAPKCS the cipher text has the same length as the private key's modulus.
        guard algorithm.isCipherTextLenghtSatisfied(ciphertext, for: privateKey) else {
            throw EncryptionError.cipherTextLenghtNotSatisfied
        }

        // Decrypt the cipher text with a given SecKeyAlgorithm and a private key, return cipher text if no error occured.
        var decryptionError: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, secKeyAlgorithm, ciphertext as CFData, &decryptionError) else {
            throw EncryptionError.decryptingFailed(description: decryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }

        return plainText as Data
    }
}
