//
//  AESCBCEncryption.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//
//  ---------------------------------------------------------------------------
//  Copyright 2020 Airside Mobile Inc.
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

struct AESCBCEncryption {
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let encryptionKey: Data
    private let hmacKey: Data
    private let hmacAlgorithm: HMACAlgorithm

    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, secretKey: Data) throws {
        guard contentEncryptionAlgorithm.checkKeyLength(for: secretKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        let hmacAlgorithm = try AESCBCEncryption.getHMACAlgorithm(for: contentEncryptionAlgorithm)
        let keys = try AESCBCEncryption.retrieveKeys(for: contentEncryptionAlgorithm, from: secretKey)

        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.hmacAlgorithm = hmacAlgorithm
        self.hmacKey = keys.hmacKey
        self.encryptionKey = keys.encryptionKey
    }

    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        let iv = try SecureRandom.generate(count: contentEncryptionAlgorithm.initializationVectorLength)
        let ciphertext = try AES.encrypt(plaintext, with: encryptionKey, using: contentEncryptionAlgorithm, and: iv)

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(iv)
        concatData.append(ciphertext)
        concatData.append(additionalAuthenticatedData.getByteLengthAsOctetHexData())

        let hmac = try HMAC.calculate(from: concatData, with: hmacKey, using: hmacAlgorithm)
        let authenticationTag = try getAuthenticationTag(for: hmac)

        return ContentEncryptionContext(
            ciphertext: ciphertext,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }

    func decrypt(
        _ ciphertext: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        authenticationTag: Data
    ) throws -> Data {
        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(initializationVector)
        concatData.append(ciphertext)
        concatData.append(additionalAuthenticatedData.getByteLengthAsOctetHexData())

        let hmacOutput = try HMAC.calculate(
            from: concatData,
            with: hmacKey,
            using: hmacAlgorithm
        )

        guard
            authenticationTag.timingSafeCompare(with: try getAuthenticationTag(for: hmacOutput))
        else {
            throw JWEError.hmacNotAuthenticated
        }

        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector,
        // return the plaintext if no error occurred.
        let plaintext = try AES.decrypt(
            cipherText: ciphertext,
            with: encryptionKey,
            using: contentEncryptionAlgorithm,
            and: initializationVector
        )

        return plaintext
    }

    static func getHMACAlgorithm(for contentEncryptionAlgorithm: ContentEncryptionAlgorithm) throws -> HMACAlgorithm {
            switch contentEncryptionAlgorithm {
            case .A256CBCHS512:
                return .SHA512
            case .A128CBCHS256:
                return .SHA256
            case .A256GCM, .A128GCM:
                throw JWEError.contentEncryptionAlgorithmMismatch
            }
    }

    static func retrieveKeys(for contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
                             from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
        switch contentEncryptionAlgorithm {
        case .A256CBCHS512:
            return (inputKey.subdata(in: 0..<32), inputKey.subdata(in: 32..<64))
        case .A128CBCHS256:
            return (inputKey.subdata(in: 0..<16), inputKey.subdata(in: 16..<32))
        case .A256GCM, .A128GCM:
            throw JWEError.contentEncryptionAlgorithmMismatch
        }
    }

    func getAuthenticationTag(for hmac: Data) throws -> Data {
        switch contentEncryptionAlgorithm {
        case .A256CBCHS512:
            return hmac.subdata(in: 0..<32)
        case .A128CBCHS256:
            return hmac.subdata(in: 0..<16)
        case .A256GCM, .A128GCM:
            throw JWEError.contentEncryptionAlgorithmMismatch
        }
    }
}

extension AESCBCEncryption: ContentEncrypter {
    func encrypt(header: JWEHeader, payload: Payload) throws -> ContentEncryptionContext {
        let plaintext = payload.data()
        let additionalAuthenticatedData = header.data().base64URLEncodedData()

        return try encrypt(plaintext, additionalAuthenticatedData: additionalAuthenticatedData)
    }
}

extension AESCBCEncryption: ContentDecrypter {
    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data {
        return try decrypt(
            decryptionContext.ciphertext,
            initializationVector: decryptionContext.initializationVector,
            additionalAuthenticatedData: decryptionContext.additionalAuthenticatedData,
            authenticationTag: decryptionContext.authenticationTag
        )
    }
}
