//
//  JOSESwiftError.swift
//  JOSESwift
//
//  Created by Carol Capek on 21.02.18.
//  Modified by Jarrod Moldrich on 02.07.18.
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

public enum JOSESwiftError: Error {
    case signingFailed(description: String)
    case verifyingFailed(description: String)
    case signatureInvalid

    case encryptingFailed(description: String)
    case decryptingFailed(description: String)

    case wrongDataEncoding(data: Data)
    case invalidCompactSerializationComponentCount(count: Int)
    case componentNotValidBase64URL(component: String)
    case componentCouldNotBeInitializedFromData(data: Data)

    case couldNotConstructJWK

    // RSA coding errors
    case modulusNotBase64URLUIntEncoded
    case exponentNotBase64URLUIntEncoded
    case privateExponentNotBase64URLUIntEncoded
    case symmetricKeyNotBase64URLEncoded

    // EC coding errors
    case xNotBase64URLUIntEncoded
    case yNotBase64URLUIntEncoded
    case privateKeyNotBase64URLUIntEncoded
    case invalidCurveType
    case compressedCurvePointsUnsupported
    case invalidCurvePointOctetLength
    case localAuthenticationFailed(errorCode: Int)

    // Compression erros
    case compressionFailed
    case decompressionFailed
    case compressionAlgorithmNotSupported
    case rawDataMustBeGreaterThanZero
    case compressedDataMustBeGreaterThanZero

    // Thumprint computation
    case thumbprintSerialization
}
