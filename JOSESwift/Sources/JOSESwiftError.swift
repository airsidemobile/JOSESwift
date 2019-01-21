//
//  JOSESwiftError.swift
//  JOSESwift
//
//  Created by Carol Capek on 21.02.18.
//  Modified by Jarrod Moldrich on 02.07.18.
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
}
