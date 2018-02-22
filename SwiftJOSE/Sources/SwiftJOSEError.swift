//
//  SwiftJOSEError.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 21.02.18.
//

import Foundation

public enum SwiftJOSEError: Error {
    case signingFailed(description: String)
    case verifyingFailed(description: String)

    case encryptingFailed(description: String)
    case decryptingFailed(description: String)

    case wrongDataEncoding(data: Data)
    case invalidCompactSerializationComponentCount(count: Int)
    case componentNotValidBase64URL(component: String)
    case componentCouldNotBeInitializedFromData(data: Data)

    case couldNotConstructJWK
    case modulusNotBase64URLUIntEncoded
    case exponentNotBase64URLUIntEncoded
    case privateExponentNotBase64URLUIntEncoded
}
