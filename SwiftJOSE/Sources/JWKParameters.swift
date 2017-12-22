//
//  JWKParameters.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21.12.17.
//

import Foundation

/// The key type parameter of a JWK identifies the cryptographic algorithm
/// family used with the key(s) represented by a JWK.
/// See [RFC-7518](https://tools.ietf.org/html/rfc7518#section-7.4) for details.
///
/// - RSA
/// - EC
/// - OCT
public enum JWKKeyType: String {
    case RSA = "RSA"
    case ellipticCurve = "EC"
    case octetSequence = "oct"

    var parameterName: String {
        return "kty"
    }
}

// Todo: Add more JWK parameters here. See https://tools.ietf.org/html/rfc7517#section-4.
