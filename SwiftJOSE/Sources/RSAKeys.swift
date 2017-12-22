//
//  RSAKeys.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

public struct RSAPublicKey: PublicKey {
    public let keyType: JWKKeyType
    public let parameters: [String: Any]
    
    public let modulus: String
    public let exponent: String

    init(modulus: String, exponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent

        self.parameters = parameters.merging(
            zip([ keyType.parameterName, "n", "e" ], [ self.keyType.rawValue, self.modulus, self.exponent ]),
            uniquingKeysWith: { (_, new) in new }
        )
    }
}

public struct RSAPrivateKey: PrivateKey, KeyPair {
    public let keyType: JWKKeyType
    public let parameters: [String: Any]
    
    public let modulus: String
    public let exponent: String
    public let privateExponent: String

    init(modulus: String, exponent: String, privateExponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent

        self.parameters = parameters.merging(
            zip([ keyType.parameterName, "n", "e", "d" ], [ self.keyType.rawValue, self.modulus, self.exponent, self.privateExponent ]),
            uniquingKeysWith: { (_, new) in new }
        )
    }
}

public typealias RSAKeyPair = RSAPrivateKey
