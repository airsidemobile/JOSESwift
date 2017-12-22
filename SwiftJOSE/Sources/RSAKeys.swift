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
    
    public let n: String
    public let e: String

    init(n: String, e: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.n = n
        self.e = e

        self.parameters = parameters.merging(
            zip([ keyType.parameterName, "n", "e" ], [ self.keyType.rawValue, self.n, self.e ]),
            uniquingKeysWith: { (_, new) in new }
        )
    }
}

public struct RSAPrivateKey: PrivateKey, KeyPair {
    public let keyType: JWKKeyType
    public let parameters: [String: Any]
    
    public let n: String
    public let e: String
    public let d: String

    init(n: String, e: String, d: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.n = n
        self.e = e
        self.d = d

        self.parameters = parameters.merging(
            zip([ keyType.parameterName, "n", "e", "d" ], [ self.keyType.rawValue, self.n, self.e, self.d ]),
            uniquingKeysWith: { (_, new) in new }
        )
    }
}

public typealias RSAKeyPair = RSAPrivateKey
