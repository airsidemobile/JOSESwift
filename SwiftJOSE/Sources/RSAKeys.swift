//
//  RSAKeys.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

public struct RSAPublicKey: JWK {
    public let keyType: KeyType
    public let parameters: [String : Any]
    
    public let n: String
    public let e: String
    
    public subscript(parameter: String) -> Any? {
        return parameters[parameter]
    }

    init(n: String, e: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.n = n
        self.e = e

        self.parameters = parameters.merging(
            zip([ keyType.parameterName, "n", "e" ], [ keyType.rawValue, n, e ]),
            uniquingKeysWith: { (_, new) in new }
        )
    }

    init(n: String, e: String) {
        self.init(n: n, e: e, additionalParameters: [:])
    }
}

public struct RSAPrivateKey: JWK {
    public let keyType: KeyType
    public let parameters: [String : Any]
    
    public let n: String
    public let e: String
    public let d: String


    public subscript(parameter: String) -> Any? {
        return parameters[parameter]
    }

    init(n: String, e: String, d: String, additionalParameters parameters: [String: Any]) {
        self.keyType = .RSA
        self.n = n
        self.e = e
        self.d = d

        self.parameters = parameters.merging(
            zip([ keyType.parameterName, "n", "e", "d" ], [ keyType.rawValue, n, e, d ]),
            uniquingKeysWith: { (_, new) in new }
        )
    }

    init(n: String, e: String, d: String) {
        self.init(n: n, e: e, d: d, additionalParameters: [:])
    }
}

public typealias RSAKeyPair = RSAPrivateKey
