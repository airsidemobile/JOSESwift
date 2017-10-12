//
//  JWEHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 12/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWEHeader: JOSEHeader {
    public let parameters: [String: Any]
    
    public init(parameters: [String: Any]) {
        // TODO: Assert that required JWE parameters are present.
        self.parameters = parameters
    }
    
    /// Initializes a `JWEHeader` with the specified algorithm and signing algorithm.
    public init(algorithm: SigningAlgorithm, encryptionAlgorithm: SigningAlgorithm) {
        self.init(parameters: [
            "alg": algorithm.rawValue,
            "enc": encryptionAlgorithm.rawValue
        ])
    }
}

// JWE specific header parameters.
public extension JWEHeader {
    /// The algorithm used to encrypt the Content Encryption Key.
    public var encryptionAlgorithm: SigningAlgorithm {
        return SigningAlgorithm(rawValue: parameters["enc"] as! String)!
    }
}

extension JWEHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWEHeader.self, at: 0)
    }
}
