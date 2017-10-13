//
//  JWEHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 12/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

/// The header of a `JWE` object.
public struct JWEHeader: JOSEHeader {
    let parameters: [String: Any]
    
    init(parameters: [String: Any]) {
        // TODO: Assert that required JWE parameters are present.
        self.parameters = parameters
    }
    
    /// Initializes a `JWEHeader` with the specified algorithm and signing algorithm.
    public init(algorithm: Algorithm, encryptionAlgorithm: Algorithm) {
        self.init(parameters: [
            "alg": algorithm.rawValue,
            "enc": encryptionAlgorithm.rawValue
        ])
    }
}

// Header parameters that both a JWS Header and a JWE Header must support.
extension JWEHeader: CommonHeaderParameterSpace {
    /// The algorithm used to encrypt or determine the value of the Content Encryption Key.
    public var algorithm: Algorithm {
        return Algorithm(rawValue: parameters["alg"] as! String)!
    }
}

// Header parameters that are specific to a JWE Header.
public extension JWEHeader {
    /// The encryption algorithm used to perform authenicated encryption of the plaintext
    /// to produce the ciphertext and the Authentication Tag.
    public var encryptionAlgorithm: Algorithm {
        return Algorithm(rawValue: parameters["enc"] as! String)!
    }
}

extension JWEHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWEHeader.self, at: 0)
    }
}
