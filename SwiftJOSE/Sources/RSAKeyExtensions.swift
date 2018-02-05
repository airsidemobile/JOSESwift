//
//  RSAKeyExtensions.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 05.02.18.
//

import Foundation

extension RSAPublicKey: Encodable {
    public func encode(to encoder: Encoder) throws {
        var commonParameters = encoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        try commonParameters.encode(keyType, forKey: .keyType)

        // Other common paramters are optional.
        for parameter in parameters {
            // Only encode known parameters.
            if let key = JWKParameter(rawValue: parameter.key) {
                try commonParameters.encode(parameter.value, forKey: key)
            }
        }

        // RSA public key specific parameters.
        var rsaParameters = encoder.container(keyedBy: RSAKeyParameter.self)
        try rsaParameters.encode(modulus, forKey: .modulus)
        try rsaParameters.encode(exponent, forKey: .exponent)
    }
}

extension RSAPublicKey: Decodable {
    public init(from decoder: Decoder) throws {
        let commonParameters = try decoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        self.keyType = try commonParameters.decode(JWKKeyType.self, forKey: .keyType)

        // Other common parameters are optional.
        var parameters: [String: String] = [:]
        for key in commonParameters.allKeys {
            parameters[key.rawValue] = try commonParameters.decode(String.self, forKey: key)
        }
        self.parameters = parameters

        // RSA public key specific parameters.
        let rsaParameters = try decoder.container(keyedBy: RSAKeyParameter.self)
        self.modulus = try rsaParameters.decode(String.self, forKey: .modulus)
        self.exponent = try rsaParameters.decode(String.self, forKey: .exponent)
    }
}

extension RSAPrivateKey: Encodable {
    public func encode(to encoder: Encoder) throws {
        var commonParameters = encoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        try commonParameters.encode(keyType, forKey: .keyType)

        // Other common paramters are optional.
        for parameter in parameters {
            // Only encode known parameters.
            if let key = JWKParameter(rawValue: parameter.key) {
                try commonParameters.encode(parameter.value, forKey: key)
            }
        }

        // RSA private key specific parameters.
        var rsaParameters = encoder.container(keyedBy: RSAKeyParameter.self)
        try rsaParameters.encode(modulus, forKey: .modulus)
        try rsaParameters.encode(exponent, forKey: .exponent)
        try rsaParameters.encode(privateExponent, forKey: .privateExponent)
    }
}

extension RSAPrivateKey: Decodable {
    public init(from decoder: Decoder) throws {
        let commonParameters = try decoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        self.keyType = try commonParameters.decode(JWKKeyType.self, forKey: .keyType)

        // Other common parameters are optional.
        var parameters: [String: String] = [:]
        for key in commonParameters.allKeys {
            parameters[key.rawValue] = try commonParameters.decode(String.self, forKey: key)
        }
        self.parameters = parameters

        // RSA private key specific parameters.
        let rsaParameters = try decoder.container(keyedBy: RSAKeyParameter.self)
        self.modulus = try rsaParameters.decode(String.self, forKey: .modulus)
        self.exponent = try rsaParameters.decode(String.self, forKey: .exponent)
        self.privateExponent = try rsaParameters.decode(String.self, forKey: .privateExponent)
    }
}
