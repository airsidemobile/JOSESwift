//
//  HMACSigner.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 14.04.21.
//

import Foundation

/// A `Signer` to sign an input with an `HMAC` algorithm.
internal struct HMACSigner: SignerProtocol {
    typealias KeyType = HMAC.KeyType

    let algorithm: SignatureAlgorithm
    let key: KeyType

    func sign(_ signingInput: Data) throws -> Data {
        guard let hmacAlgorithm = algorithm.hmacAlgorithm else {
            throw HMACError.algorithmNotSupported
        }
        return try HMAC.calculate(from: signingInput, with: key, using: hmacAlgorithm)
    }
}
