//
//  HMACVerifier.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 14.04.21.
//

import Foundation

/// A `Verifier` to verify a signature created with an `HMAC` algorithm.
internal struct HMACVerifier: VerifierProtocol {
    typealias KeyType = HMAC.KeyType

    let algorithm: SignatureAlgorithm
    let key: KeyType

    func verify(_ signingInput: Data, against signature: Data) throws -> Bool {
        guard let hmacAlgorithm = algorithm.hmacAlgorithm else {
            throw HMACError.algorithmNotSupported
        }
        let hmacOutput = try HMAC.calculate(from: signingInput, with: key, using: hmacAlgorithm)
        return hmacOutput.timingSafeCompare(with: signature)
    }
}
