//
//  Signer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol Signer {
    init(algorithm: SigningAlgorithm, key: String)
    func sign(_ signatureInput: Data) -> Data
}

public protocol Verifier {
    init(algorithm: SigningAlgorithm, key: String)
    func verify(_ signature: Data, against signatureInput: Data) -> Bool
}

public struct SigningAlgorithm {
    // Add supported signing Algorithms in the respective `Signer` implementation.
    let secKeyAlgorithm: SecKeyAlgorithm
    let identifier: String
}
