//
//  Verifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//

import Foundation

public protocol Verifier {
    init(key: SecKey)
    func verify(_ signature: Data, against signingInput: Data, using algorithm: SigningAlgorithm) throws -> Bool
}
