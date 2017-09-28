//
//  Verifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol Verifier {
    init(key: String)
    func verify(_ signature: Signature, against signingInput: Data, using algorithm: SigningAlgorithm) -> Bool
}
