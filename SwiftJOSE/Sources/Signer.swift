//
//  Signer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public enum SigningAlgorithm: String {
    case rs512 = "RS512"
}

public protocol Signer {
    init(key: String)
    func sign(_ signingInput: Data, using algorithm: SigningAlgorithm) -> Data?
}
