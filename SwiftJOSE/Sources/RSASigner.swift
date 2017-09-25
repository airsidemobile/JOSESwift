//
//  RSASigner.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

extension SigningAlgorithm {
    public static var rs512: SigningAlgorithm {
        return SigningAlgorithm(secKeyAlgorithm: .rsaSignatureMessagePKCS1v15SHA512, identifier: "RS512")
    }
}

public struct RSASigner: Signer {
    let algorithm: SigningAlgorithm
    let key: String
    
    public init(algorithm: SigningAlgorithm, key: String) {
        self.algorithm = algorithm
        self.key = key
    }
    
    public func sign(_ signatureInput: Data) -> Data {
        let string = String.init(data: signatureInput, encoding: .utf8)!
        return "Signature(\(string))".data(using: .utf8)!
    }
}
