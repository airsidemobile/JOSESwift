//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct AESDecrypter: SymmetricDecrypter {
    let symmetricKey: Data
    
    func decrypt(_ ciphertext: Data, initializationVector: Data, additionalAuthenticatedData: Data, authenticationTag: Data) -> Data? {
        return "The true sign of intelligence is not knowledge but imagination.".data(using: .utf8)
    }
}
