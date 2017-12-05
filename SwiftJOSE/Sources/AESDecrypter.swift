//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation

public struct AESDecrypter: SymmetricDecrypter {
    let algorithm: SymmetricEncryptionAlgorithm
    
    func decrypt(_ context: SymmetricDecryptionContext, with symmetricKey: Data) throws -> Data {
        // Todo: Throw error if necessary.
        return "The true sign of intelligence is not knowledge but imagination.".data(using: .utf8)!
    }
}
