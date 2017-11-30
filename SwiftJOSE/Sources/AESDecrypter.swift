//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation

public struct AESDecrypter: SymmetricDecrypter {
    func decrypt(_ context: SymmetricDecryptionContext, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> Data {
        // Todo: Throw error if necessary.
        return "The true sign of intelligence is not knowledge but imagination.".data(using: .utf8)!
    }
}
