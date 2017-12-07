//
//  Random.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 07.12.17.
//

import Foundation

public enum RandomGenerationError: Error {
    case failed(status: OSStatus)
}

public struct Random {
    public static func generate(count: Int) throws -> Data {
        var generatedRandom = Data(count: count)
        
        let randomGenerationStatus = generatedRandom.withUnsafeMutableBytes { mutableRandomBytes in
            SecRandomCopyBytes(kSecRandomDefault, generatedRandom.count, mutableRandomBytes)
        }
        
        guard randomGenerationStatus == errSecSuccess else {
            throw RandomGenerationError.failed(status: randomGenerationStatus)
        }
        
        return generatedRandom
    }
}
