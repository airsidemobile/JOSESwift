//
//  SecureRandom.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 07.12.17.
//

import Foundation

public enum SecureRandomGenerationError: Error {
    case failed(status: OSStatus)
}

public struct SecureRandom {
    
    /**
     Generates secure random data with a given count.
     - Parameters:
        - count: The count of the random generated data.
     
     - Returns: The random generated data.
     */
    public static func generate(count: Int) throws -> Data {
        var generatedRandom = Data(count: count)
        
        let randomGenerationStatus = generatedRandom.withUnsafeMutableBytes { mutableRandomBytes in
            SecRandomCopyBytes(kSecRandomDefault, generatedRandom.count, mutableRandomBytes)
        }
        
        guard randomGenerationStatus == errSecSuccess else {
            throw SecureRandomGenerationError.failed(status: randomGenerationStatus)
        }
        
        return generatedRandom
    }
}
