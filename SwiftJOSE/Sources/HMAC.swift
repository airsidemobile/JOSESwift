//
//  HMAC.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 05.12.17.
//

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

public enum HMACAlgorithm: String {
    case SHA512 = "SHA512"
    
    var ccAlgorithm: CCAlgorithm {
        switch self {
        case .SHA512:
            return CCAlgorithm(kCCHmacAlgSHA512)
        }
    }
    
    var keyLength: size_t {
        switch self {
        case .SHA512:
            return size_t()
        }
    }
    
}

public struct HMAC {
    
    /**
     Calculates a HMAC of an input with a specific HMAC algorithm and the corresponding HMAC key.
     - Parameters:
        - input: The input to calculate a HMAC for.
        - key: The key used in the HMAC algorithm.
        - algorithm: The algorithm used to calculate the HMAC.
     
     - Returns: The calculated HMAC.
     */
    public static func calculate(from input: Data, with key: Data, using algorithm: HMACAlgorithm) -> Data {
        let keyLength = size_t(kCCKeySizeAES256)
        var hmacOutData = Data(count: 64)
        
        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            key.withUnsafeBytes { keyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(algorithm.ccAlgorithm, keyBytes, keyLength, inputBytes, input.count, hmacOutBytes)
                }
            }
        }
        
        return hmacOutData
    }
}
