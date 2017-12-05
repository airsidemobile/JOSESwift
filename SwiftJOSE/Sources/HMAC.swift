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
    
    /**
     Checks if the reference authentication tag matches with, from the input calculated, authentication tag.
     - Parameters:
        - input: The input to authenticate a HMAC for.
        - referenceAuthenticationTag: The reference authentication tag received with the message.
        - key: The key used in the HMAC algorithm.
        - algorithm: The algorithm used to calculate the HMAC.
     
     - Returns: True if the message is authenticated (the authentication tags match), false if the message is not authenticated (the authentication tags do not match)
     */
    public static func authenticate(input: Data, for referenceAuthenticationTag: Data, and key: Data, using algorithm: HMACAlgorithm) -> Bool {
        let keyLength = size_t(kCCKeySizeAES256)
        var hmacOutData = Data(count: 64)
        
        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            key.withUnsafeBytes { keyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(algorithm.ccAlgorithm, keyBytes, keyLength, inputBytes, input.count, hmacOutBytes)
                }
            }
        }
        
        return referenceAuthenticationTag == hmacOutData.subdata(in: 0..<32) ? true : false
    }
}
