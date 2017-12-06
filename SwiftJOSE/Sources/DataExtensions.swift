//
//  Data+Base64URL.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 22/09/2017.
//

import Foundation

extension Data {
    /**
     Creates a new data buffer from a base64url encoded string.
     
     - Parameters:
         - base64URLString: The base64url encoded string to parse.
     
     - Returns: `nil` if the input is not recognized as valid base64url.
     */
    init?(base64URLEncoded base64URLString: String) {
        var s = base64URLString
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let mod = s.count % 4
        switch mod {
            case 0: break
            case 2: s.append("==")
            case 3: s.append("=")
            default: return nil
        }

        self.init(base64Encoded: s)
    }

    /**
     Creates a new data buffer from base64url, UTF-8 encoded data.
     
     - Parameters:
         - base64URLData: The base64url, UTF-8 encoded data.
     
     - Returns: `nil` if the input is not recognized as valid base64url.
     */
    init?(base64URLEncoded base64URLData: Data) {
        guard let s = String(data: base64URLData, encoding: .utf8) else {
            return nil
        }

        self.init(base64URLEncoded: s)
    }

    /**
     Returns a base64url encoded string.
     
     - Returns: The base64url encoded string.
     */
    func base64URLEncodedString() -> String {
        let s = self.base64EncodedString()
        return s
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    /**
     Returns base64url encoded data.
     
     - Returns: The base64url encoded data.
     */
    func base64URLEncodedData() -> Data {
        // UTF-8 can represent [all Unicode characters](https://en.wikipedia.org/wiki/UTF-8), so this 
        // forced unwrap is safe. See also [this](https://stackoverflow.com/a/46152738/5233456) SO answer.
        return self.base64URLEncodedString().data(using: .utf8)!
    }
    
    /**
     Returns the length of a data object in ???????
     
     - Returns: The data length in ???????
    */
    func getHexLength() -> Data {
        let dataLength = UInt64(self.count * 8)
        let dataLengthInHex = String(dataLength, radix: 16, uppercase: false)
    
        var dataLengthBytes = [UInt8](repeatElement(0x00, count: 8))
        
        var dataIndex = dataLengthBytes.count-1
        for i in stride(from: 0, to: dataLengthInHex.count, by: 2) {
            var offset = 2
            var hexStringChunk = ""
            
            if dataLengthInHex.count-i == 1 {
                offset = 1
            }
            
            let endIndex = dataLengthInHex.index(dataLengthInHex.endIndex, offsetBy: -i)
            let startIndex = dataLengthInHex.index(endIndex, offsetBy: -offset)
            let range = Range(uncheckedBounds: (lower: startIndex, upper: endIndex))
            hexStringChunk = String(dataLengthInHex[range])
            
            if let hexByte = UInt8(hexStringChunk, radix: 16) {
                dataLengthBytes[dataIndex] = hexByte
            }
            
            dataIndex -= 1
        }
        
        return Data(bytes: dataLengthBytes)
    }
}

extension Data: DataConvertible {
    public init(_ data: Data) {
        self = data
    }

    public func data() -> Data {
        return self
    }
}
