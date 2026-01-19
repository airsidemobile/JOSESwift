//
//  Base64URL.swift
//  JOSESwift
//
//  Created by Prem Eide on 10/12/2025.
//

import Foundation

internal enum Base64URLError: Error {
    case invalidBase64URLString
}

public struct Base64URL {
    public let value: String

    public init(_ base64URL: String) {
        self.value = base64URL
    }
    
    public init(_ data: Data) {
        self.value = data.base64EncodedString()
    }
    
    public func decode() throws -> Data {
        guard let data = Data(base64URLEncoded: value) else {
            throw Base64URLError.invalidBase64URLString
        }
        return data
    }
}
