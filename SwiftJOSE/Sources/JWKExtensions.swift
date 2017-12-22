//
//  JWKExtensions.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21.12.17.
//

import Foundation

extension JWK {
    public subscript(parameter: String) -> Any? {
        return parameters[parameter]
    }

    public func jsonString() throws -> String {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw JWKError.JWKToJSONConversionFailed
        }

        // The forced unwrap is ok here since we checked `isValidJSONObject` above.
        // swiftlint:disable:next_line force_try
        let jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])

        // The forced unwrap is ok here since `JSONSerialization.data()` returns UTF-8.
        // swiftlint:disable:next_line force_unwrap
        return String(data: jsonData, encoding: .utf8)!
    }

    public func jsonData() throws -> Data {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw JWKError.JWKToJSONConversionFailed
        }

        // The forced unwrap is ok here since we checked `isValidJSONObject` above.
        // swiftlint:disable:next_line force_try
        let jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])

        return jsonData
    }
}
