//
//  JWKExtensions.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21.12.17.
//

import Foundation

extension JWK {
    public func jsonString() throws -> String {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw JWKError.JWKToJSONConversionFailed
        }

        // The forced unwrap is ok here since we checked `isValidJSONObject` above.
        // swiftlint:disable:next_line force_try
        let jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])

        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw JWKError.JWKToJSONConversionFailed
        }

        return jsonString
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
