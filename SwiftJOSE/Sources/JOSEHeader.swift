//
//  JOSEHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2018 Airside Mobile Inc. All rights reserved.
//

import Foundation

enum HeaderParsingError: Error {
    case requiredHeaderParameterMissing(parameter: String)
    case headerIsNotValidJSONObject
}

/// A `JOSEHeader` is a JSON object representing various Header Parameters.
/// Moreover, a `JOSEHeader` is a `JOSEObjectComponent`. Therefore it can be initialized from and converted to `Data`.
protocol JOSEHeader: DataConvertible, CommonHeaderParameterSpace {
    var headerData: Data { get }
    var parameters: [String: Any] { get }
    
    init(parameters: [String: Any], headerData: Data) throws

    init?(_ data: Data)
    func data() -> Data
}

// `DataConvertible` implementation.
extension JOSEHeader {
    public init?(_ data: Data) {
        // Verify that the header is a completely valid JSON object.
        guard
            let json = try? JSONSerialization.jsonObject(with: data, options: []),
            let parameters = json as? [String: Any]
        else {
            return nil
        }

        try? self.init(parameters: parameters, headerData: data)
    }

    public func data() -> Data {
        return headerData
    }
}

/// JWS and JWE share a common Header Parameter space that both JWS and JWE headers must support.
/// Those header parameters may have a different meaning depending on whether they are part of a JWE or JWS.
public protocol CommonHeaderParameterSpace {
    var jku: URL? { get }
    var jwk: String? { get } //TODO: Use JWK class
    var kid: String? { get }
    var x5u: URL? { get }
    var x5c: [String: Any]? { get }
    var x5t: String? { get }
    var x5tS256: String? { get }
    var typ: String? { get }
    var cty: String? { get }
    var crit: [String]? { get }
}
