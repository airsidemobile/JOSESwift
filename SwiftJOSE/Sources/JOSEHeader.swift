//
//  JOSEHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

/// A `JOSEHeader` is a JSON object representing various Header Parameters.
/// Moreover, a `JOSEHeader` is a `JOSEObjectComponent`. Therefore it can be initialized from and converted to `Data`.
protocol JOSEHeader: JOSEObjectComponent {
    var parameters: [String: Any] { get }
    init(parameters: [String: Any])
}

// `JOSEObjectComponent` implementation.
extension JOSEHeader {
    public init(from data: Data) {
        let parameters = try! JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
        self.init(parameters: parameters)
    }
    
    public func data() -> Data {
        // The resulting data of this operation is UTF-8 encoded.
        return try! JSONSerialization.data(withJSONObject: parameters, options: [])
    }
}

/// JWS and JWE share a common Header Parameter space that both JWS and JWE headers must support.
public protocol CommonHeaderParameterSpace {
    var algorithm: Algorithm { get }
}

