//
//  Header.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

internal protocol Header: JOSEObjectComponent {
    var parameters: [String: Any] { get }
    init(parameters: [String: Any])
    init(algorithm: SigningAlgorithm)
}
    
internal extension Header {
    init(from data: Data) {
        let parameters = try! JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
        self.init(parameters: parameters)
    }
    
    func data() -> Data {
        return try! JSONSerialization.data(withJSONObject: parameters, options: [])
    }
}
