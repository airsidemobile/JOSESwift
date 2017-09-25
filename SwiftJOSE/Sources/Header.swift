//
//  Header.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Header {
    let parameters: [String: Any]
    
    public init(_ parameters: [String: Any]) {
        self.parameters = parameters
    }
}

extension Header: ExpressibleByData {
    init(_ data: Data) {
        let parameters = try! JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
        self.init(parameters)
    }
    
    func data() -> Data {
        return try! JSONSerialization.data(withJSONObject: parameters, options: [])
    }
}

extension Header: CompactDeserializable {
    init(from deserializer: CompactDeserializerProtocol) {
        self = deserializer.deserialize(Header.self, at: 0)
    }
}
