//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Payload {
    let data: Data?
    let dict: [String: Any]?
    
    public init(_ data: Data) {
        self.data = data
        self.dict = nil
    }
    
    public init(_ dict: [String: Any]) {
        self.data = nil
        self.dict = dict
    }
}

extension Payload: Base64URLCodable {
    func base64URLEncoded() -> String {
        if data == nil, let dict = dict {
            return try! JSONSerialization.data(withJSONObject: dict, options: []).base64URLEncoded()
        }
        return data!.base64URLEncoded()
    }
    
    init(base64URLEncoded: String) {
        let data = Data(base64URLEncoded: base64URLEncoded)
        do {
            self.dict = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
            self.data = nil
        } catch {
            self.data = data
            self.dict = nil
        }
    }
}
