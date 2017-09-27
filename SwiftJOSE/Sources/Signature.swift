//
//  Signature.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 25/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Signature {
    fileprivate let signature: Data
    
    public init(_ signature: Data) {
        self.signature = signature
    }
}

extension Signature: JOSEObjectComponent {
    init(from data: Data) {
        self.signature = data
    }
    
    func data() -> Data {
        return signature
    }
}

extension Signature: CompactDeserializable {
    init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(Signature.self, at: 2)
    }
}
