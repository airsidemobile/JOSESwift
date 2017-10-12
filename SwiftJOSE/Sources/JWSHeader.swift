//
//  JWSHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 27/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWSHeader: JOSEHeader {
    let parameters: [String : Any]
    
    init(parameters: [String : Any]) {
        // assert required parameters for JWS
        self.parameters = parameters
    }
}

extension JWSHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWSHeader.self, at: 0)
    }
}
