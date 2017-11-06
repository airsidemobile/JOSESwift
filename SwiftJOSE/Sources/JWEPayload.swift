//
//  JWEPayload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWEPayload: Payload {
    let data: Data
    
    public init(_ data: Data) {
        self.data = data
    }
}
