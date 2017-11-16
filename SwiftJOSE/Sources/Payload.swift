//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Payload: JOSEObjectComponent {
    let payload: Data
    
    public init(_ payload: Data) {
        self.payload = payload
    }
    
    public func data() -> Data {
        return payload
    }
}
