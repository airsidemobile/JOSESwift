//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

protocol Payload: JOSEObjectComponent {
    var data: Data { get }
    init(_ data: Data)
}

extension Payload {
    public init(from data: Data) {
        self.init(data)
    }
    
    public func data() -> Data {
        return data
    }
}
