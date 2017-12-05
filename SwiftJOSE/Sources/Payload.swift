//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//

import Foundation

public struct Payload: DataConvertible {
    let payload: Data

    public init(_ payload: Data) {
        self.payload = payload
    }

    public func data() -> Data {
        return payload
    }
}
