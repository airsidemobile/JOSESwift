//
//  Payload.swift
//  JOSESwift
//
//  Created by Daniel Egger on 20/09/2017.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
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

    func compressed(using algorithm: CompressionAlgorithm?) throws -> Payload {
        let compressor = try CompressorFactory.makeCompressor(algorithm: algorithm)
        return Payload(try compressor.compress(data: payload))
    }
}
