//
//  DataECPrivateKey.swift
//  JOSESwift
//
//  Created by Jarrod Moldrich on 10.01.2019.
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

extension Data: ExpressibleAsECPrivateKeyComponents {
    public static func representing(ecPrivateKeyComponents components: ECPrivateKeyComponents) throws -> Data {
        let xBytes = [UInt8](components.x)
        let yBytes = [UInt8](components.y)
        let dBytes = [UInt8](components.d)
        let uncompressedIndication: [UInt8] = [ECCompression.Uncompressed.rawValue]

        guard
                xBytes.count == yBytes.count,
                xBytes.count == dBytes.count,
                ECCurveType.fromCoordinateOctetLength(xBytes.count) != nil else {
            throw JOSESwiftError.invalidCurvePointOctetLength
        }

        return Data(uncompressedIndication + xBytes + yBytes + dBytes)
    }

    public func ecPrivateKeyComponents() throws -> ECPrivateKeyComponents {
        var privateKeyBytes = [UInt8](self)

        guard privateKeyBytes.removeFirst() == ECCompression.Uncompressed.rawValue else {
            throw JOSESwiftError.compressedCurvePointsUnsupported
        }

        let pointSize = privateKeyBytes.count / 3
        guard let curve = ECCurveType.fromCoordinateOctetLength(pointSize) else {
            throw JOSESwiftError.invalidCurvePointOctetLength
        }

        let xBytes = privateKeyBytes[0..<pointSize]
        let yBytes = privateKeyBytes[pointSize..<pointSize*2]
        let dBytes = privateKeyBytes[pointSize*2..<pointSize*3]
        let xData = Data(xBytes)
        let yData = Data(yBytes)
        let dData = Data(dBytes)
        return (curve.rawValue, xData, yData, dData)
    }
}
