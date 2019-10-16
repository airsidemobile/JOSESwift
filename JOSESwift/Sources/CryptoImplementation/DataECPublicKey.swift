//
//  DataECPublicKey.swift
//  JOSESwift
//
//  Created by Jarrod Moldrich on 02.07.18.
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

extension Data: ExpressibleAsECPublicKeyComponents {
    public static func representing(ecPublicKeyComponents components: ECPublicKeyComponents) throws -> Data {
        let xBytes = [UInt8](components.x)
        let yBytes = [UInt8](components.y)
        let uncompressedIndication: [UInt8] = [ECCompression.Uncompressed.rawValue]

        guard
                xBytes.count == yBytes.count,
                ECCurveType.fromCoordinateOctetLength(xBytes.count) != nil else {
            throw JOSESwiftError.invalidCurvePointOctetLength
        }

        return Data(uncompressedIndication + xBytes + yBytes)
    }

    public func ecPublicKeyComponents() throws -> ECPublicKeyComponents {
        var publicKeyBytes = [UInt8](self)

        guard publicKeyBytes.removeFirst() == ECCompression.Uncompressed.rawValue else {
            throw JOSESwiftError.compressedCurvePointsUnsupported
        }

        let pointSize = publicKeyBytes.count / 2
        guard let curve = ECCurveType.fromCoordinateOctetLength(pointSize) else {
            throw JOSESwiftError.invalidCurvePointOctetLength
        }

        let xBytes = publicKeyBytes[0..<pointSize]
        let yBytes = publicKeyBytes[pointSize..<pointSize*2]
        let xData = Data(xBytes)
        let yData = Data(yBytes)
        return (curve.rawValue, xData, yData)
    }
}
