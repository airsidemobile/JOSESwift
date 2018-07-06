//
// Created by Jarrod Moldrich on 02.07.18.
//

import Foundation

extension Data: ExpressibleAsECPublicKeyComponents {
    public static func representing(ecPublicKeyComponents components: ECPublicKeyComponents) throws -> Data {
        let xBytes = [UInt8](components.x)
        let yBytes = [UInt8](components.y)
        let uncompressedIndication: [UInt8] = [0x04]

        guard
                xBytes.count == yBytes.count,
                ECCurveType.fromCoordinateOctetLength(xBytes.count) != nil else {
            throw JOSESwiftError.unsupportedCurvePointSize
        }

        return Data(bytes: uncompressedIndication + xBytes + yBytes)
    }

    public func ecPublicKeyComponents() throws -> ECPublicKeyComponents {
        var publicKeyBytes = [UInt8](self)

        guard publicKeyBytes.removeFirst() == 0x04 else {
            throw JOSESwiftError.compressedCurvePointsUnsuported
        }

        let pointSize = publicKeyBytes.count / 2
        guard let curve = ECCurveType.fromCoordinateOctetLength(pointSize) else {
            throw JOSESwiftError.unsupportedCurvePointSize
        }

        let xBytes = publicKeyBytes[0..<pointSize]
        let yBytes = publicKeyBytes[pointSize..<pointSize*2]
        let xData = Data(bytes: xBytes)
        let yData = Data(bytes: yBytes)
        return (curve.rawValue, xData, yData)
    }
}
