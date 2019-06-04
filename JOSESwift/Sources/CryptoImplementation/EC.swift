//
//  EC.swift
//  JOSESwift
//
//  Created by Jarrod Moldrich on 02.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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
import Security
import CommonCrypto

internal enum ECError: Error {
    case algorithmNotSupported
    case signingFailed(description: String)
    case verifyingFailed(description: String)
    case encryptingFailed(description: String)
    case decryptingFailed(description: String)
    case invalidCurveDigestAlgorithm
    case couldNotAllocateMemoryForSignature
}

/// Identifies the curve type parameter of a JWK representing an elliptic curve key
/// See [RFC-7518](https://tools.ietf.org/html/rfc7518#section-7.4) for details.
public enum ECCurveType: String, Codable {
    case P256 = "P-256"
    case P384 = "P-384"
    case P521 = "P-521"

    var keyBitLength: Int {
        switch self {
        case .P256:
            return 256
        case .P384:
            return 384
        case .P521:
            return 521
        }
    }

    var coordinateOctetLength: Int {
        switch self {
        case .P256:
            return 32
        case .P384:
            return 48
        case .P521:
            return 66
        }
    }

    var signatureOctetLength: Int {
        return self.coordinateOctetLength * 2
    }

    static func fromKeyBitLength(_ length: Int) -> ECCurveType? {
        switch length {
        case ECCurveType.P256.keyBitLength:
            return .P256
        case ECCurveType.P384.keyBitLength:
            return .P384
        case ECCurveType.P521.keyBitLength:
            return .P521
        default:
            return nil
        }
    }

    static func fromCoordinateOctetLength(_ length: Int) -> ECCurveType? {
        switch length {
        case ECCurveType.P256.coordinateOctetLength:
            return .P256
        case ECCurveType.P384.coordinateOctetLength:
            return .P384
        case ECCurveType.P521.coordinateOctetLength:
            return .P521
        default:
            return nil
        }
    }
}

// converting integers to and from DER encoded ASN.1 as described here:
// https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-integer
fileprivate extension Data {
    func withLengthFixedTo(_ octetLength: Int) -> Data {
        let varLength = self.count
        if varLength > octetLength + 1 {
            fatalError("Unable to parse ASN.1 Integer")
        }
        if varLength == octetLength + 1 {
            return self.dropFirst()
        }
        if varLength == octetLength {
            return self
        }
        if varLength < octetLength {
            return Data.init(count: octetLength - varLength) + self
        }
        fatalError("Unable to parse ASN.1 Integer")
    }

    func fixedLengthToAsn1() -> Data {
        assert(self.count > 0)
        let msb : UInt8 = 0b1000_0000
        let varlen = self.drop { $0 == 0}
        if (varlen.first! & msb) == msb {
            return Data(count: 1) + varlen
        }
        return varlen
    }}

fileprivate extension SignatureAlgorithm {

    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .ES256:
            return .ecdsaSignatureMessageX962SHA256
        case .ES384:
            return .ecdsaSignatureMessageX962SHA384
        case .ES512:
            return .ecdsaSignatureMessageX962SHA512
        default:
            return nil
        }
    }

    var curveType: ECCurveType? {
        switch self {
        case .ES256:
            return ECCurveType.P256
        case .ES384:
            return ECCurveType.P384
        case .ES512:
            return ECCurveType.P521
        default:
            return nil
        }
    }
}

// Point compression prefix. Based on X9.62, Section 4.3.6
public enum ECCompression: UInt8 {
    case CompressedYEven = 0x02
    case CompressedYOdd = 0x03
    case Uncompressed = 0x04 // supported only
    case HybridYEven = 0x06
    case HybridYOdd = 0x07
}

internal struct EC {
    typealias KeyType = SecKey

    ///  Signs input data with a given elliptic curve algorithm and the corresponding private key.
    ///
    /// - Parameters:
    ///   - signingInput: The data to sign.
    ///   - privateKey: The private key used by the `SignatureAlgorithm`.
    ///   - algorithm: The algorithm to sign the input data.
    /// - Returns: The signature.
    /// - Throws: `ECError` if any errors occur while signing the input data.
    static func sign(_ signingInput: Data, with privateKey: KeyType, and algorithm: SignatureAlgorithm) throws -> Data {
        guard let curveType = algorithm.curveType else {
            throw ECError.invalidCurveDigestAlgorithm
        }
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm else {
            throw ECError.algorithmNotSupported
        }

        var cfErrorRef: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(privateKey, secKeyAlgorithm, signingInput as CFData, &cfErrorRef)
        if cfErrorRef != nil {
            throw ECError.signingFailed(description: "Error creating signature. (CFError: \(cfErrorRef!.takeRetainedValue()))")
        }

        // unpack BER encoded ASN.1 format signature to raw format as specified for JWS
        let ecSignatureTLV = [UInt8](signature! as Data)
        do {
            let ecSignature = try ecSignatureTLV.read(.sequence)
            let varlenR = try Data(ecSignature.read(.integer))
            let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
            let fixlenR = varlenR.withLengthFixedTo(curveType.coordinateOctetLength)
            let fixlenS = varlenS.withLengthFixedTo(curveType.coordinateOctetLength)

            return fixlenR + fixlenS
        } catch {
            throw ECError.signingFailed(description: "could not unpack ASN.1 EC signature")
        }
    }

    /// Verifies input data against a signature with a given elliptic curve algorithm and the corresponding public key.
    ///
    /// - Parameters:
    ///   - verifyingInput: The data to verify.
    ///   - signature: The signature to verify against.
    ///   - publicKey: The public key used by the `SignatureAlgorithm`.
    ///   - algorithm: The algorithm to verify the input data.
    /// - Returns: True if the signature is verified, false if it is not verified.
    /// - Throws: `ECError` if any errors occur while verifying the input data against the signature.
    static func verify(_ verifyingInput: Data, against signature: Data, with publicKey: KeyType, and algorithm: SignatureAlgorithm) throws -> Bool {
        // Verify the raw signature against an input with a hashing algorithm and public key.
        guard let curveType = algorithm.curveType else {
            throw ECError.invalidCurveDigestAlgorithm
        }
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm else {
            throw ECError.algorithmNotSupported
        }

        // pack raw signature as apecified for JWS into BER encoded ASN.1 format
        let fixlenR = signature.prefix(curveType.coordinateOctetLength)
        let varlenR = [UInt8](fixlenR.fixedLengthToAsn1())
        let fixlenS = signature.suffix(curveType.coordinateOctetLength)
        let varlenS = [UInt8](fixlenS.fixedLengthToAsn1())
        let asn1Signature = Data((varlenR.encode(as: .integer) + varlenS.encode(as: .integer)).encode(as: .sequence))

        var cfErrorRef: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(publicKey, secKeyAlgorithm, verifyingInput as CFData, asn1Signature as CFData, &cfErrorRef)
        if cfErrorRef != nil {
            throw ECError.signingFailed(description: "Error verifying signature. (CFError: \(cfErrorRef!.takeRetainedValue()))")
        }
        return isValid
    }

}
