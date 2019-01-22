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

fileprivate extension SignatureAlgorithm {
    typealias DigestFunction = (
            Optional<UnsafeRawPointer>,
            UInt32,
            Optional<UnsafeMutablePointer<UInt8>>
    ) -> Optional<UnsafeMutablePointer<UInt8>>

    func createDigest(input: Data) throws -> [UInt8] {
        guard
                let computedDigestLength = digestLength,
                let computedDigestFunction = digestFunction
                else {
            throw ECError.invalidCurveDigestAlgorithm
        }
        var digest = [UInt8](repeating: 0, count: computedDigestLength)
        _ = computedDigestFunction(Array(input), UInt32(input.count), &digest)
        return digest
    }

    var digestLength: Int? {
        switch self {
        case .ES256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        case .ES384:
            return Int(CC_SHA384_DIGEST_LENGTH)
        case .ES512:
            return Int(CC_SHA512_DIGEST_LENGTH)
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

    var digestFunction: DigestFunction? {
        switch self {
        case .ES256:
            return CC_SHA256
        case .ES384:
            return CC_SHA384
        case .ES512:
            return CC_SHA512
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
        // Sign the input as raw elliptic curve coordinates using a hashing algorithm and a private key.
        guard let curveType = algorithm.curveType else {
            throw ECError.invalidCurveDigestAlgorithm
        }
        let digest = try algorithm.createDigest(input: signingInput)
        var signatureLength = curveType.signatureOctetLength
        let signature = NSMutableData(length: signatureLength)!
        let signatureBytes = signature.mutableBytes.assumingMemoryBound(to: UInt8.self)
        let status = SecKeyRawSign(privateKey, .sigRaw, digest, digest.count, signatureBytes, &signatureLength)
        if status != errSecSuccess {
            throw ECError.signingFailed(description: "Error creating signature. (OSStatus: \(status))")
        }

        return signature as Data
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
        let digest = try algorithm.createDigest(input: verifyingInput)
        let signatureBytes: [UInt8] = Array(signature)
        let status = SecKeyRawVerify(publicKey, .sigRaw, digest, digest.count, signatureBytes, curveType.signatureOctetLength)
        if status != errSecSuccess {
            throw ECError.verifyingFailed(description: "Error validating signature. (OSStatus: \(status))")
        }

        return true
    }

}
