//
//  ECDHKeyAgreement.swift
//  JOSESwift
//
//  Created by Mikael Rucinsky on 07.12.20.
//

import Foundation
import CommonCrypto

/// keyAgreementCompute
///
/// - Parameters:
///   - algorithm: KeyManagementAlgorithm.
///   - encryption: ContentEncryptionAlgorithm.
///   - privateKey: EC private JWK.
///   - publicKey: EC public JWK.
///   - apu: agreementPartyUInfo.
///   - apv: agreementPartyVInfo.
/// - Returns: Result of key agreement operation as a Data
/// - Throws: `ECError.deriveKeyFail` if any error occurs while derivation.
// swiftlint:disable:next function_parameter_count
func keyAgreementCompute(with algorithm: KeyManagementAlgorithm, encryption: ContentEncryptionAlgorithm, privateKey: ECPrivateKey, publicKey: ECPublicKey, apu: Data, apv: Data) throws -> Data {

    let z = try ecdhDeriveBits(for: privateKey, publicKey: publicKey)
    var algId: Data, keyDataLen: Int
    if algorithm == .ECDH_ES {
        guard let ident = encryption.rawValue.data(using: .utf8) else {
            throw ECError.deriveKeyFail(reason: "AlgorithmID Problem - @See Section 5.8.1.2 of [NIST.800-56A]")
        }
        algId = ident
        keyDataLen = encryption.keyBitSize
    } else {
        guard let ident = algorithm.rawValue.data(using: .utf8) else {
            throw ECError.deriveKeyFail(reason: "AlgorithmID Problem -  @See Section 5.8.1.2 of [NIST.800-56A]")
        }
        algId = ident
        keyDataLen = algorithm.keyWrapAlgorithm?.keyBitSize ?? 0
    }
    let algorithmID = prefixedBigEndenLen(from: algId)
    let partyUInfo = prefixedBigEndenLen(from: apu)
    let partyVInfo = prefixedBigEndenLen(from: apv)
    let suppPubInfo = intToData(value: UInt32(keyDataLen).bigEndian)
    return try concatKDF(hash: Hash.SHA256, z: z, keyDataLen: keyDataLen, algorithmID: algorithmID, partyUInfo: partyUInfo, partyVInfo: partyVInfo, suppPubInfo: suppPubInfo)
}

/// Derive ECDH Key Data
///
/// - Parameters:
///   - privateKey: EC private JWK.
///   - publicKey: EC public JWK.
///   - bitLen: key size
/// - Returns: Result of key exchange operation as a Data
/// - Throws: `ECError.deriveKeyFail` if any error occurs while derivation.
func ecdhDeriveBits(for privateKey: ECPrivateKey, publicKey: ECPublicKey, bitLen: Int = 0) throws -> Data {
    if privateKey.crv != publicKey.crv {
        throw ECError.deriveKeyFail(reason: "Private Key curve and Public Key curve are different")
    }
    let pubKey = try publicKey.converted(to: SecKey.self)
    let privKey = try privateKey.converted(to: SecKey.self)
    let parameters = [String: Any]()
    var error: Unmanaged<CFError>?

    guard let derivedData = SecKeyCopyKeyExchangeResult(privKey, SecKeyAlgorithm.ecdhKeyExchangeStandard, pubKey, parameters as CFDictionary, &error) else {
        let errStr = error?.takeRetainedValue().localizedDescription ?? "Derive Key Fail"
        throw ECError.deriveKeyFail(reason: errStr)
    }
    return bitLen > 0 ? truncateBitLen(from: (derivedData as Data), bitLen: bitLen) : (derivedData as Data) as Data
}

func truncateBitLen(from: Data, bitLen: Int) -> Data {
    if bitLen >= from.count * 8 {
        return from
    } else if bitLen % 8 == 0 {
        return from[0 ..< (bitLen / 8)]
    }
    let lastPos = Int(bitLen / 8)
    var result = from[0 ..< (lastPos + 1)]
    result[lastPos] = result[lastPos] & (~(0xFF >> (UInt(bitLen) % 8)))
    return result
}

func prefixedBigEndenLen(from: Data) -> Data {
    let prefix = intToData(value: UInt32(from.count).bigEndian)
    return prefix + from
}

func intToData<T>(value: T) -> Data where T: FixedWidthInteger {
    var int = value
    return Data(bytes: &int, count: MemoryLayout<T>.size)
}

/// Concat KDF see https://tools.ietf.org/html/rfc7518#section-4.6.2
///
/// - Parameters:
///   - hash: HASH algorithm
///   - z: The shared secret Z
///   - keyDataLen: The number of bits in the desired output key.
///   - algorithmID: AlgorithmID @See Section 5.8.1.2 of [NIST.800-56A]
///   - partyUInfo: PartyUInfo @See Section 5.8.1.2 of [NIST.800-56A]
///   - partyVInfo: PartyVInfo @See Section 5.8.1.2 of [NIST.800-56A]
///   - suppPubInfo: SuppPubInfo @See Section 5.8.1.2 of [NIST.800-56A]
///   - suppPrivInfo: SuppPrivInfo @See Section 5.8.1.2 of [NIST.800-56A]
/// - Returns: Derived Keying Material as a Data
/// - Throws: `ECDHError` if any error occurs while derivation.
// swiftlint:disable:next function_parameter_count
func concatKDF(hash: Hash, z: Data, keyDataLen: Int, algorithmID: Data, partyUInfo: Data, partyVInfo: Data, suppPubInfo: Data = Data(), suppPrivInfo: Data = Data()) throws -> Data {
    if keyDataLen == 0 {
        return Data()
    }
    let modLen = keyDataLen % hash.bitLength
    let reps = (keyDataLen / hash.bitLength) + (modLen > 0 ? 1 : 0)

    let concatedData = z + algorithmID + partyUInfo + partyVInfo + suppPubInfo + suppPrivInfo
    let hashInputLen = 4 + concatedData.count
    guard hashInputLen <= 0xFFFF else {
        throw ECError.deriveKeyFail(reason: "Derivation parameter (couter + Z + otherInfor) is more than max HASH input length")
    }

    var derivedKeyingMaterial = Data()
    for i in 1 ..< reps {
        derivedKeyingMaterial += hash.digest(intToData(value: UInt32(i).bigEndian) + concatedData)
    }

    if modLen == 0 {
        derivedKeyingMaterial += hash.digest(intToData(value: UInt32(reps).bigEndian) + concatedData)
    } else {
        let digest = hash.digest(intToData(value: UInt32(reps).bigEndian) + concatedData)
        derivedKeyingMaterial += truncateBitLen(from: digest, bitLen: modLen)
    }
    return derivedKeyingMaterial
}

func randomBytes(size: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: size)
    guard errSecSuccess == SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) else {
        return Data(count: size)
    }
    return Data(bytes)
}

//

enum Hash: String {
    case SHA256 = "SHA-256"
    case SHA384 = "SHA-384"
    case SHA512 = "SHA-512"

    func digest(_ value: Data) -> Data {
        var digestData = [UInt8](repeating: 0, count: digestByteLength)
        _ = digestFunc(Array(value), UInt32(value.count), &digestData)
        return Data(digestData)
    }

    func mac(key: Data, value: Data) -> Data {
        var outData = [UInt8](repeating: 0, count: digestByteLength)
        CCHmac(ccHmacAlgorithm, Array(key), key.count, Array(value), value.count, &outData)
        return Data(outData)
    }

    fileprivate var ccHmacAlgorithm: CCHmacAlgorithm {
        switch self {
        case .SHA256:
            return CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .SHA384:
            return CCHmacAlgorithm(kCCHmacAlgSHA384)
        case .SHA512:
            return CCHmacAlgorithm(kCCHmacAlgSHA512)
        }
    }

    fileprivate var digestFunc: (UnsafeRawPointer?, UInt32, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>? {
        switch self {
        case .SHA256:
            return CC_SHA256
        case .SHA384:
            return CC_SHA384
        case .SHA512:
            return CC_SHA512
        }
    }

    var bitLength: Int {
        switch self {
        case .SHA256:
            return 256
        case .SHA384:
            return 384
        case .SHA512:
            return 512
        }
    }

    var digestByteLength: Int {
        switch self {
        case .SHA256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        case .SHA384:
            return Int(CC_SHA384_DIGEST_LENGTH)
        case .SHA512:
            return Int(CC_SHA512_DIGEST_LENGTH)
        }
    }
}
