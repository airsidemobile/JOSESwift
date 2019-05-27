//
//  Compressor.swift
//  JOSESwift
//
//  Created by Florian Häser on 13.02.19.
//

import Foundation

protocol CompressorProtocol {
    /// Compresses data using the `CompressionAlgorithm`.
    ///
    /// - Parameter data: The uncompressed data.
    /// - Returns: The compressed data.
    func compress(data: Data) throws -> Data
    /// Decompresses data using the `CompressionAlgorithm`.
    ///
    /// - Parameter data: The compressed data.
    /// - Returns: The decompressed data.
    func decompress(data: Data) throws -> Data
}

/// A `Compressor` that takes the data and passes it back without doing any compression or decompression.
/// Used for having the JWE implementation more readable.
struct NoneCompressor: CompressorProtocol {
    func compress(data: Data) -> Data {
        return data
    }
    func decompress(data: Data) -> Data {
        return data
    }
}

struct CompressorFactory {
    /// Select the appropriate `Compressor` for a given `CompressionAlgorithm. Defaults to the `NoneCompressor`.
    ///
    /// - Parameter algorithm: The `CompressionAlgorithm` for selecting the appropriate compressor.
    /// - Returns: The appropriate compressor
    static func makeCompressor(algorithm: CompressionAlgorithm?) throws -> CompressorProtocol {
        switch algorithm {
        case .DEFLATE?:
            return DeflateCompressor()
        case .NONE?:
            return NoneCompressor()
        default:
            throw JOSESwiftError.compressionAlgorithmNotSupported
        }
    }
}
