//
//  Compressor.swift
//  JOSESwift
//
//  Created by Florian Häser on 13.02.19.
//

import Foundation

protocol CompressorProtocol {
    func compress(data: Data) -> Data
    func decompress(data: Data) -> Data
}

struct NoneCompressor: CompressorProtocol {
    func compress(data: Data) -> Data {
        return data
    }
    func decompress(data: Data) -> Data {
        return data
    }
}

struct CompressorFactory {
    static func getCompressor(algorithm: CompressionAlgorithm?) -> CompressorProtocol {
        switch algorithm {
        case .deflate?:
            return DeflateCompressor()
        default:
            return NoneCompressor()
        }
    }
}
