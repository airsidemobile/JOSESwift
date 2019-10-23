//
//  DeflateWrapper.swift
//  JOSESwift
//
//  Modified by Florian Häser on 24.12.18.
//  Removed all but the only supported and required compression algorithm.
//  [JOSE compression algorithm](https://www.iana.org/assignments/jose/jose.xhtml#web-encryption-compression-algorithms)
//  [Compression Algorithm) Header Parameter](https://tools.ietf.org/html/rfc7516#section-4.1.3)
//
//  Originally created by mw99 (Markus Wanke) in his libcompression wrapper https://github.com/mw99/DataCompression
//  licensed under Apache License, Version 2.0
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
import Compression

struct DeflateCompressor: CompressorProtocol {
    /// Compresses the data using the zlib deflate algorithm.
    /// - returns: raw deflated data according to [RFC-1951](https://tools.ietf.org/html/rfc1951).
    /// - note: Fixed at compression level 5 (best trade off between speed and time)
    public func compress(data: Data) throws -> Data {
        guard data.count > 0 else {
            throw JOSESwiftError.rawDataMustBeGreaterThanZero
        }

        let config = (operation: COMPRESSION_STREAM_ENCODE, algorithm: COMPRESSION_ZLIB)
        if let data = data.withUnsafeBytes({ sourcePtr in
            // Force unwrapping is ok, since data is guaranteed not to be empty.
            // From the docs: If the baseAddress of this buffer is nil, the count is zero.
            // swiftlint:disable:next force_unwrapping
            perform(config, source: sourcePtr.baseAddress!.assumingMemoryBound(to: UInt8.self), sourceSize: data.count)
        }) {
            return data
        } else {
            throw JOSESwiftError.compressionFailed
        }
    }

    /// Decompresses the data using the zlib deflate algorithm. Self is expected to be a raw deflate
    /// stream according to [RFC-1951](https://tools.ietf.org/html/rfc1951).
    /// - returns: uncompressed data
    public func decompress(data: Data) throws -> Data {
        guard data.count > 0 else {
            throw JOSESwiftError.compressedDataMustBeGreaterThanZero
        }

        let config = (operation: COMPRESSION_STREAM_DECODE, algorithm: COMPRESSION_ZLIB)
        if let data = data.withUnsafeBytes({ sourcePtr in
            // Force unwrapping is ok, since data is guaranteed not to be empty.
            // From the docs: If the baseAddress of this buffer is nil, the count is zero.
            // swiftlint:disable:next force_unwrapping
            perform(config, source: sourcePtr.baseAddress!.assumingMemoryBound(to: UInt8.self), sourceSize: data.count)
        }) {
            return data
        } else {
            throw JOSESwiftError.decompressionFailed
        }
    }
}

private typealias Config = (operation: compression_stream_operation, algorithm: compression_algorithm)

private func perform(_ config: Config, source: UnsafePointer<UInt8>, sourceSize: Int, preload: Data = Data()) -> Data? {
    guard config.operation == COMPRESSION_STREAM_ENCODE || sourceSize > 0 else { return nil }

    let streamBase = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
    defer { streamBase.deallocate() }
    var stream = streamBase.pointee

    let status = compression_stream_init(&stream, config.operation, config.algorithm)
    guard status != COMPRESSION_STATUS_ERROR else { return nil }
    defer { compression_stream_destroy(&stream) }

    let bufferSize = Swift.max( Swift.min(sourceSize, 64 * 1024), 64)
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
    defer { buffer.deallocate() }

    stream.dst_ptr  = buffer
    stream.dst_size = bufferSize
    stream.src_ptr  = source
    stream.src_size = sourceSize

    var res = preload
    let flags: Int32 = Int32(COMPRESSION_STREAM_FINALIZE.rawValue)

    while true {
        switch compression_stream_process(&stream, flags) {
        case COMPRESSION_STATUS_OK:
            guard stream.dst_size == 0 else { return nil }
            res.append(buffer, count: stream.dst_ptr - buffer)
            stream.dst_ptr = buffer
            stream.dst_size = bufferSize

        case COMPRESSION_STATUS_END:
            res.append(buffer, count: stream.dst_ptr - buffer)
            return res

        default:
            return nil
        }
    }
}
