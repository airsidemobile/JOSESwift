//
//  DataTimingSafeCompare.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 14.04.21.
//

import Foundation

extension Data {
    /// Compares data in constant-time.
    ///
    /// The running time of this method is independent of the data compared, making it safe to use for comparing secret values such as cryptographic MACs.
    ///
    /// The number of bytes of both data are expected to be of same length.
    ///
    /// - Parameter other: Other data for comparison.
    /// - Returns: `true` if both data are equal, otherwise `false`.
    func timingSafeCompare(with other: Data) -> Bool {
        assert(self.count == other.count, "parameters should be of same length")
        if #available(iOS 10.1, *) {
            return timingsafe_bcmp([UInt8](self), [UInt8](other), self.count) == 0
        } else {
            var diff: UInt8 = 0
            for i in 0 ..< self.count {
                diff |= self[i] ^ other[i]
            }
            return diff == 0
        }
    }
}
