//
//  UnprotectedHeader.swift
//  JOSESwift
//
//  Created by Prem Eide on 12/12/2025.
//

public struct UnprotectedHeader {
    public var parameters: [String: Any]
    
    public init(parameters: [String: Any]) {
        self.parameters = parameters
    }
    
    public var keyID: String? {
        parameters["kid"] as? String
    }
    
    public var alg: KeyManagementAlgorithm? {
        guard let algStr = parameters["alg"] as? String else { return nil }
        return KeyManagementAlgorithm(rawValue: algStr)
    }
}
