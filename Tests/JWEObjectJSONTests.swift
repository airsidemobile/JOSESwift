//
//  JWEObjectJSONTests.swift
//  JOSESwift
//
//  Created by Prem Eide on 02/12/2025.
//


import XCTest
@testable import JOSESwift

final class JWEObjectJSONTests: ECCryptoTestCase {
    
    private let GENERAL_JSON_JWE_COMBINED = """
    {
        "ciphertext": "cBE1WhgQcg9iA1pcYe6hCO8XdqJ_ZGReEAOeqw9iJaHhQsMzvWlD_ErX5KOd5hI0wZvc",
        "protected": "eyJ0eXAiOiJKV0UiLCJlbmMiOiJBMjU2R0NNIn0",
        "recipients": [
            {
                "encrypted_key": "TnBh1cV3P8sbqnWoajeeuyBQf9oNiOp2hPxxprO6mLepq1zt0V-Jed2P5-ZAYpOq5JaPKn7egvfs0uuMsFAL4xt7EgSZfYHuXUHMZRNVATrmoXR70bXCH9__vMtSYBrceVWSJSwF01TaNGwPrwetu2hvGO7YVXF5wDjJKB-cnJ5M4U3em0cNoSM986VgyZG3ArztxmKiWs3TX8u03QkUNTG0lWjFHEvHwLt9tGJMoiwx4tfh5Q0OcuxcA1xFYeOy9JsP2LNe6rCKjgA396np5us22-coqABttwY8kA78wTsr4YEus8NyhogaCV6aJ-S-NnhNMISkUlnU-kmnX3WDZA",
                "header": {
                    "alg": "RSA-OAEP-256",
                    "kid": "rsa1"
                }
            },
            {
                "encrypted_key": "fDP0iySx6SnQao0xegMesiNq3v5GrVgTax5sh3Y6TMV5LX1YMXRLhg",
                "header": {
                    "epk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "x7b6-aldF4veusN1YlK1kHv1m8xUp2BxPG3rcrMyY2U",
                        "y": "CESJcKwPhK4Il8hAVSNke8wq6SbHqY_BCWuIkntk5Bk"
                    },
                    "alg": "ECDH-ES+A256KW",
                    "kid": "ec1"
                }
            }
        ],
        "tag": "bUky-v6rh_Ge7_CFMQOTuw",
        "iv": "GdKaxFnxvcWweY-X"
    }
    """
    
    private let GENERAL_JSON_JWE_EC = """
    {
        "ciphertext": "OiouIje2Yrec1J9Whw",
        "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
        "recipients": [
            {
                "encrypted_key": "_g0qbd2s-JmouR6gJcm5yQHdjHnwljuT",
                "header": {
                    "alg": "ECDH-ES+A128KW",
                    "kid": "y0kvfqkdTR5eYPsd6u0ncuqmG7fF72Z-ty2c0S1wzvc"
                }
            },
            {
                "encrypted_key": "Go0AE2zNKwvgMaJcOF2sGFrPk-8mM_ll",
                "header": {
                    "alg": "ECDH-ES+A128KW",
                    "kid": "wSgBepPu4b3vdNc2rpTGkQQ8UZw3ZF7lfWrpCEz51Uw"
                }
            }
        ],
        "tag": "XWIuEs_QKfD5vtRlN9LNVA",
        "iv": "-K7qUpvoKT0SIcFi"
    }
    """
    
    func testParsingGeneralJsonJweCombined() throws {
        let jwe = try JWEObjectJSON(jsonString: GENERAL_JSON_JWE_COMBINED)
        
        XCTAssertEqual(jwe.recipients.count, 2)
        XCTAssertEqual(jwe.cipherText.value, "cBE1WhgQcg9iA1pcYe6hCO8XdqJ_ZGReEAOeqw9iJaHhQsMzvWlD_ErX5KOd5hI0wZvc")
        XCTAssertEqual(jwe.iv.value, "GdKaxFnxvcWweY-X")
        XCTAssertEqual(jwe.tag.value, "bUky-v6rh_Ge7_CFMQOTuw")
        
        XCTAssertEqual(jwe.protected.parameters["enc"] as? String, "A256GCM")
        
        XCTAssertEqual(jwe.recipients[0].unprotectedHeader?.alg as? String, "RSA-OAEP-256")
        XCTAssertEqual(jwe.recipients[1].unprotectedHeader?.alg as? String, "ECDH-ES+A256KW")
    }
    
    func testParsingGeneralJsonJweEC() throws {
        let jwe = try JWEObjectJSON(jsonString: GENERAL_JSON_JWE_EC)
        
        XCTAssertEqual(jwe.recipients.count, 2)
        XCTAssertEqual(jwe.cipherText.value, "OiouIje2Yrec1J9Whw")
        XCTAssertEqual(jwe.iv.value, "-K7qUpvoKT0SIcFi")
        XCTAssertEqual(jwe.tag.value, "XWIuEs_QKfD5vtRlN9LNVA")
        
        XCTAssertEqual(jwe.protected.parameters["enc"] as? String, "A128GCM")
        
        XCTAssertEqual(jwe.recipients[0].unprotectedHeader?.alg as? String, "ECDH-ES+A128KW")
        XCTAssertEqual(jwe.recipients[1].unprotectedHeader?.alg as? String, "ECDH-ES+A128KW")
    }
    
    func testJoiningHeaders() throws {
        let jwe = try JWEObjectJSON(jsonString: GENERAL_JSON_JWE_EC)
        
        let recipientHeader = try XCTUnwrap(jwe.recipients.first?.unprotectedHeader)
        let joined = try jwe.protected.join(recipientHeader)
        
        XCTAssertEqual(joined.parameters["enc"] as? String, "A128GCM")
        XCTAssertEqual(joined.parameters["alg"] as? String, "ECDH-ES+A128KW")
        XCTAssertEqual(joined.parameters["kid"] as? String, "y0kvfqkdTR5eYPsd6u0ncuqmG7fF72Z-ty2c0S1wzvc")
    }
    
    func testJoiningHeadersCollisionThrows() throws {
        let jwe = try JWEObjectJSON(jsonString: GENERAL_JSON_JWE_EC)
        
        let collidingHeader = UnprotectedHeader(parameters: [
            "enc": "A256GCM"
        ])
        
        XCTAssertThrowsError(
            try jwe.protected.join(collidingHeader),
            "Expected join to throw on header collision"
        )
    }
}
