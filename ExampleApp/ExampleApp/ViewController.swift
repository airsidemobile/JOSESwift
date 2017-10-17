//
//  ViewController.swift
//  ExampleApp
//
//  Created by Daniel Egger on 17/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import UIKit
import SwiftJOSE

class ViewController: UIViewController {

    let message = "so cool"
    let privateKey = "thePrivateKey"
    let publicKey = "thePublicKey"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        demoJWS()
        demoJWE()
    }
    
    func demoJWS() {
        print("Message:\n\(message)\n")
        
        let header = JWSHeader(algorithm: .rs512)
        let payload = JWSPayload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey)
        let firstJWS = JWS(header: header, payload: payload, signer: signer)
        let compactSerializationFirstJWS = firstJWS.compactSerialized
        
        print("Serialized:\n\(compactSerializationFirstJWS)\n")
        
        let secondJWS = JWS(compactSerialization: compactSerializationFirstJWS)
        let verifier =  RSAVerifier(key: publicKey)
        if secondJWS.validates(against: verifier) {
            print("Deserialized:\n\(secondJWS)\n")
        }
        
        let justTheHeader = JOSEDeserializer().deserialize(JWSHeader.self, fromCompactSerialization: compactSerializationFirstJWS)
        print("Just The Header:\n\(justTheHeader)\n")
        let justThePayload = JOSEDeserializer().deserialize(JWSPayload.self, fromCompactSerialization: compactSerializationFirstJWS)
        print("Just The Payload:\n\(justThePayload)")
    }
    
    func demoJWE() {
        let header = JWEHeader(algorithm: .rs512, encryptionAlgorithm: .rs512)
        let payload = JWEPayload(message.data(using: .utf8)!)
        let encrypter = AESEncrypter(publicKey: "key")
        let jwe = JWE(header: header, payload: payload, encrypter: encrypter)
        print(jwe.compactSerialized)
        
        let secondJWE = JWE(compactSerialization: jwe.compactSerialized)
        print(secondJWE)
    }

}
