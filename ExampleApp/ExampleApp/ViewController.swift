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
    }
    
    func demoJWS() {
        print("Message:\n\(message)\n")
        
        let header = JWSHeader(algorithm: .rs512)
        let payload = JWSPayload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey)
        let firstJWS = JWS(header: header, payload: payload, signer: signer)
        let compactSerialization = firstJWS.compactSerialized
        
        print("Serialized:\n\(compactSerialization)\n")
        
        let secondJWS = JWS(compactSerialization: compactSerialization)
        let verifier =  RSAVerifier(key: publicKey)
        if secondJWS.validates(against: verifier) {
            print("Deserialized:\n\(secondJWS)\n")
        }
        
        let justTheHeader = Deserializer().deserialize(JWSHeader.self, fromCompactSerialization: compactSerialization)
        print("Just The Header:\n\(justTheHeader)\n")
        let justThePayload = Deserializer().deserialize(JWSPayload.self, fromCompactSerialization: compactSerialization)
        print("Just The Payload:\n\(justThePayload)")
    }

}
