//
//  ViewController.swift
//  ExampleApp
//
//  Created by Daniel Egger on 17/08/2017.
//

import UIKit
import SwiftJOSE

class ViewController: UIViewController {

    let message = "The true sign of intelligence is not knowledge but imagination."
    let privateKeyTag = "com.airsidemobile.SwiftJOSE.testPrivateKey"
    var privateKey: SecKey?
    var publicKey: SecKey?
    var symmetricKey: SecKey?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        setupKeys()
        
        demoJWS()
        demoJWE()
    }
    
    func demoJWS() {
        guard publicKey != nil, privateKey != nil else {
            return
        }
        
        print("\n========== JWS ==========\n")
        print("Message:\n\(message)\n")
        
        let header = JWSHeader(algorithm: .RS512)
        let payload = Payload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey!)
     
        guard let firstJWS = JWS(header: header, payload: payload, signer: signer) else {
            print("Could not create JWS.")
            return
        }
        
        let serialized = firstJWS.compactSerialized
        
        print("JWS:\n\(serialized)\n")
        
        guard let secondJWS = try? JWS(compactSerialization: serialized) else {
            print("Could not parse JWS.")
            return
        }
        
        let verifier = RSAVerifier(key: publicKey!)
        if secondJWS.validates(against: verifier) {
            print("Signature correct.")
        } else {
            print("Signature wrong.")
        }
    }
    
    func demoJWE() {
        guard publicKey != nil, privateKey != nil else {
            return
        }
        
        print("\n========== JWE ==========\n")
        print("Message:\n\(message)\n")
        
        let header = JWEHeader(algorithm: .RSAOAEP, encryptionAlgorithm: .AESGCM256)
        let payload = Payload(message.data(using: .utf8)!)
        guard let encrypter = try? Encrypter(keyEncryptionAlgorithm: .RSAOAEP, keyEncryptionKey: publicKey!, contentEncyptionAlgorithm: .AESGCM256, contentEncryptionKey: symmetricKey!) else {
            print("Could not create Encrypter.")
            return
        }
        guard let firstJwe = JWE(header: header, payload: payload, encrypter: encrypter) else {
            print("Could not create JWE.")
            return
        }
        let compactSerializationFirstJWE = firstJwe.compactSerialized
        
        print("Serialized:\n\(compactSerializationFirstJWE)\n")
        
        guard let secondJWE = try? JWE(compactSerialization: compactSerializationFirstJWE) else {
            print("Could not parse JWE.")
            return
        }
        
        print("Deserialized:\n\(secondJWE)\n")
        
        guard let decrypter = try? Decrypter(keyDecryptionAlgorithm: .RSAOAEP, keyDecryptionKey: privateKey!) else {
            print("Could not create Decrypter.")
            return
        }
        if let payload = secondJWE.decrypt(with: decrypter) {
            print("Plaintext:\n\(String(data: payload.data(), encoding: .utf8)!)\n")
        }
    }

    private func setupKeys() {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: privateKeyTag
            ]
        ]
            
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print("\(error!)")
            return
        }
        
        privateKey = secKey
        publicKey = SecKeyCopyPublicKey(secKey)
        symmetricKey = secKey
    }
}
