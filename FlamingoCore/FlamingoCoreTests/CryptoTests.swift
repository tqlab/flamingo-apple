//
//  CryptoTests.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/12.
//

import Testing
import Foundation
@testable import FlamingoCore

struct CryptoTests {
    
    @Test func testEncryptDecrypt() async throws {
        let priKey1 = Crypto.createEcdhKeypair()
        let priKey2 = Crypto.createEcdhKeypair()
        
        let sender = try Crypto(privateKey: priKey1, algorithmType: AlgorithmType.AES_GCM_128, publicKey: priKey2.publicKey.rawRepresentation)
        let receiver = try Crypto(privateKey: priKey2, algorithmType: AlgorithmType.AES_GCM_128, publicKey: priKey1.publicKey.rawRepresentation)
    
        let encrypt = try sender.encrypt(data: Data("abc".utf8))
        let plain = try receiver.decrypt(data: encrypt);
        let s = String(decoding: plain, as: UTF8.self)
        print("\(s)")
    }

    @Test func testSpeed() async throws {
        let speed = try Crypto.testSpeed(algorithmType: AlgorithmType.AES_GCM_128, maxNanoTime: 100_000_000)
        print("AES_GCM_128: \(String(format: "%.1f MiB/s", speed))")
        let speed2 = try Crypto.testSpeed(algorithmType: AlgorithmType.AES_GCM_256, maxNanoTime: 100_000_000)
        print("AES_GCM_256: \(String(format: "%.1f MiB/s", speed2))")
        let speed3 = try Crypto.testSpeed(algorithmType: AlgorithmType.CHACHA20_POLY1305, maxNanoTime: 100_000_000)
        print("CHACHA20_POLY1305: \(String(format: "%.1f MiB/s", speed3))")
    }

}
