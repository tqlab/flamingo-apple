//
//  CryptoTests.swift
//  FlamingoCore
//
//  Created by wangjuan on 2024/12/12.
//

import Testing
@testable import FlamingoCore

struct CryptoTests {

    @Test func testSpeed() async throws {
        let speed = try Crypto.testSpeed(algorithmType: AlgorithmType.AES_GCM_128, maxNanoTime: 100_000_000)
        print("AES_GCM_128: \(String(format: "%.1f MiB/s", speed))")
        let speed2 = try Crypto.testSpeed(algorithmType: AlgorithmType.AES_GCM_256, maxNanoTime: 100_000_000)
        print("AES_GCM_256: \(String(format: "%.1f MiB/s", speed2))")
        let speed3 = try Crypto.testSpeed(algorithmType: AlgorithmType.CHACHA20_POLY1305, maxNanoTime: 100_000_000)
        print("CHACHA20_POLY1305: \(String(format: "%.1f MiB/s", speed3))")
    }

}
