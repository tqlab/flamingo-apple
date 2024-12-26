//
//  ProtocolTests.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/22.
//

import Testing
import Foundation
@testable import FlamingoCore

struct ProtocolTests {
    
    @Test func testCalculateHash() async throws {
        let key = Crypto.createEcdhKeypair();
        let r = Signature.calculateHash(key: key.publicKey.rawRepresentation, salt: Data([0,1,2,3]))
        print("r: \(r.toHexString())")
    }
    

}
