//
//  IpPacketTests.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/26.
//

import Foundation
import Network
import Testing

@testable import FlamingoCore

struct IpPacketTests {

    @Test func testIp() async throws {
        let address = IPv6Address("ff06:0:0:0:0:0:0:c3")!
        let data: Data = address
            .rawValue.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                return Data(Array(ptr))
            }
        let s = bytesToIpv6String(bytes: data)!
        assert(s == "ff06::c3")
        print("\(s)")
    }

}
