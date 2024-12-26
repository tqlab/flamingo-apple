//
//  DnsTests.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/25.
//

import Testing
import Foundation
@testable import FlamingoCore

struct DnsTests {
    
    @Test func testParse() async throws {
        let ips = try Dns.parse(domain: "baidu.com");
        print("\(ips)")
    }
}
