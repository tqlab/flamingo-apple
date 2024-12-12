//
//  EdgeTests.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/22.
//


import Testing
@testable import FlamingoCore

struct EdgeTests {
    
    func handleError(error: Error?) {
        
    }

    @Test func test() async throws {
        let config = EdgeConfig(password: "test", host: "172.16.89.128", port: 9527)
        let edge = try Edge(config: config, pendingCompletion: handleError)
        edge.connect()
        
        try await Task.sleep(nanoseconds: UInt64(600_000_000_000))
    }
    

}
