//
//  EdgeTests.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/22.
//

import Foundation
import Network
import Testing

@testable import FlamingoCore

struct EdgeTests {

    func handleError(error: Error?) {

    }

    func onIp(ip: IPAddress) {

    }

    func onData(data: Data) {

    }

    @Test func test() async throws {
        let config = PeerConfig(
            password: "test", host: "172.16.89.128", port: 9527, listen: 9527)
        let edge = try Edge(
            config: config, onIp: onIp, onData: onData,
            pendingCompletion: handleError)
        try edge.writeData(data: Data.random(length: 1024))

        try await Task.sleep(nanoseconds: UInt64(600_000_000_000))
    }

}
