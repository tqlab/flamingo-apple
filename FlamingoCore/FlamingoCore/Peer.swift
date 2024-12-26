//
//  Peer.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/24.
//
import Foundation
internal import NIOCore
import Network

public struct PeerId {
    var id: Data
}

public class Peer {
    var id: PeerId
    var channel: Channel
    var crypto: Crypto
    var superNode: Bool
    var lastActiveTime: Int32

    init(
        id: PeerId, channel: Channel, crypto: Crypto,
        superNode: Bool
    ) {
        self.id = id
        self.channel = channel
        self.crypto = crypto
        self.superNode = superNode
        self.lastActiveTime = Int32(Date().timeIntervalSince1970)
    }

    public func isSuperNode() -> Bool {
        return superNode
    }

    public func updateActiveTime() {
        self.lastActiveTime = Int32(Date().timeIntervalSince1970)
    }

    public func getActiveTime() -> Int32 {
        return self.lastActiveTime
    }
}

class Peers {
    private var peers: [String: Peer]
    private let superNodeIp: String

    init(superNodeIp: String) {
        self.peers = Dictionary()
        self.superNodeIp = superNodeIp
    }

    public func createPeer(
        ip: String,
        id: PeerId, channel: Channel, crypto: Crypto,
        superNode: Bool
    ) -> Peer {
        let peer = Peer(
            id: id,
            channel: channel, crypto: crypto,
            superNode: superNode)
        self.peers[ip] = peer
        return peer
    }

    public func findPeer(ip: String) -> Peer? {
        guard let peer = self.peers[ip] else {
            return self.peers[self.superNodeIp]
        }
        return peer
    }

    public func findPeerWithoutDefault(ip: String) -> Peer? {
        return self.peers[ip]
    }

    public func getAll() -> [Peer] {
        return Array(self.peers.values)
    }
}
