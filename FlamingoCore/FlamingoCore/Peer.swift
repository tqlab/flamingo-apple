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

extension PeerId: Equatable {
    static public func == (lhs: PeerId, rhs: PeerId) -> Bool {
        return
            lhs.id == rhs.id
    }
}

extension PeerId: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.id)
    }
}

public struct PendingPeer {
    var ip: String
    var port: Int
}

public class Peer {
    fileprivate var id: PeerId
    // intranet ip
    fileprivate var ip: String
    fileprivate var channel: Channel
    var crypto: Crypto
    fileprivate var superNode: Bool
    fileprivate var lastActiveTime: Int32
    fileprivate var socketAddress: SocketAddress

    init(
        id: PeerId, ip: String,
        port: Int, natIp: String, channel: Channel, crypto: Crypto,
        superNode: Bool
    ) {
        self.id = id
        self.ip = ip
        self.channel = channel
        self.crypto = crypto
        self.superNode = superNode
        self.lastActiveTime = Int32(Date().timeIntervalSince1970)
        self.socketAddress = try! SocketAddress(ipAddress: natIp, port: port)
    }

    public func writeAndFlush(_ data: Data) {
        let buffer = self.channel.allocator.buffer(bytes: data.bytes)
        let envelope = AddressedEnvelope<ByteBuffer>(
            remoteAddress: socketAddress, data: buffer)
        self.channel.writeAndFlush(NIOAny(envelope), promise: nil)

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

    public func getIp() -> String {
        return self.ip
    }
}

extension Peer: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.id)
    }
}

extension Peer: Equatable {
    static public func == (lhs: Peer, rhs: Peer) -> Bool {
        return
            lhs.id == rhs.id
    }
}

class Peers {

    private var pendingPeers: [String: PendingPeer]
    private var peers: [String: Peer]
    private let superNodeIp: String

    var gateway: String?
    var cidr: String?

    init(superNodeIp: String) {
        self.pendingPeers = Dictionary()
        self.peers = Dictionary()
        self.superNodeIp = superNodeIp
    }

    public func createPeer(
        id: PeerId, ip: String, port: Int, natIp: String, channel: Channel,
        crypto: Crypto,
        superNode: Bool
    ) -> Peer {
        let peer = Peer(
            id: id, ip: ip, port: port, natIp: natIp, channel: channel,
            crypto: crypto, superNode: superNode)
        self.peers[natIp] = peer
        self.peers[ip] = peer
        return peer
    }

    public func addPendingPeer(ip: String, port: Int) {
        self.pendingPeers[ip] = PendingPeer(ip: ip, port: port)
    }

    public func getPendingPeers() -> [PendingPeer] {
        return Array(self.pendingPeers.values)
    }

    public func removePendingPeer(ip: String) {
        self.pendingPeers.removeValue(forKey: ip)
    }

    public func addPeer(ip: String, peer: Peer) {
        self.peers[ip] = peer
        return
    }

    public func findPeerWithoutDefault(ip: String) -> Peer? {
        return self.peers[ip]
    }

    public func findDefaultPeer() -> Peer? {
        return self.peers[self.superNodeIp]
    }

    // 删除peer
    public func removePeer(ip: String) {
        if let peer = self.peers[ip] {
            // supernode不可以删除
            if peer.isSuperNode() {
                return
            }

            //
            self.peers.removeValue(forKey: peer.ip)
            self.peers.removeValue(forKey: peer.socketAddress.ipAddress!)
        }

        self.removePendingPeer(ip: ip)
    }

    public func findValidPeers() -> Set<Peer> {
        var peers = Set<Peer>()
        var toBeDeleted: [String] = Array()

        for peer in self.peers.values {
            // 如果超过60秒没有发送心跳包，则会被删除
            if Int32(Date().timeIntervalSince1970) - peer.lastActiveTime > 60 {
                toBeDeleted.append(peer.socketAddress.ipAddress!)
                // 如果是superNode长期失效，则添加到pending队列，待重新握手
                if peer.superNode {
                    self.addPendingPeer(
                        ip: peer.socketAddress.ipAddress!,
                        port: peer.socketAddress.port!)
                }
            } else {
                peers.insert(peer)
            }
        }
        // 清理无效的peer
        for ip in toBeDeleted {
            self.removePeer(ip: ip)
        }
        return peers
    }

    fileprivate func ipv4ToInt(ip: String) -> UInt32? {
        var sin = sockaddr_in()
        if ip.withCString({ cstring in
            inet_pton(AF_INET, cstring, &sin.sin_addr)
        }) == 1 {
            return sin.sin_addr.s_addr
        }
        return nil
    }

    public func isSubnet(ip: String) -> Bool {
        if self.cidr == nil {
            return false
        }
        let cidrComponents = self.cidr!.split(separator: "/")
        if cidrComponents.count == 2 {
            guard let networkInt = self.ipv4ToInt(ip: String(cidrComponents[0]))
            else { return false }
            guard let ipInt = self.ipv4ToInt(ip: ip) else { return false }
            guard let prefixLen = UInt32(cidrComponents[1]) else {
                return false
            }
            if prefixLen > 32 {
                return false
            } else {
                let mask = UInt32.max << (32 - prefixLen)
                return networkInt & mask == ipInt & mask
            }

        }
        return false
    }
}
