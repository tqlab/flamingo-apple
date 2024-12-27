import CryptoKit
//
//  Edge.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/25.
//
import Foundation
internal import NIOCore
internal import NIOPosix
import Network
import os.log

public enum EdgeError: Error {
    case connectionFailed
}

///
/// 握手
///
private func handshake(
    log: OSLog,
    id: PeerId,
    channel: Channel,
    socketAddress: SocketAddress,
    signature: Signature,
    algorithms: [Algorithm],
    publicKey: Data
) {
    do {
        let data = try Protocol.buildHandshakeRequest(
            signature: signature,
            id: id,
            publicKey: publicKey,
            algorithms: algorithms)

        let buffer = channel.allocator.buffer(bytes: data.bytes)
        let envelope = AddressedEnvelope<ByteBuffer>(
            remoteAddress: socketAddress, data: buffer)

        channel.writeAndFlush(
            NIOAny(envelope),
            promise: nil
        )

        os_log(.debug, log: log, "Send handshake packet: \(socketAddress)")

    } catch {
        os_log(
            .error, log: log, "Handshake error: %{public}@",
            "\(error)"
        )
    }
}

public class Edge {
    private static let log = OSLog(
        subsystem: "net.dighole.flamingo", category: "network")
    private static let queue = DispatchQueue(
        label: "net.dighole.flamingo", attributes: .concurrent)
    // 每一个edge都有一个公私钥对，公钥将通过handshake包发送给远端，用于协商对称密钥，用于加解密
    private static let privateKey: Curve25519.KeyAgreement.PrivateKey =
        Crypto.createEcdhKeypair()
    private static let id: PeerId = PeerId(id: UUID().data)
    private static let algorithms: [Algorithm] = calculateAlgorithm()
    private let group = MultiThreadedEventLoopGroup(
        numberOfThreads: System.coreCount)
    private let bootstrap: DatagramBootstrap
    private let signature: Signature
    private let peers: Peers

    // 握手定时任务
    private let handshakeTimer: DispatchSourceTimer
    // 心跳定时任务
    private let heartbeatTimer: DispatchSourceTimer
    private let channel: Channel

    init(
        config: PeerConfig,
        onIp: @escaping ((IPAddress) -> Void),
        onData: @escaping ((Data) -> Void),
        pendingCompletion: @escaping ((Error?) -> Void)
    )
        throws
    {
        let address = try SocketAddress.makeAddressResolvingHost(
            config.host, port: Int(config.port))
        let superNodeIp = address.ipAddress!
        self.peers = Peers(superNodeIp: superNodeIp)

        self.handshakeTimer = DispatchSource.makeTimerSource(queue: Edge.queue)
        self.heartbeatTimer = DispatchSource.makeTimerSource(queue: Edge.queue)

        let signature = try Signature(password: config.password)
        self.signature = signature
        let handler = UDPClientHandler(
            peers: self.peers,
            signature: signature,
            superNodeIp: superNodeIp, onIp: onIp, onData: onData)

        self.bootstrap = DatagramBootstrap(group: group)
            // Enable SO_REUSEADDR.
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            //.channelOption(.socketOption(.ipv6_v6only), value: 0)
            .channelInitializer { (channel) -> EventLoopFuture<Void> in
                channel.pipeline.addHandler(handler)
            }

        // 本地监听一个端口，用于P2P通信
        switch address {
        case .v4:
            self.channel =
                try bootstrap.bind(host: "0.0.0.0", port: Int(config.port))
                .wait()
        case .v6:
            self.channel =
                try bootstrap.bind(host: "::1", port: Int(config.port))
                .wait()
        case .unixDomainSocket:
            throw EdgeError.connectionFailed
        }

        // 加入等待握手的队列
        peers.addPendingPeer(ip: superNodeIp, port: Int(config.port))

        // 握手定时任务
        handshakeTimer.schedule(
            deadline: .now(), repeating: .seconds(10))
        handshakeTimer.setEventHandler {
            self.handshake()
        }
        handshakeTimer.activate()

        // 心跳定时任务
        heartbeatTimer.schedule(
            deadline: .now() + 10.0, repeating: .seconds(10))
        heartbeatTimer.setEventHandler {
            self.heartbeat()
        }
        heartbeatTimer.activate()

    }

    public func writeData(data: Data) throws {
        if let ipPacket = SimpleIpPacket(data: data) {

            if let peer = findPeer(ip: ipPacket.destation) {

                let data = try Protocol.buildData(
                    crypto: peer.crypto, data: data)
                peer.writeAndFlush(data)

                os_log(
                    .debug, log: Edge.log,
                    "src: \(ipPacket.source) -> dest: \(ipPacket.destation).")

            }
        }
    }

    public func close() throws {
        for peer in self.peers.findValidPeers() {
            //peer.
            let data = try Protocol.buildClose(
                crypto: peer.crypto, id: Edge.id)
            peer.writeAndFlush(data)
            os_log(
                .info, log: Edge.log,
                "Send close packet to peer: \(peer.getIp()).")
        }
        sleep(1)
        try self.channel.closeFuture.wait()
        try self.group.syncShutdownGracefully()
    }

    private func findPeer(ip: String) -> Peer? {
        // 如果当前目标ip属于子网ip，则先查找是否有p2p的通信节点，如果没有，则通过supernode查找，如果有，则直接通信
        if self.peers.isSubnet(ip: ip) {
            if let peer = self.peers.findPeerWithoutDefault(ip: ip) {
                return peer
            } else {
                //
                self.peerQuery(ip: ip)
                return self.peers.findDefaultPeer()
            }
        }
        // 如果不属于子网ip，则使用supernode通信
        else {
            return self.peers.findDefaultPeer()
        }
    }

    ///
    /// Peer 查询
    ///
    private func peerQuery(ip: String) {
        do {
            if let peer = self.peers.findDefaultPeer() {
                let data = try Protocol.buildPeerQuery(
                    crypto: peer.crypto, id: Edge.id, ip: ip)
                peer.writeAndFlush(data)
                os_log(.info, log: Edge.log, "Peer query \(ip).")

            }
        } catch {
            os_log(
                .error, log: Edge.log, "Peer query error: %{public}@",
                "\(error)"
            )
        }
    }

    private func handshake() {
        do {
            for pendingPeer in peers.getPendingPeers() {

                // handshake
                let address = try SocketAddress(
                    ipAddress: pendingPeer.ip, port: pendingPeer.port)
                FlamingoCore.handshake(
                    log: Edge.log,
                    id: Edge.id,
                    channel: self.channel, socketAddress: address,
                    signature: self.signature, algorithms: Edge.algorithms,
                    publicKey: Edge.privateKey.publicKey.rawRepresentation)
            }
        } catch {
            os_log(
                .error, log: Edge.log, "Handshake error: %{public}@", "\(error)"
            )
        }

    }

    ///
    /// 发送心跳包
    ///
    private func heartbeat() {
        // send heartbeat
        do {

            for peer in self.peers.findValidPeers() {
                let data = try Protocol.buildPing(
                    crypto: peer.crypto, id: Edge.id)
                peer.writeAndFlush(data)
            }
            os_log(.info, log: Edge.log, "Send heartbeat packet.")

        } catch {
            os_log(
                .error, log: Edge.log, "Heartbeat error: %{public}@", "\(error)"
            )
        }

    }

    private final class UDPClientHandler: ChannelDuplexHandler {
        public typealias OutboundIn = AddressedEnvelope<ByteBuffer>
        public typealias InboundIn = AddressedEnvelope<ByteBuffer>
        public typealias OutboundOut = AddressedEnvelope<ByteBuffer>

        private var receiveBuffer: ByteBuffer = ByteBuffer()
        private var peers: Peers
        private var signature: Signature
        private var superNodeIp: String
        // 握手成功的回调方法，根据握手返回的ip设置到虚拟网卡中
        private var onIp: ((IPAddress) -> Void)
        // 收到网络数据包的回调方法，用于写回虚拟网卡
        private var onData: ((Data) -> Void)

        init(
            peers: Peers,
            signature: Signature,
            superNodeIp: String,
            onIp: @escaping ((IPAddress) -> Void),
            onData: @escaping ((Data) -> Void)
        ) {
            self.peers = peers
            self.signature = signature
            self.superNodeIp = superNodeIp
            self.onIp = onIp
            self.onData = onData
        }

        public func write(
            context: ChannelHandlerContext, data: NIOAny,
            promise: EventLoopPromise<Void>?
        ) {
            context.write(data, promise: promise)
        }

        public func channelActive(context: ChannelHandlerContext) {
            context.fireChannelActive()
        }

        public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            context.fireChannelActive()
            var unwrappedInboundData = self.unwrapInboundIn(data)

            receiveBuffer.clear()
            receiveBuffer.writeBuffer(&unwrappedInboundData.data)

            guard
                let bytes = receiveBuffer.readBytes(
                    length: receiveBuffer.readableBytes)
            else {
                return
            }
            let remoteAddress = unwrappedInboundData.remoteAddress

            let type = bytes[0]
            switch type {
            case 1:
                do {

                    let response = try Protocol.parseHandshakeResponse(
                        signature: self.signature, data: Data(bytes[1...]))
                    let publicKey = response.publicKeyData
                    let algorithmType = AlgorithmType.fromCode(
                        code: response.algorithm.algorithmType.rawValue)
                    guard let type = algorithmType else { return }
                    // 握手成功，初始化加密套件，用于后续数据的加密操作
                    let crypto = try Crypto(
                        privateKey: privateKey, algorithmType: type,
                        publicKey: publicKey)

                    // 清理待握手的列表
                    let ip = remoteAddress.ipAddress!
                    peers.removePendingPeer(ip: ip)

                    let port = remoteAddress.port!
                    let superNode = self.superNodeIp == ip

                    if superNode {
                        self.peers.gateway = response.gateway
                        self.peers.cidr = response.cidr
                        let peer = self.peers.createPeer(
                            id: PeerId(id: response.id), ip: response.gateway,
                            port: port,
                            natIp: ip,
                            channel: context.channel, crypto: crypto,
                            superNode: superNode)
                        // 如果是与superNode握手完成，则给本地申请vpn ip
                        let data = try Protocol.buildApplyIp(
                            crypto: peer.crypto, id: Edge.id, ip: nil)
                        peer.writeAndFlush(data)
                    } else {
                        let _ = self.peers.createPeer(
                            id: PeerId(id: response.id), ip: response.ip,
                            port: port,
                            natIp: ip,
                            channel: context.channel, crypto: crypto,
                            superNode: superNode)
                    }

                    os_log(
                        .info, log: log,
                        "Handshake successfully! \(type.toString())")

                } catch {
                    os_log(
                        .error, log: log,
                        "Parse handshake response error: \(error)")
                }
            case 2:
                // supernode拒绝，需要重新握手
                FlamingoCore.handshake(
                    log: Edge.log,
                    id: Edge.id,
                    channel: context.channel,
                    socketAddress: remoteAddress,
                    signature: self.signature, algorithms: Edge.algorithms,
                    publicKey: Edge.privateKey.publicKey.rawRepresentation)
            case 3:
                // 申请ip成功后，需要将ip设置到本地的虚拟网卡中
                do {
                    let ip = remoteAddress.ipAddress!
                    guard let peer = self.peers.findPeerWithoutDefault(ip: ip)
                    else { return }

                    let applyIp = try Protocol.parseApplyIp(
                        crypto: peer.crypto, data: Data(bytes[1...]))
                    if let iPAddress = IPv4Address(applyIp.ip) {
                        self.onIp(iPAddress)
                    }

                    os_log(
                        .info, log: log,
                        "Received new ip address! \(applyIp.ip)")
                } catch {
                    os_log(
                        .error, log: log, "Decrypt data error: \(error)")
                }
            case 5:
                // 心跳包处理
                do {
                    let ip = remoteAddress.ipAddress!
                    guard let peer = self.peers.findPeerWithoutDefault(ip: ip)
                    else { return }
                    peer.updateActiveTime()

                    let pong = try Protocol.parsePong(
                        crypto: peer.crypto, data: Data(bytes[1...]))

                    os_log(
                        .info, log: log,
                        "Received pong. timestamp: \(pong.ts)"
                    )

                } catch {
                    os_log(
                        .error, log: log, "Decrypt data error: \(error)")
                }
            case 9:
                // 处理数据包
                do {
                    let ip = remoteAddress.ipAddress!
                    guard let peer = self.peers.findPeerWithoutDefault(ip: ip)
                    else { return }

                    let plainData = try peer.crypto.decrypt(
                        data: Data(bytes[1...]))
                    self.onData(plainData)
                } catch {
                    os_log(.error, log: log, "Decrypt data error: \(error)")
                }
            case 0x20:
                do {
                    guard let peer = self.peers.findDefaultPeer() else {
                        return
                    }
                    let query = try Protocol.parsePeerQuery(
                        crypto: peer.crypto, data: Data(bytes[1...]))
                    //
                    os_log(
                        .info, log: log, "Received peer. query: %{public}@",
                        "\(query)")

                    // 加入等待握手的队列
                    peers.addPendingPeer(ip: query.natIp, port: Int(query.port))

                } catch {
                    os_log(.error, log: log, "Decrypt data error: \(error)")
                }
            case 0xFF:
                // 主动关闭链接，清理数据
                let ip = remoteAddress.ipAddress!
                peers.removePeer(ip: ip)
            default:
                os_log(.error, log: log, "Unknown type: \(type)")
            }
        }

    }

    private static func calculateAlgorithm() -> [Algorithm] {
        var algorithms: [Algorithm] = Array()

        do {
            let speed = try Crypto.testSpeed(
                algorithmType: AlgorithmType.AES_GCM_128,
                maxNanoTime: 100_000_000)
            let speed2 = try Crypto.testSpeed(
                algorithmType: AlgorithmType.AES_GCM_256,
                maxNanoTime: 100_000_000)
            let speed3 = try Crypto.testSpeed(
                algorithmType: AlgorithmType.CHACHA20_POLY1305,
                maxNanoTime: 100_000_000)
            let a1 = Algorithm(type: AlgorithmType.AES_GCM_128, speed: speed)
            let a2 = Algorithm(type: AlgorithmType.AES_GCM_256, speed: speed2)
            let a3 = Algorithm(
                type: AlgorithmType.CHACHA20_POLY1305, speed: speed3)

            os_log(
                .info, log: log,
                "AES_GCM_128: \(String(format: "%.1f MiB/s", speed)), AES_GCM_256: \(String(format: "%.1f MiB/s", speed2)), CHACHA20_POLY1305: \(String(format: "%.1f MiB/s", speed3))"
            )

            algorithms.append(a1)
            algorithms.append(a2)
            algorithms.append(a3)
        } catch {
            os_log(.error, log: log, "Crypto test speed error: \(error)")
        }

        return algorithms
    }
}
