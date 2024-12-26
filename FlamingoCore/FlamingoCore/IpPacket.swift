//
//  IpPacket.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/26.
//
import Foundation
import Network

class SimpleIpPacket {
    var version: UInt8
    var source: String
    var destation: String

    init?(data: Data) {
        if data.count < 20 {
            return nil
        }
        let bytes = data.bytes
        let version = bytes[0] >> 4

        self.version = version

        if version == 4 {
            let source = String(
                format: "%d.%d.%d.%d", bytes[12], bytes[13], bytes[14],
                bytes[15])
            let destation = String(
                format: "%d.%d.%d.%d", bytes[16], bytes[17], bytes[18],
                bytes[19])
            self.source = source
            self.destation = destation
        } else if version == 6 {
            if data.count < 28 {
                return nil
            }
            self.source = bytesToIpv6String(
                bytes: Data(bytes[8..<20]))!
            self.destation = bytesToIpv6String(
                bytes: Data(bytes[20..<28]))!
        } else {
            return nil
        }
    }

}

func bytesToIpv6String(bytes: Data) -> String? {
    guard bytes.count == MemoryLayout<in6_addr>.size else {
        return nil
    }
    var address = bytes.withUnsafeBytes({
        (rawBufferPointer: UnsafeRawBufferPointer) -> in6_addr in
        // Convert UnsafeRawBufferPointer to UnsafeBufferPointer<UInt8>
        let bufferPointer = rawBufferPointer.bindMemory(to: UInt8.self)
        // Convert UnsafeBufferPointer<UInt8> to UnsafePointer<UInt8>
        if let bytesPointer = bufferPointer.baseAddress?
            .withMemoryRebound(
                to: UInt8.self, capacity: bytes.count, { return $0 })
        {
            return bytesPointer.withMemoryRebound(
                to: in6_addr.self, capacity: 1
            ) { $0.pointee }
        }
        return in6_addr()
    })

    let length = Int(INET6_ADDRSTRLEN)
    var presentationBytes = [CChar](repeating: 0, count: length)
    guard
        inet_ntop(
            AF_INET6, &address, &presentationBytes, socklen_t(length))
            != nil
    else {
        return nil
    }
    return String(cString: presentationBytes)
}
