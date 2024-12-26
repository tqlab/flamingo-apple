//
//  Dns.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/25.
//
import Foundation
import Network

public class Dns {

    public static func isIpAddress(str: String) -> Bool {

        var sin = sockaddr_in()
        var sin6 = sockaddr_in6()

        if str.withCString({ cstring in
            inet_pton(AF_INET6, cstring, &sin6.sin6_addr)
        }) == 1 {
            // IPv6 peer.
            return true
        } else if str.withCString({ cstring in
            inet_pton(AF_INET, cstring, &sin.sin_addr)
        }) == 1 {
            // IPv4 peer.
            return true
        }

        return false
    }

    public static func parse(domain: String) throws -> [String] {

        // ip 解析
        var ipList: [String] = []

        let host = CFHostCreateWithName(nil, domain as CFString)
            .takeRetainedValue()

        CFHostStartInfoResolution(host, .addresses, nil)

        var success: DarwinBoolean = false

        if let addresses = CFHostGetAddressing(host, &success)?
            .takeUnretainedValue() as NSArray?
        {

            for case let theAddress as NSData in addresses {

                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))

                if getnameinfo(
                    theAddress.bytes.assumingMemoryBound(to: sockaddr.self),
                    socklen_t(theAddress.length),
                    &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST
                ) == 0 {

                    ipList.append(String(cString: hostname))
                }
            }
        }

        return ipList
    }
}
