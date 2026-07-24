// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

enum TunnelStateLogDescription {
    static func describe(_ state: TunnelState) -> String {
        switch state {
        case .disconnected:
            return "disconnected"
        case .connecting(let candidates):
            return "connecting candidates=\(describe(candidates))"
        case .tlsHandshaking(let via):
            return "tls_handshaking via=\(describe(via))"
        case .awaitingBroker(let via):
            return "awaiting_broker via=\(describe(via))"
        case .connected(let via):
            return "connected via=\(describe(via))"
        case .failed(let error):
            return "failed error=\(describe(error))"
        }
    }

    static func describe(_ candidates: [ConnectedVia]) -> String {
        candidates.map { describe($0) }.joined(separator: ", ")
    }

    static func describe(_ via: ConnectedVia) -> String {
        switch via {
        case .lanDirect(let host, let port):
            return "lan \(host):\(port)"
        case .relay(let endpoint):
            let scheme = endpoint.scheme ?? "unknown"
            let host = endpoint.host ?? "unknown"
            let port = endpoint.port.map(String.init) ?? "default"
            return "relay \(scheme)://\(host):\(port)"
        }
    }

    static func describe(_ error: SessionError) -> String {
        switch error {
        case .unreachable:
            return "unreachable"
        case .tlsFailed:
            return "tlsFailed"
        case .revoked:
            return "revoked"
        case .authRefreshRequired:
            return "authRefreshRequired"
        case .notEntitled:
            return "notEntitled"
        case .notConnected:
            return "notConnected"
        case .directKeepaliveMissed:
            return "directKeepaliveMissed"
        case .relayKeepaliveMissed:
            return "relayKeepaliveMissed"
        case .transportFailed(let reason):
            return "transportFailed(\(reason))"
        case .inboundClosed(let fault):
            return "inboundClosed(fault=\(fault ?? "nil"))"
        }
    }
}
