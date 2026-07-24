// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import os

private let logger = SPLLogging.logger(for: .dial)

public enum DialError: Error, Equatable, Sendable {
    case invalidPort(Int)
    case invalidRelayURL(String)
    case connectTimeout
    case connectionFailed(String)
    case sendFailed(String)
    case receiveFailed(String)
    case unexpectedTextFrame
    case relayUnauthorized
    case relayNotEntitled
    /// Relay closed the WebSocket with clean close code 4401 "unauthorized" (`tokens.md:260`).
    case relayCloseUnauthorized
    /// Pair-dial received the protocol's uniform coarse 401 for no-window/closed/consumed/limiter states (`session.md:239`, `pair-window.md:108`).
    case pairingWindowClosed
    case relayInstanceUnknown
    case wsHandshakeFailed(httpStatus: Int?)
}

public enum DialClient {
    public static func dial(
        _ endpoint: TransportEndpoint,
        clientInfo: SPLClientInfo,
        timeout: Duration = .seconds(5)
    ) async throws -> any ByteTransport {
        switch endpoint {
        case .lan(let host, let port, _, _):
            return try await dialLAN(host: host, port: port, timeout: timeout)
        case .relay(let endpoint, let instanceID, let deviceToken):
            return try await dialRelay(
                endpoint: endpoint,
                instanceID: instanceID,
                authToken: deviceToken,
                path: "session/dial",
                clientInfo: clientInfo,
                timeout: timeout
            )
        }
    }

    static func dialPairRelay(
        endpoint: URL,
        pairKey: PairWindowRelayKey,
        clientInfo: SPLClientInfo,
        timeout: Duration = .seconds(5)
    ) async throws -> any ByteTransport {
        return try await dialRelay(
            endpoint: endpoint,
            credential: .pair(pairKey: pairKey),
            path: "session/pair-dial",
            clientInfo: clientInfo,
            timeout: timeout
        )
    }

    private static func dialLAN(host: String, port: Int, timeout: Duration) async throws -> LANTransport {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)), 1...65535 ~= port else {
            throw DialError.invalidPort(port)
        }

        let startedAt = ContinuousClock.now
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        let transport = LANTransport(connection: connection)

        do {
            try await withTimeout(timeout) {
                try await startAndWaitReady(connection)
            }
            let elapsed = startedAt.duration(to: .now).milliseconds
            logger.debug("connected transport=\("lan", privacy: .public) duration_ms=\(elapsed, privacy: .public)")
            return transport
        } catch DialError.connectTimeout {
            await transport.close()
            throw DialError.connectTimeout
        } catch {
            await transport.close()
            throw DialError.connectionFailed(error.localizedDescription)
        }
    }

    private static func dialRelay(
        endpoint: URL,
        instanceID: String,
        authToken: String,
        path: String,
        clientInfo: SPLClientInfo,
        timeout: Duration
    ) async throws -> RelayWSTransport {
        try await dialRelay(
            endpoint: endpoint,
            credential: .session(instanceID: instanceID, authToken: authToken),
            path: path,
            clientInfo: clientInfo,
            timeout: timeout
        )
    }

    private static func dialRelay(
        endpoint: URL,
        credential: RelayCredential,
        path: String,
        clientInfo: SPLClientInfo,
        timeout: Duration
    ) async throws -> RelayWSTransport {
        let transport = try RelayWSTransport(
            endpoint: endpoint,
            credential: credential,
            path: path,
            clientInfo: clientInfo
        )
        let startedAt = ContinuousClock.now

        do {
            try await withTimeout(timeout) {
                try await transport.open()
            }
            let elapsed = startedAt.duration(to: .now).milliseconds
            logger.debug("connected transport=\("relay", privacy: .public) duration_ms=\(elapsed, privacy: .public)")
            return transport
        } catch {
            await transport.close()
            throw error
        }
    }
}

actor LANTransport: ByteTransport {
    nonisolated let transportKind = "lan"

    private let connection: NWConnection
    private var closed = false

    init(connection: NWConnection) {
        self.connection = connection
    }

    func send(_ data: Data) async throws {
        guard !closed else {
            throw DialError.sendFailed("transport closed")
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: DialError.sendFailed(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func receive() async throws -> Data? {
        guard !closed else {
            return nil
        }

        return try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: DialError.receiveFailed(error.localizedDescription))
                    return
                }
                if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                    return
                }
                if isComplete {
                    continuation.resume(returning: nil)
                    return
                }
                continuation.resume(returning: nil)
            }
        }
    }

    func close() async {
        guard !closed else {
            return
        }
        closed = true
        connection.cancel()
    }
}

actor RelayWSTransport: ByteTransport {
    nonisolated let transportKind = "relay"

    private let session: URLSession
    private let delegate: WebSocketOpenDelegate
    private let task: URLSessionWebSocketTask
    private var closed = false

    init(endpoint: URL, credential: RelayCredential, path: String, clientInfo: SPLClientInfo) throws {
        let request = try Self.makeRequest(
            endpoint: endpoint,
            path: path,
            credential: credential,
            clientInfo: clientInfo
        )
        let delegate = WebSocketOpenDelegate(failureMode: credential.failureMode)
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        let task = session.webSocketTask(with: request)

        self.session = session
        self.delegate = delegate
        self.task = task
    }

    func open() async throws {
        let cancellation = WebSocketOpenCancellation(task: task, session: session, delegate: delegate)
        task.resume()
        do {
            try await withTaskCancellationHandler {
                try await delegate.waitForOpen()
            } onCancel: {
                cancellation.cancel()
            }
        } catch let error as DialError {
            throw Self.openFailureError(
                error,
                taskCloseCode: task.closeCode.rawValue,
                recordedCloseCode: delegate.recordedCloseCode
            )
        } catch {
            throw Self.openFailureError(
                error,
                taskCloseCode: task.closeCode.rawValue,
                recordedCloseCode: delegate.recordedCloseCode
            )
        }
    }

    func send(_ data: Data) async throws {
        guard !closed else {
            throw DialError.sendFailed("transport closed")
        }
        do {
            try await task.send(.data(data))
        } catch let error as DialError {
            throw error
        } catch {
            if let closeError = relayCloseError() {
                throw closeError
            }
            throw DialError.sendFailed(error.localizedDescription)
        }
    }

    func receive() async throws -> Data? {
        guard !closed else {
            return nil
        }
        do {
            switch try await task.receive() {
            case .data(let data):
                return data
            case .string:
                throw DialError.unexpectedTextFrame
            @unknown default:
                throw DialError.receiveFailed("unknown websocket message")
            }
        } catch let error as DialError {
            throw error
        } catch {
            if let closeError = relayCloseError() {
                throw closeError
            }
            throw DialError.receiveFailed(error.localizedDescription)
        }
    }

    func close() async {
        guard !closed else {
            return
        }
        closed = true
        task.cancel(with: .normalClosure, reason: nil)
        session.invalidateAndCancel()
    }

    static func makeRequest(
        endpoint: URL,
        path: String,
        credential: RelayCredential,
        clientInfo: SPLClientInfo
    ) throws -> URLRequest {
        let url = try Self.webSocketURL(endpoint: endpoint, path: path, instanceID: credential.instanceID)
        var request = URLRequest(url: url)
        request.setValue(clientInfo.userAgent, forHTTPHeaderField: "User-Agent")
        switch credential {
        case .session(_, let authToken):
            request.setValue("Bearer \(authToken)", forHTTPHeaderField: "Authorization")
        case .pair(let pairKey):
            request.setValue(pairKey.secPairKeyHeaderValue, forHTTPHeaderField: "Sec-Pair-Key")
        }
        return request
    }

    static func webSocketURL(endpoint: URL, path: String, instanceID: String?) throws -> URL {
        guard var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased() else {
            throw DialError.invalidRelayURL(endpoint.absoluteString)
        }

        switch scheme {
        case "https":
            components.scheme = "wss"
        case "http":
            components.scheme = "ws"
        case "wss", "ws":
            components.scheme = scheme
        default:
            throw DialError.invalidRelayURL(endpoint.absoluteString)
        }

        let basePath = components.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let dialPath = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.percentEncodedPath = "/" + [basePath, dialPath].filter { !$0.isEmpty }.joined(separator: "/")
        var queryItems = components.queryItems ?? []
        if let instanceID {
            queryItems.append(URLQueryItem(name: "instance", value: instanceID))
        }
        components.queryItems = queryItems.isEmpty ? nil : queryItems

        guard let url = components.url else {
            throw DialError.invalidRelayURL(endpoint.absoluteString)
        }
        return url
    }

    static func relayCloseReason(forCloseCode code: Int) -> DialError? {
        switch code {
        case 4401:
            return .relayCloseUnauthorized
        default:
            return nil
        }
    }

    static func openFailureError(
        _ error: any Error,
        taskCloseCode: Int,
        recordedCloseCode: Int?
    ) -> any Error {
        if let reason = Self.relayCloseReason(forCloseCode: taskCloseCode) {
            return reason
        }
        if let recordedCloseCode,
           let reason = Self.relayCloseReason(forCloseCode: recordedCloseCode) {
            return reason
        }
        return error
    }

    private func relayCloseError() -> DialError? {
        if let reason = Self.relayCloseReason(forCloseCode: task.closeCode.rawValue) {
            return reason
        }
        if let recorded = delegate.recordedCloseCode {
            return Self.relayCloseReason(forCloseCode: recorded)
        }
        return nil
    }
}

enum RelayCredential: Sendable, Equatable {
    case session(instanceID: String, authToken: String)
    case pair(pairKey: PairWindowRelayKey)

    var instanceID: String? {
        switch self {
        case .session(let instanceID, _):
            return instanceID
        case .pair:
            return nil
        }
    }

    var failureMode: WebSocketOpenDelegate.FailureMode {
        switch self {
        case .session:
            return .session
        case .pair:
            return .pairDial
        }
    }
}

private final class WebSocketOpenCancellation: @unchecked Sendable {
    // why: cancellation may run off actor isolation; URLSession task cancellation is thread-safe and delegate is locked.
    private let task: URLSessionWebSocketTask
    private let session: URLSession
    private let delegate: WebSocketOpenDelegate

    init(task: URLSessionWebSocketTask, session: URLSession, delegate: WebSocketOpenDelegate) {
        self.task = task
        self.session = session
        self.delegate = delegate
    }

    func cancel() {
        task.cancel()
        session.invalidateAndCancel()
        delegate.cancelOpen()
    }
}

// why: URLSession invokes delegate callbacks outside actor isolation; access is guarded by NSLock.
final class WebSocketOpenDelegate: NSObject, URLSessionWebSocketDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    enum FailureMode: Sendable, Equatable {
        case session
        case pairDial
    }

    private let lock = NSLock()
    private let failureMode: FailureMode
    private var continuation: CheckedContinuation<Void, Error>?
    private var result: Result<Void, Error>?
    private var closeCode: Int?

    init(failureMode: FailureMode = .session) {
        self.failureMode = failureMode
    }

    var recordedCloseCode: Int? {
        lock.withLock { closeCode }
    }

    func waitForOpen() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let result: Result<Void, Error>? = lock.withLock {
                if let result = self.result {
                    return result
                }
                self.continuation = continuation
                return nil
            }

            if let result {
                continuation.resume(with: result)
            }
        }
    }

    func urlSession(
        _: URLSession,
        webSocketTask _: URLSessionWebSocketTask,
        didOpenWithProtocol _: String?
    ) {
        complete(.success(()))
    }

    func urlSession(
        _: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: (any Error)?
    ) {
        guard let error else {
            return
        }
        complete(.failure(Self.mapFailure(error: error, task: task, failureMode: failureMode)))
    }

    func urlSession(
        _: URLSession,
        webSocketTask _: URLSessionWebSocketTask,
        didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
        reason _: Data?
    ) {
        lock.withLock {
            self.closeCode = closeCode.rawValue
        }
        if let reason = RelayWSTransport.relayCloseReason(forCloseCode: closeCode.rawValue) {
            complete(.failure(reason))
        }
    }

    func cancelOpen() {
        complete(.failure(DialError.connectionFailed("cancelled")))
    }

    private func complete(_ result: Result<Void, Error>) {
        let continuation = lock.withLock {
            guard self.result == nil else {
                return nil as CheckedContinuation<Void, Error>?
            }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume(with: result)
    }

    private static func mapFailure(error: any Error, task: URLSessionTask, failureMode: FailureMode) -> any Error {
        let nsError = error as NSError
        let response = (task.response as? HTTPURLResponse)
            ?? (nsError.userInfo["NSErrorFailingURLResponseKey"] as? HTTPURLResponse)

        guard let status = response?.statusCode else {
            return DialError.connectionFailed(error.localizedDescription)
        }

        switch status {
        case 401 where failureMode == .pairDial:
            return DialError.pairingWindowClosed
        case 401, 403:
            return DialError.relayUnauthorized
        case 402:
            return DialError.relayNotEntitled
        case 404:
            return DialError.relayInstanceUnknown
        default:
            return DialError.wsHandshakeFailed(httpStatus: status)
        }
    }
}

private final class ConnectionReadyWaiter: @unchecked Sendable {
    // why: NWConnection state callbacks may race cancellation; NSLock ensures exactly one continuation resume.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var result: Result<Void, Error>?

    func wait() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let result: Result<Void, Error>? = lock.withLock {
                if let result = self.result {
                    return result
                }
                self.continuation = continuation
                return nil
            }

            if let result {
                continuation.resume(with: result)
            }
        }
    }

    func complete(_ result: Result<Void, Error>) {
        let continuation = lock.withLock {
            guard self.result == nil else {
                return nil as CheckedContinuation<Void, Error>?
            }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume(with: result)
    }
}

private func startAndWaitReady(_ connection: NWConnection) async throws {
    let waiter = ConnectionReadyWaiter()
    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            waiter.complete(.success(()))
        case .failed(let error):
            waiter.complete(.failure(DialError.connectionFailed(error.localizedDescription)))
        case .cancelled:
            waiter.complete(.failure(DialError.connectionFailed("cancelled")))
        case .setup, .waiting, .preparing:
            break
        @unknown default:
            break
        }
    }
    connection.start(queue: .global(qos: .utility))
    try await withTaskCancellationHandler {
        try await waiter.wait()
    } onCancel: {
        connection.cancel()
    }
}

private func withTimeout<T: Sendable>(
    _ timeout: Duration,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw DialError.connectTimeout
        }

        let value = try await group.next()!
        group.cancelAll()
        return value
    }
}

private extension Duration {
    var milliseconds: Int {
        let components = components
        return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    }
}
