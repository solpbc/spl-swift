// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network

/// `NWListener.cancel()` releases the socket asynchronously. Tests that rebind
/// the same port must wait for release or they can race their previous listener
/// and fail the bind with POSIX 48.
func cancelListenerAndWaitForRelease(_ listener: NWListener) async {
    let cancelWaiter = ListenerCancelWaiter()
    listener.stateUpdateHandler = { state in
        switch state {
        case .cancelled, .failed:
            cancelWaiter.complete()
        case .setup, .waiting, .ready:
            break
        @unknown default:
            break
        }
    }
    listener.cancel()
    await cancelWaiter.wait()
}

private final class ListenerCancelWaiter: @unchecked Sendable {
    // why: NWListener state callbacks cross actor/task boundaries; NSLock guards one-shot continuation resume.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var isComplete = false

    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let shouldResume: Bool = lock.withLock {
                if isComplete {
                    return true
                }
                self.continuation = continuation
                return false
            }

            if shouldResume {
                continuation.resume()
            }
        }
    }

    func complete() {
        let continuation = lock.withLock {
            guard !isComplete else {
                return nil as CheckedContinuation<Void, Never>?
            }
            isComplete = true
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume()
    }
}
