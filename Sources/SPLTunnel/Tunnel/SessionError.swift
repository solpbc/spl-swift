// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

public enum SessionError: Error, Equatable, Sendable {
    case unreachable
    case tlsFailed(String)
    case revoked
    case authRefreshRequired
    case notEntitled
}
