/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine

/// Deduplicates concurrent refresh-token network calls.
///
/// When two or more callers request a refresh for the same credential before the
/// first in-flight request completes, only ONE network request is dispatched.
/// All concurrent callers share the result of that single request.
///
/// Thread safety is provided by `NSLock`. Every code path through `refresh` —
/// including the early-return path that reuses an existing in-flight publisher —
/// is guarded with `defer { lock.unlock() }` placed immediately after `lock.lock()`,
/// so no path can leak the lock regardless of how the function returns.
///
/// Key: `identityURL.absoluteString|refreshToken` (falls back to `accessToken`
/// when `refreshToken` is nil), per REQ-SFR-02.
internal final class SalesforceRefreshCoordinator {

    // MARK: - State

    private let lock = NSLock()
    private var inFlight: [String: AnyPublisher<Credential, Error>] = [:]

    // MARK: - Public API

    /// Returns a publisher that produces a refreshed `Credential`.
    ///
    /// If a refresh for `credential`'s key is already in flight, the existing publisher
    /// is returned immediately (no new network call). Otherwise, `operation` is invoked
    /// exactly once and its publisher is stored and shared with all concurrent callers.
    ///
    /// When the in-flight publisher completes (success, failure, or cancellation),
    /// its entry is removed so subsequent calls start a fresh request.
    func refresh(
        credential: Credential,
        operation: @escaping () -> AnyPublisher<Credential, Error>
    ) -> AnyPublisher<Credential, Error> {

        let key = self.key(for: credential)

        // Lock — defer guarantees unlock on EVERY exit path:
        // 1. Early-return (existing in-flight publisher)
        // 2. Normal return (new publisher stored and returned)
        // 3. Any unexpected throw (Swift defers run on throw too)
        lock.lock()
        defer { lock.unlock() }

        // Early-return path: existing publisher is returned while still holding the lock,
        // then defer fires and unlocks. Lock is balanced.
        if let existing = inFlight[key] {
            return existing
        }

        // Build the publisher for this new in-flight request.
        let publisher = operation()
            .handleEvents(
                receiveCompletion: { [weak self] _ in
                    self?.remove(key: key)
                },
                receiveCancel: { [weak self] in
                    self?.remove(key: key)
                }
            )
            .share()
            .eraseToAnyPublisher()

        inFlight[key] = publisher
        // defer fires here — unlocks the lock. Lock is balanced.
        return publisher
    }

    // MARK: - Private helpers

    /// Composite key: `identityURL|refreshToken` (falls back to `accessToken`
    /// when `refreshToken` is nil). Per REQ-SFR-02.
    private func key(for credential: Credential) -> String {
        let tokenPart = credential.refreshToken ?? credential.accessToken
        return "\(credential.identityURL.absoluteString)|\(tokenPart)"
    }

    /// Removes the in-flight entry for `key` under its own lock/unlock pair.
    /// Called from the Combine completion / cancel handlers (off the lock held
    /// in `refresh`), so a separate lock acquisition is correct here.
    private func remove(key: String) {
        lock.lock()
        defer { lock.unlock() }
        inFlight[key] = nil
    }
}
