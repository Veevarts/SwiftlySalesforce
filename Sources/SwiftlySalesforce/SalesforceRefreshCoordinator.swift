//
//  SalesforceRefreshCoordinator.swift
//  SwiftlySalesforce
//

import Foundation
import Combine

internal final class SalesforceRefreshCoordinator {
    private let lock = NSLock()
    private var activeRefreshes: [String: AnyPublisher<Credential, Error>] = [:]

    /// Coalesces concurrent refreshes for the same user and prevents reuse of a
    /// refresh token that was already rotated out.
    ///
    /// Under refresh-token rotation (RTR) each refresh token is single-use: a
    /// successful refresh rotates RT0 -> RT1 and invalidates RT0. When many
    /// requests share one `Salesforce` instance and their access token expires,
    /// they all try to refresh the same RT0. The first winner rotates and persists
    /// RT1; a *staggered* straggler that arrives after the in-flight entry was
    /// freed would otherwise launch a second refresh of the now-dead RT0, which
    /// Salesforce rejects with `invalid_grant`.
    ///
    /// - Parameters:
    ///   - credential: the (possibly stale) credential that triggered the refresh.
    ///   - latestCredential: returns the most recently persisted credential for the
    ///     user, evaluated at the moment a refresh is about to start. If it has
    ///     already been rotated past `credential`, it is reused instead of
    ///     refreshing a superseded refresh token. Defaults to `nil` (no store).
    ///   - operation: performs the network refresh and persists its result before
    ///     completing, so the rotated credential is durable before this entry frees.
    func refresh(
        credential: Credential,
        latestCredential: @escaping () -> Credential? = { nil },
        operation: @escaping () -> AnyPublisher<Credential, Error>
    ) -> AnyPublisher<Credential, Error> {
        let key = refreshKey(for: credential)

        lock.lock()
        if let active = activeRefreshes[key] {
            lock.unlock()
            return active
        }

        // No in-flight refresh for this user. If the stored credential was already
        // rotated past the one we hold, reuse it rather than refresh a dead token.
        if let latest = latestCredential(), latest != credential {
            lock.unlock()
            return Just(latest).setFailureType(to: Error.self).eraseToAnyPublisher()
        }

        let publisher = operation()
            .handleEvents(receiveCompletion: { [weak self] _ in
                self?.removeRefresh(for: key)
            }, receiveCancel: { [weak self] in
                self?.removeRefresh(for: key)
            })
            .share()
            .eraseToAnyPublisher()
        activeRefreshes[key] = publisher
        lock.unlock()
        return publisher
    }

    private func removeRefresh(for key: String) {
        lock.lock()
        activeRefreshes[key] = nil
        lock.unlock()
    }

    private func refreshKey(for credential: Credential) -> String {
        // Key by user identity only. Keying by the refresh token would let a
        // straggler carrying an already-rotated-out token start a second refresh
        // instead of coalescing with — or reusing the result of — the first one.
        credential.identityURL.absoluteString
    }
}
