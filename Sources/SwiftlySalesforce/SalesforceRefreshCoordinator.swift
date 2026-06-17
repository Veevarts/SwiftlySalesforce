//
//  SalesforceRefreshCoordinator.swift
//  SwiftlySalesforce
//

import Foundation
import Combine

internal final class SalesforceRefreshCoordinator {
    private let lock = NSLock()
    private var activeRefreshes: [String: AnyPublisher<Credential, Error>] = [:]

    func refresh(credential: Credential, operation: @escaping () -> AnyPublisher<Credential, Error>) -> AnyPublisher<Credential, Error> {
        let key = refreshKey(for: credential)

        lock.lock()
        if let active = activeRefreshes[key] {
            lock.unlock()
            return active
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
        [credential.identityURL.absoluteString, credential.refreshToken ?? credential.accessToken].joined(separator: "|")
    }
}
