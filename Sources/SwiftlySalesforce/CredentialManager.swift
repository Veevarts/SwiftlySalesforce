/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine

// MARK: - AuthMethod enum (internal — no public API change)

/// Selects the interactive-login flow used by `CredentialManager.grantCredential`.
///
/// - `pkce`: OAuth 2.0 Authorization Code + PKCE (default; Salesforce-recommended for mobile).
/// - `userAgent`: Legacy OAuth 2.0 User-Agent (implicit) flow via `UserAgentFlow`.
enum AuthMethod: Equatable {
    case pkce
    case userAgent
}

// MARK: - CredentialManager

struct CredentialManager {
    var consumerKey: String
    var callbackURL: URL
    var defaultHost: String = "login.salesforce.com"
    /// The interactive-login mechanism. Defaults to `.pkce`.
    var authenticator: AuthMethod = .pkce
}

extension CredentialManager {
    
    func getCredential(for user: UserIdentifier? = nil, allowsLogin: Bool = true) -> AnyPublisher<Credential, Error> {
        AnyPublisher<Credential?, Error>
            .just(try getStoredCredential(for: user))
            .unwrap(orThrow: SalesforceError.userAuthenticationRequired)
            .tryCatchUserAuthenticationRequiredError { grantCredential(allowsLogin: allowsLogin) }
            .eraseToAnyPublisher()
    }
    
    func getStoredCredential(for user: UserIdentifier? = nil) throws -> Credential? {
        guard let user = user ?? defaults?.user else {
            return nil
        }
        return try store.retrieve(for: user)
    }
    
    func clearStoredCredential(for user: UserIdentifier? = nil) throws -> Void {
        guard let user = user ?? defaults?.user else {
            return
        }
        return try store.delete(for: user)
    }
        
    func grantCredential(replacing credential: Credential? = nil, allowsLogin: Bool = true) -> AnyPublisher<Credential, Error> {
        return CredentialManager.queue.sync {
            let token = credential?.refreshToken ?? ""
            if let pub = CredentialManager.pendingGranters[token] {
                return pub.eraseToAnyPublisher()
            }
            else {
                let host = resolvedHost(for: credential)
                let pub = AnyPublisher<String?, Error>
                    .just(credential?.refreshToken)
                    .unwrap(orThrow: SalesforceError.userAuthenticationRequired)
                    .flatMap { refreshToken in
                        RefreshTokenFlow(refreshToken: refreshToken, consumerKey: consumerKey, host: host).publisher
                    }
                    .tryCatch { [authenticator] error -> AnyPublisher<Credential, Error> in
                        guard allowsLogin else { throw error }
                        switch authenticator {
                        case .userAgent:
                            return UserAgentFlow(host: host, consumerKey: consumerKey, callbackURL: callbackURL).publisher
                        case .pkce:
                            // Instantiate flow locally; capture it strongly so it outlives the
                            // ASWebAuthenticationSession callback (class-lifetime-in-struct resolution).
                            // `.handleEvents` pins `flow` until the publisher completes/errors.
                            let flow = AuthorizationCodePKCEFlow(session: URLSession(configuration: .ephemeral))
                            return flow.publisher(host: host, consumerKey: consumerKey, callbackURL: callbackURL)
                                .handleEvents(receiveCompletion: { _ in withExtendedLifetime(flow) {} })
                                .eraseToAnyPublisher()
                        }
                    }
                    .validate { newCredential in
                        try store.store(newCredential)
                        defaults?.user = newCredential.user
                    }
                    .onCompletion { _ in
                        CredentialManager.pendingGranters.removeValue(forKey: token)
                    }
                    .share()
                    .eraseToAnyPublisher()
                CredentialManager.pendingGranters[token] = pub
                return pub
            }
        }
    }

    func revokeCredential(_ credential: Credential) -> AnyPublisher<Void, Error> {
        return CredentialManager.queue.sync {
            let token = credential.refreshToken ?? credential.accessToken
            if let pub = CredentialManager.pendingRevokers[token] {
                return pub.eraseToAnyPublisher()
            }
            else {
                let host = resolvedHost(for: credential)
                let pub = RevokeTokenFlow(token: token, host: host).publisher
                    .share()
                    .validate { _ in
                        try store.delete(for: credential.user)
                        defaults?.user = nil
                    }
                    .onCompletion { _ in CredentialManager.pendingRevokers.removeValue(forKey: token) }
                    .share()
                    .eraseToAnyPublisher()
                CredentialManager.pendingRevokers[token] = pub
                return pub
            }
        }
    }
}

private extension CredentialManager {
    
    static var queue = DispatchQueue(label: "\(#fileID).\(UUID().uuidString)")
    static var pendingGranters: [String : AnyPublisher<Credential, Error>] = [:]
    static var pendingRevokers: [String : AnyPublisher<Void, Error>] = [:]

    var store: CredentialStore {
        CredentialStore(consumerKey: consumerKey)
    }
    
    var defaults: UserDefaults? {
        return UserDefaults(consumerKey: consumerKey)
    }
    
    func resolvedHost(for credential: Credential?) -> String {
        if let siteHost = credential?.siteURL?.host {
            return siteHost
        }
        else if let myDomainHost = credential?.instanceURL.host, myDomainHost.lowercased().hasSuffix("my.salesforce.com") {
            return myDomainHost
        }
        return defaultHost
    }
}
