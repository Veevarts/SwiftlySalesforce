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

        // MARK: Refresh path — delegate to SalesforceRefreshCoordinator (Slice 3)
        //
        // When `credential` is present and has a refreshToken, the coordinator handles
        // single-flight dedup using a composite key (identityURL|refreshToken).
        // This replaces the `pendingGranters` dedup for the refresh-token path.
        if let credential = credential, credential.refreshToken != nil {
            let host = resolvedHost(for: credential)
            return CredentialManager.refreshCoordinator
                .refresh(credential: credential) {
                    RefreshTokenFlow(
                        refreshToken: credential.refreshToken!,
                        consumerKey: consumerKey,
                        host: host
                    ).publisher
                }
                .tryCatch { [authenticator] error -> AnyPublisher<Credential, Error> in
                    guard allowsLogin else { throw error }
                    switch authenticator {
                    case .userAgent:
                        return UserAgentFlow(host: host, consumerKey: consumerKey, callbackURL: callbackURL).publisher
                    case .pkce:
                        let flow = AuthorizationCodePKCEFlow(session: URLSession(configuration: .ephemeral))
                        return flow.publisher(host: host, consumerKey: consumerKey, callbackURL: callbackURL)
                            .handleEvents(receiveCompletion: { _ in withExtendedLifetime(flow) {} })
                            .eraseToAnyPublisher()
                    }
                }
                .validate { [self] newCredential in
                    try store.store(newCredential)
                    defaults?.user = newCredential.user
                }
                .eraseToAnyPublisher()
        }

        // MARK: Fresh-login path — use pendingGranters for concurrent login dedup
        //
        // When there is no credential (or no refreshToken), this is a fresh interactive login.
        // `pendingGranters` deduplicates concurrent fresh-login calls with the empty-string key.
        let loginPublisher: AnyPublisher<Credential, Error> = CredentialManager.queue.sync { () -> AnyPublisher<Credential, Error> in
            let token = ""
            if let pub = CredentialManager.pendingGranters[token] {
                return pub.eraseToAnyPublisher()
            }
            let host = resolvedHost(for: credential)
            // Fresh interactive login. `.tryCatchUserAuthenticationRequiredError` is not
            // available here without a preceding publisher, so we build the login publisher
            // directly and guard `allowsLogin` inline.
            let pub: AnyPublisher<Credential, Error>
            if allowsLogin {
                let loginFlow: AnyPublisher<Credential, Error>
                switch authenticator {
                case .userAgent:
                    loginFlow = UserAgentFlow(host: host, consumerKey: consumerKey, callbackURL: callbackURL).publisher
                case .pkce:
                    let flow = AuthorizationCodePKCEFlow(session: URLSession(configuration: .ephemeral))
                    loginFlow = flow.publisher(host: host, consumerKey: consumerKey, callbackURL: callbackURL)
                        .handleEvents(receiveCompletion: { _ in withExtendedLifetime(flow) {} })
                        .eraseToAnyPublisher()
                }
                pub = loginFlow
                    .validate { [self] newCredential in
                        try store.store(newCredential)
                        defaults?.user = newCredential.user
                    }
                    .onCompletion { _ in CredentialManager.pendingGranters.removeValue(forKey: token) }
                    .share()
                    .eraseToAnyPublisher()
            } else {
                pub = Fail<Credential, Error>(error: SalesforceError.userAuthenticationRequired)
                    .onCompletion { _ in CredentialManager.pendingGranters.removeValue(forKey: token) }
                    .share()
                    .eraseToAnyPublisher()
            }
            CredentialManager.pendingGranters[token] = pub
            return pub
        }
        return loginPublisher
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
    /// Deduplicates concurrent fresh-login requests (key = ""; only one interactive
    /// login flow is allowed at a time). Refresh-path dedup is handled by `refreshCoordinator`.
    static var pendingGranters: [String : AnyPublisher<Credential, Error>] = [:]
    static var pendingRevokers: [String : AnyPublisher<Void, Error>] = [:]
    /// Deduplicates concurrent refresh-token network calls. Replaces the `pendingGranters`
    /// dedup for the refresh path (Slice 3 — SalesforceRefreshCoordinator).
    static var refreshCoordinator = SalesforceRefreshCoordinator()

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
