//
//  OAuthManager.swift
//  SwiftlySalesforce
//
//  For license & details see: https://www.github.com/mike4aday/SwiftlySalesforce
//  Copyright (c) 2019. All rights reserved.

import Foundation
import Combine

public struct OAuthManager {
    
    public var hostname: String
    public var connectedApp: ConnectedApp
    public var authenticator: Authenticator
    public var refresher: Refresher
    
    public init(connectedApp: ConnectedApp, hostname: String, authenticator: Authenticator, refresher: Refresher) {
        self.connectedApp = connectedApp
        self.hostname = hostname
        self.authenticator = authenticator
        self.refresher = refresher
    }
    
    public init(connectedApp: ConnectedApp, hostname: String) {
        self.init(
            connectedApp: connectedApp,
            hostname: hostname,
            authenticator: AuthorizationCodePKCEFlow(),
            refresher: RefreshTokenFlow()
        )
    }
    
    public func authenticate() -> AnyPublisher<Credential, Error> {
        return authenticator.publisher(connectedApp: connectedApp, hostname: hostname)
    }

    /// Stops any in-progress user authentication. Call this before switching the
    /// OAuth hostname (e.g. when the user changes their My Domain mid-login) so the
    /// next `authenticate()` starts a fresh PKCE transaction against the new host.
    public func cancelAuthentication() {
        authenticator.cancel()
    }
    
    public func refresh(credential: Credential) -> AnyPublisher<Credential, Error> {
        return refresher.publisher(credential: credential, connectedApp: connectedApp, hostname: hostname)
    }
    
    public func revoke(credential: Credential) -> AnyPublisher<Void, Error> {
        return revoke(token: credential.refreshToken ?? credential.accessToken)
    }
}

public protocol Authenticator {
    func publisher(connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error>
    /// Stops an in-progress authentication so a new one can start cleanly.
    /// Defaults to a no-op for authenticators that don't hold cancellable state.
    func cancel()
}

public extension Authenticator {
    func cancel() {}
}

public protocol Refresher {
    func publisher(credential: Credential, connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error>
}

internal extension OAuthManager {
    
    func revoke(token: String) -> AnyPublisher<Void, Error> {
        
        struct RevokeTokenErrorResult: Decodable {
            var error: String
            var error_description: String?
        }
        
        // URL
        guard let url = URL(string: "https://\(hostname)/services/oauth2/revoke") else {
            return Fail(outputType: Void.self, failure: URLError(URLError.badURL)).eraseToAnyPublisher()
        }
        
        // URLRequest
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        req.httpMethod = HTTPMethod.post.rawValue
        req.httpBody = ["token" : token].asPercentEncodedString()?.data(using: .utf8)
        
        return URLSession.shared.dataTaskPublisher(for: req)
        .tryMap { (data, response) -> Data in
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                // Try to decode error information from data
                if let err = try? JSONDecoder().decode(RevokeTokenErrorResult.self, from: data)   {
                    throw OAuthManagerError.endpointFailure(code: err.error, description: err.error_description, response: response)
                }
                else {
                    throw OAuthManagerError.endpointFailure(code: "Unknown", description: nil, response: response)
                }
            }
            return data
        }
        .map { _ in }
        .eraseToAnyPublisher()
    }
}

public enum OAuthManagerError: Error {
    case endpointFailure(code: String, description: String?, response: URLResponse)
}
