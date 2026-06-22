//
//  RefreshTokenFlow.swift
//  SwiftlySalesforce
//
//  For license & details see: https://www.github.com/mike4aday/SwiftlySalesforce
//  Copyright (c) 2019. All rights reserved.

import Foundation
import Combine

public struct RefreshTokenFlow {

    // Registry of in-flight refreshes, keyed by "consumerKey|refreshToken", so concurrent refreshes
    // for the same credential share one token request — required for safety under refresh token
    // rotation, where the first refresh invalidates the token the others would otherwise reuse.
    fileprivate static let inFlightLock = NSLock()
    fileprivate static var inFlight: [String: (subject: PassthroughSubject<Credential, Error>, cancellable: AnyCancellable?)] = [:]

    // Result of the most recently completed refresh per consumer key, keyed by its input token, so a
    // straggler still presenting that (now-rotated) token replays the result instead of reusing a
    // server-invalidated token. One entry per consumer key (overwritten by the next refresh).
    fileprivate static var completed: [String: (inputToken: String, credential: Credential)] = [:]
}

extension RefreshTokenFlow: Refresher {

    public func publisher(credential: Credential, connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error> {

        // A refresh token is required; without one, full authentication is needed instead.
        guard let refreshToken = credential.refreshToken else {
            return Fail(outputType: Credential.self, failure: RefreshTokenFlowError.invalidRequest(message: "Missing refresh token")).eraseToAnyPublisher()
        }

        // Coalesce concurrent refreshes and replay a just-completed rotation to stragglers.
        return RefreshTokenFlow.coordinatedRefresh(consumerKey: connectedApp.consumerKey, refreshToken: refreshToken) {
            RefreshTokenFlow.performRefresh(credential: credential, connectedApp: connectedApp, hostname: hostname)
        }
    }
}

internal extension RefreshTokenFlow {

    /// Performs a single refresh-token request against the token endpoint.
    static func performRefresh(credential: Credential, connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error> {

        // Shorthand way to return error publisher
        let fail = { (error: Error) in Fail(outputType: Credential.self, failure: error).eraseToAnyPublisher() }

        // Salesforce OAuth2 refresh token endpoint URL
        guard let url = URL(string: "https://\(hostname)/services/oauth2/token") else {
            return fail(RefreshTokenFlowError.invalidEndpointURL)
        }

        // Encoded body data to be posted to OAuth refresh endpoint
        guard let refreshToken = credential.refreshToken else {
            return fail(RefreshTokenFlowError.invalidRequest(message: "Missing refresh token"))
        }
        let params: [String: String] = [
            "format" : "json",
            "grant_type": "refresh_token",
            "client_id": connectedApp.consumerKey,
            "refresh_token": refreshToken]
        guard let body = params.asPercentEncodedString()?.data(using: .utf8) else {
            return fail(RefreshTokenFlowError.invalidRequest(message: nil))
        }

        // Build URL request
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 60)
        req.httpMethod = HTTPMethod.post.rawValue
        req.httpBody = body

        // Publisher for request
        return URLSession.shared.dataTaskPublisher(for: req)
            .tryMap { (data, response) -> Data in
                if let error = RefreshTokenFlow.endpointError(data: data, response: response) {
                    throw error
                }
                return data
            }
            .tryMap { try RefreshTokenFlow.refreshedCredential(from: $0, credential: credential) }
            .eraseToAnyPublisher()
    }

    /// Coordinates refreshes for a credential so that, under refresh token rotation, no token is ever
    /// used twice against the server:
    /// - concurrent refreshes for the same token share one in-flight request (coalescing), and
    /// - a refresh presenting a token that a just-completed refresh already rotated replays that
    ///   result instead of issuing a new request (straggler replay).
    /// The single underlying refresh runs once, outside the lock (its completion re-acquires the lock
    /// on an arbitrary URLSession queue, so locking inside it while held would deadlock). The result
    /// is recorded before the in-flight entry is cleared, so no straggler can slip through the gap.
    static func coordinatedRefresh(consumerKey: String, refreshToken: String, _ make: () -> AnyPublisher<Credential, Error>) -> AnyPublisher<Credential, Error> {

        let key = "\(consumerKey)|\(refreshToken)"

        inFlightLock.lock()
        // Straggler replay: this exact token was already refreshed by a completed refresh.
        if let last = completed[consumerKey], last.inputToken == refreshToken {
            inFlightLock.unlock()
            return Just(last.credential).setFailureType(to: Error.self).eraseToAnyPublisher()
        }
        // Overlapping: join the in-flight refresh.
        if let existing = inFlight[key] {
            inFlightLock.unlock()
            return existing.subject.eraseToAnyPublisher()
        }
        let subject = PassthroughSubject<Credential, Error>()
        inFlight[key] = (subject: subject, cancellable: nil)
        inFlightLock.unlock()

        // Start the single underlying refresh outside the lock.
        let cancellable = make().sink(
            receiveCompletion: { completion in
                inFlightLock.lock()
                inFlight[key] = nil
                inFlightLock.unlock()
                subject.send(completion: completion)
            },
            receiveValue: { credential in
                // Record the result (keyed by the input token) BEFORE clearing the in-flight entry,
                // so a straggler arriving after completion replays it instead of refreshing a dead token.
                inFlightLock.lock()
                completed[consumerKey] = (inputToken: refreshToken, credential: credential)
                inFlightLock.unlock()
                subject.send(credential)
            }
        )

        // Retain the subscription for as long as the refresh is in flight (skip if it already finished).
        inFlightLock.lock()
        if inFlight[key] != nil {
            inFlight[key]?.cancellable = cancellable
        }
        inFlightLock.unlock()

        return subject.eraseToAnyPublisher()
    }

    /// Test hook: clears all in-flight and completed refresh registry state.
    static func resetInFlightRefreshes() {
        inFlightLock.lock()
        inFlight.removeAll()
        completed.removeAll()
        inFlightLock.unlock()
    }

    /// Decodes a token-endpoint response and applies refresh token rotation: the new `refresh_token`
    /// is used when present, otherwise the previous one is retained.
    static func refreshedCredential(from tokenResponse: Data, credential: Credential) throws -> Credential {
        return try JSONDecoder().decode(RefreshTokenFlowResult.self, from: tokenResponse).refreshing(credential: credential)
    }

    /// Maps a token-endpoint response to an error, or `nil` for a successful (HTTP 200) response.
    /// An `invalid_grant` error is surfaced as `refreshTokenRotatedOrExpired` so callers can re-authenticate.
    static func endpointError(data: Data, response: URLResponse) -> Error? {
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            let decoded = try? JSONDecoder().decode(RefreshTokenFlowErrorResult.self, from: data)
            if decoded?.error == "invalid_grant" {
                return RefreshTokenFlowError.refreshTokenRotatedOrExpired(description: decoded?.error_description, response: response)
            }
            return RefreshTokenFlowError.endpointFailure(code: decoded?.error ?? "Unknown", description: decoded?.error_description, response: response)
        }
        return nil
    }
}

public enum RefreshTokenFlowError: LocalizedError {
    case invalidEndpointURL
    case invalidRequest(message: String?)
    case endpointFailure(code: String, description: String?, response: URLResponse)
    /// The refresh token was rotated or expired (`invalid_grant`); re-authentication is required.
    case refreshTokenRotatedOrExpired(description: String?, response: URLResponse)
}

fileprivate struct RefreshTokenFlowResult {

    let accessToken: String
    let instanceURL: URL
    let identityURL: URL
    let refreshToken: String?
    let issuedAt: UInt?
    let communityURL: URL?
    let communityID: String?

    func refreshing(credential: Credential) -> Credential {
        // Refresh token rotation: use the rotated token when the server returned one, otherwise keep the existing one.
        return Credential(accessToken: accessToken, instanceURL: instanceURL, identityURL: identityURL, refreshToken: refreshToken ?? credential.refreshToken, issuedAt: issuedAt, idToken: credential.idToken, communityURL: communityURL, communityID: communityID)
    }
}

extension RefreshTokenFlowResult: Decodable {

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case instanceURL = "instance_url"
        case identityURL = "id"
        case refreshToken = "refresh_token"
        case issuedAt = "issued_at"
        case communityURL = "sfdc_community_url"
        case communityID = "sfdc_community_id"
    }

    public init(from decoder: Decoder) throws {

        // Top level container
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Set properties
        self.accessToken = try container.decode(String.self, forKey: .accessToken)
        self.instanceURL = try container.decode(URL.self, forKey: .instanceURL)
        self.identityURL = try container.decode(URL.self, forKey: .identityURL)
        self.refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
        self.issuedAt = try {
            guard let s = try container.decodeIfPresent(String.self, forKey: .issuedAt) else {
                return nil
            }
            return UInt(s)
        }()
        self.communityURL = try container.decodeIfPresent(URL.self, forKey: .communityURL)
        self.communityID = try container.decodeIfPresent(String.self, forKey: .communityID)
    }
}

fileprivate struct RefreshTokenFlowErrorResult: Decodable {
    var error: String
    var error_description: String?
}
