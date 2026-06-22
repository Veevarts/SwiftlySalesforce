//
//  AuthorizationCodeFlow.swift
//  SwiftlySalesforce
//
//  For license & details see: https://www.github.com/mike4aday/SwiftlySalesforce
//

import Foundation
import Combine
import AuthenticationServices

/// OAuth 2.0 authorization-code flow with PKCE (RFC 7636).
/// See [OAuth 2.0 Web Server Flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_web_server_flow.htm).
public struct AuthorizationCodeFlow {
    static internal var activeSubject: (subject: PassthroughSubject<Credential, Error>, consumerKey: String, verifier: String)?
}

extension AuthorizationCodeFlow: Authenticator {

    public func publisher(connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error> {

        let pkce = PKCE()
        guard let authURL = AuthorizationCodeFlow.authorizationURL(connectedApp: connectedApp, hostname: hostname, challenge: pkce.challenge) else {
            return Fail(error: AuthorizationCodeFlowError.invalidEndpointURL).eraseToAnyPublisher()
        }

        if let subj = AuthorizationCodeFlow.activeSubject {
            if subj.consumerKey == connectedApp.consumerKey {
                // Reusing existing subject for authorization-code flow
                return subj.subject.eraseToAnyPublisher()
            }
            else {
                return Fail(error: AuthorizationCodeFlowError.authenticationInProgress).eraseToAnyPublisher()
            }
        }
        else {
            // Creating new subject for authorization-code flow
            let subj = PassthroughSubject<Credential, Error>()
            AuthorizationCodeFlow.activeSubject = (subj, connectedApp.consumerKey, pkce.verifier)
            var tokenSubscription: AnyCancellable?
            let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: connectedApp.callbackURL.scheme) { (url, error) in
                let verifier = AuthorizationCodeFlow.activeSubject?.verifier ?? pkce.verifier
                AuthorizationCodeFlow.activeSubject = nil
                if let error = error {
                    // User cancelled authentication, or something else went wrong
                    subj.send(completion: .failure(error))
                }
                else if let url = url, let code = AuthorizationCodeFlow.code(from: url) {
                    // Exchange the authorization code for tokens at the token endpoint
                    tokenSubscription = AuthorizationCodeFlow.exchange(code: code, verifier: verifier, connectedApp: connectedApp, hostname: hostname)
                        .sink(receiveCompletion: { completion in
                            if case let .failure(err) = completion {
                                subj.send(completion: .failure(err))
                            }
                            _ = tokenSubscription // retain until completion
                        }, receiveValue: { credential in
                            subj.send(credential)
                            subj.send(completion: .finished)
                        })
                }
                else {
                    subj.send(completion: .failure(AuthorizationCodeFlowError.unparseableCallbackURL))
                }
            }
            DispatchQueue.main.async {
                let contextProvider = KeyWindowPresentationAnchor()
                session.presentationContextProvider = contextProvider
                if !session.start() {
                    subj.send(completion: .failure(AuthorizationCodeFlowError.sessionFailure))
                    AuthorizationCodeFlow.activeSubject = nil
                }
            }
            return subj.eraseToAnyPublisher()
        }
    }
}

internal extension AuthorizationCodeFlow {

    /// Builds the `/authorize` URL carrying the PKCE challenge (S256).
    static func authorizationURL(connectedApp: ConnectedApp, hostname: String, challenge: String) -> URL? {
        let parameters = [
            "response_type" : "code",
            "client_id" : connectedApp.consumerKey,
            "redirect_uri" : connectedApp.callbackURL.absoluteString,
            "code_challenge" : challenge,
            "code_challenge_method" : "S256",
            "prompt" : "login consent",
            "display" : "touch" ]
        var comps = URLComponents(string: "https://\(hostname)/services/oauth2/authorize")
        comps?.queryItems = parameters.map { URLQueryItem(name: $0.key, value: $0.value) }
        return comps?.url
    }

    /// Parameters posted to the `/token` endpoint for the authorization-code grant.
    /// `client_secret` is included only when the connected app provides one.
    static func tokenParameters(code: String, verifier: String, connectedApp: ConnectedApp) -> [String: String] {
        var parameters = [
            "format" : "json",
            "grant_type" : "authorization_code",
            "code" : code,
            "client_id" : connectedApp.consumerKey,
            "redirect_uri" : connectedApp.callbackURL.absoluteString,
            "code_verifier" : verifier ]
        if let secret = connectedApp.clientSecret {
            parameters["client_secret"] = secret
        }
        return parameters
    }

    /// Extracts the authorization `code` from the callback URL's query (not its fragment).
    static func code(from url: URL) -> String? {
        return URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { $0.name == "code" })?
            .value
    }

    /// Decodes a token-endpoint JSON response into a `Credential`, including any returned `refresh_token`.
    static func credential(from tokenResponse: Data) throws -> Credential {
        return try JSONDecoder().decode(AuthorizationCodeFlowResult.self, from: tokenResponse).credential
    }

    /// Exchanges an authorization code for a `Credential` at the token endpoint.
    static func exchange(code: String, verifier: String, connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error> {

        let fail = { (error: Error) in Fail(outputType: Credential.self, failure: error).eraseToAnyPublisher() }

        guard let url = URL(string: "https://\(hostname)/services/oauth2/token") else {
            return fail(AuthorizationCodeFlowError.invalidEndpointURL)
        }
        guard let body = tokenParameters(code: code, verifier: verifier, connectedApp: connectedApp).asPercentEncodedString()?.data(using: .utf8) else {
            return fail(AuthorizationCodeFlowError.invalidRequest(message: nil))
        }

        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 60)
        req.httpMethod = HTTPMethod.post.rawValue
        req.httpBody = body

        return URLSession.shared.dataTaskPublisher(for: req)
            .tryMap { (data, response) -> Data in
                guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                    if let err = try? JSONDecoder().decode(AuthorizationCodeFlowErrorResult.self, from: data) {
                        throw AuthorizationCodeFlowError.endpointFailure(code: err.error, description: err.error_description, response: response)
                    }
                    else {
                        throw AuthorizationCodeFlowError.endpointFailure(code: "Unknown", description: nil, response: response)
                    }
                }
                return data
            }
            .tryMap { try AuthorizationCodeFlow.credential(from: $0) }
            .eraseToAnyPublisher()
    }
}

public enum AuthorizationCodeFlowError: LocalizedError {
    case invalidEndpointURL
    case invalidRequest(message: String?)
    case unparseableCallbackURL
    case sessionFailure
    case authenticationInProgress
    case endpointFailure(code: String, description: String?, response: URLResponse)
}

fileprivate struct AuthorizationCodeFlowResult {

    let accessToken: String
    let instanceURL: URL
    let identityURL: URL
    let refreshToken: String?
    let issuedAt: UInt?
    let idToken: String?
    let communityURL: URL?
    let communityID: String?

    var credential: Credential {
        return Credential(accessToken: accessToken, instanceURL: instanceURL, identityURL: identityURL, refreshToken: refreshToken, issuedAt: issuedAt, idToken: idToken, communityURL: communityURL, communityID: communityID)
    }
}

extension AuthorizationCodeFlowResult: Decodable {

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case instanceURL = "instance_url"
        case identityURL = "id"
        case refreshToken = "refresh_token"
        case issuedAt = "issued_at"
        case idToken = "id_token"
        case communityURL = "sfdc_community_url"
        case communityID = "sfdc_community_id"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
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
        self.idToken = try container.decodeIfPresent(String.self, forKey: .idToken)
        self.communityURL = try container.decodeIfPresent(URL.self, forKey: .communityURL)
        self.communityID = try container.decodeIfPresent(String.self, forKey: .communityID)
    }
}

fileprivate struct AuthorizationCodeFlowErrorResult: Decodable {
    var error: String
    var error_description: String?
}

fileprivate class KeyWindowPresentationAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        var anchor: ASPresentationAnchor?
        #if canImport(UIKit)
            anchor = UIApplication.shared.windows.first { $0.isKeyWindow }
        #endif
        guard let returnMe = anchor else {
            fatalError("Failed to get key window for authentication session!")
        }
        return returnMe
    }
}
