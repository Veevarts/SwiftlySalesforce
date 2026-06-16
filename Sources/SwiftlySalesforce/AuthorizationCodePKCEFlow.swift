//
//  AuthorizationCodePKCEFlow.swift
//  SwiftlySalesforce
//

import Foundation
import Combine
import AuthenticationServices
import CryptoKit
import Security
#if canImport(UIKit)
import UIKit
#endif

/// Salesforce OAuth authorization-code flow with PKCE S256 support.
public final class AuthorizationCodePKCEFlow {
    static internal var activeSubject: (subject: PassthroughSubject<Credential, Error>, consumerKey: String)?

    private let session: URLSession
    private let verifierGenerator: () throws -> String
    private var authenticationSession: ASWebAuthenticationSession?
    private var presentationContextProvider: ASWebAuthenticationPresentationContextProviding?
    private var subscriptions = Set<AnyCancellable>()
    private var currentVerifier: String?

    internal var currentVerifierForTesting: String? { currentVerifier }

    public init(session: URLSession = .shared, verifierGenerator: @escaping () throws -> String = AuthorizationCodePKCEFlow.generateCodeVerifier) {
        self.session = session
        self.verifierGenerator = verifierGenerator
    }
}

extension AuthorizationCodePKCEFlow: Authenticator {
    public func publisher(connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error> {
        if let subj = AuthorizationCodePKCEFlow.activeSubject {
            if subj.consumerKey == connectedApp.consumerKey {
                return subj.subject.eraseToAnyPublisher()
            } else {
                return Fail(error: AuthorizationCodePKCEFlowError.authenticationInProgress).eraseToAnyPublisher()
            }
        }

        let subject = PassthroughSubject<Credential, Error>()
        AuthorizationCodePKCEFlow.activeSubject = (subject, connectedApp.consumerKey)

        let authURL: URL
        do {
            authURL = try authorizationURL(connectedApp: connectedApp, hostname: hostname)
        } catch {
            AuthorizationCodePKCEFlow.activeSubject = nil
            return Fail(error: error).eraseToAnyPublisher()
        }

        let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: connectedApp.callbackURL.scheme) { [weak self] url, error in
            guard let self = self else { return }
            defer {
                self.currentVerifier = nil
                self.authenticationSession = nil
                self.presentationContextProvider = nil
                AuthorizationCodePKCEFlow.activeSubject = nil
            }

            if let error = error {
                subject.send(completion: .failure(error))
                return
            }

            do {
                guard let verifier = self.currentVerifier else {
                    throw AuthorizationCodePKCEFlowError.missingCodeVerifier
                }
                guard let url = url else {
                    throw AuthorizationCodePKCEFlowError.missingAuthorizationCode
                }
                let code = try self.authorizationCode(from: url)
                self.exchangeCode(code, codeVerifier: verifier, connectedApp: connectedApp, hostname: hostname)
                    .sink(receiveCompletion: { completion in
                        if case let .failure(error) = completion {
                            subject.send(completion: .failure(error))
                        }
                    }, receiveValue: { credential in
                        subject.send(credential)
                        subject.send(completion: .finished)
                    })
                    .store(in: &self.subscriptions)
            } catch {
                subject.send(completion: .failure(error))
            }
        }

        DispatchQueue.main.async {
            let contextProvider = KeyWindowPresentationAnchor()
            self.presentationContextProvider = contextProvider
            session.presentationContextProvider = contextProvider
            if !session.start() {
                subject.send(completion: .failure(AuthorizationCodePKCEFlowError.sessionFailure))
                self.currentVerifier = nil
                self.authenticationSession = nil
                self.presentationContextProvider = nil
                AuthorizationCodePKCEFlow.activeSubject = nil
            }
        }

        self.authenticationSession = session
        return subject.eraseToAnyPublisher()
    }
}

public extension AuthorizationCodePKCEFlow {
    static func generateCodeVerifier() throws -> String {
        try generateCodeVerifier(randomBytes: secureRandomBytes)
    }

    static func generateCodeVerifier(randomBytes: (Int) throws -> [UInt8]) throws -> String {
        let allowed = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
        let bytes = try randomBytes(64)
        guard bytes.count == 64 else {
            throw AuthorizationCodePKCEFlowError.randomGenerationFailed
        }
        return String(bytes.map { allowed[Int($0) % allowed.count] })
    }

    static func codeChallenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64URLEncodedString()
    }
}

internal extension AuthorizationCodePKCEFlow {
    func authorizationURL(connectedApp: ConnectedApp, hostname: String) throws -> URL {
        let verifier = try verifierGenerator()
        currentVerifier = verifier

        let parameters = [
            "response_type": "code",
            "client_id": connectedApp.consumerKey,
            "redirect_uri": connectedApp.callbackURL.absoluteString,
            "prompt": "login consent",
            "display": "touch",
            "code_challenge": AuthorizationCodePKCEFlow.codeChallenge(for: verifier),
            "code_challenge_method": "S256"
        ]

        var comps = URLComponents(string: "https://\(hostname)/services/oauth2/authorize")
        comps?.queryItems = parameters.map { URLQueryItem(name: $0.key, value: $0.value) }
        guard let url = comps?.url else {
            currentVerifier = nil
            throw AuthorizationCodePKCEFlowError.invalidEndpointURL
        }
        return url
    }

    func authorizationCode(from callbackURL: URL) throws -> String {
        defer { currentVerifier = nil }
        guard let code = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { $0.name == "code" })?
            .value,
            !code.isEmpty else {
            throw AuthorizationCodePKCEFlowError.missingAuthorizationCode
        }
        return code
    }

    func exchangeCode(_ code: String, codeVerifier: String, connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error> {
        guard let url = URL(string: "https://\(hostname)/services/oauth2/token") else {
            return Fail(error: AuthorizationCodePKCEFlowError.invalidEndpointURL).eraseToAnyPublisher()
        }

        let parameters = [
            "format": "json",
            "grant_type": "authorization_code",
            "client_id": connectedApp.consumerKey,
            "redirect_uri": connectedApp.callbackURL.absoluteString,
            "code": code,
            "code_verifier": codeVerifier
        ]
        guard let body = parameters.asPercentEncodedString()?.data(using: .utf8) else {
            return Fail(error: AuthorizationCodePKCEFlowError.invalidRequest).eraseToAnyPublisher()
        }

        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 60)
        request.httpMethod = HTTPMethod.post.rawValue
        request.httpBody = body

        return session.dataTaskPublisher(for: request)
            .tryMap { data, response -> Data in
                guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                    if let err = try? JSONDecoder().decode(AuthorizationCodePKCEFlowErrorResult.self, from: data) {
                        throw OAuthManagerError.endpointFailure(code: err.error, description: err.error_description, response: response)
                    }
                    throw OAuthManagerError.endpointFailure(code: "Unknown", description: nil, response: response)
                }
                return data
            }
            .decode(type: AuthorizationCodePKCEFlowResult.self, decoder: JSONDecoder())
            .map { $0.credential }
            .eraseToAnyPublisher()
    }
}

public enum AuthorizationCodePKCEFlowError: LocalizedError {
    case invalidEndpointURL
    case invalidRequest
    case missingAuthorizationCode
    case missingCodeVerifier
    case sessionFailure
    case authenticationInProgress
    case randomGenerationFailed
}

private func secureRandomBytes(count: Int) throws -> [UInt8] {
    guard count > 0 else {
        throw AuthorizationCodePKCEFlowError.randomGenerationFailed
    }

    var bytes = [UInt8](repeating: 0, count: count)
    let status = bytes.withUnsafeMutableBytes { buffer -> OSStatus in
        guard let baseAddress = buffer.baseAddress else {
            return errSecAllocate
        }
        return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
    }
    guard status == errSecSuccess else {
        throw AuthorizationCodePKCEFlowError.randomGenerationFailed
    }
    return bytes
}

private struct AuthorizationCodePKCEFlowResult: Decodable {
    let accessToken: String
    let instanceURL: URL
    let identityURL: URL
    let refreshToken: String?
    let issuedAt: UInt?
    let idToken: String?
    let communityURL: URL?
    let communityID: String?

    var credential: Credential {
        Credential(accessToken: accessToken, instanceURL: instanceURL, identityURL: identityURL, refreshToken: refreshToken, issuedAt: issuedAt, idToken: idToken, communityURL: communityURL, communityID: communityID)
    }

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

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try container.decode(String.self, forKey: .accessToken)
        instanceURL = try container.decode(URL.self, forKey: .instanceURL)
        identityURL = try container.decode(URL.self, forKey: .identityURL)
        refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
        issuedAt = try container.decodeIfPresent(String.self, forKey: .issuedAt).flatMap(UInt.init)
        idToken = try container.decodeIfPresent(String.self, forKey: .idToken)
        communityURL = try container.decodeIfPresent(URL.self, forKey: .communityURL)
        communityID = try container.decodeIfPresent(String.self, forKey: .communityID)
    }
}

private struct AuthorizationCodePKCEFlowErrorResult: Decodable {
    var error: String
    var error_description: String?
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

fileprivate class KeyWindowPresentationAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
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
