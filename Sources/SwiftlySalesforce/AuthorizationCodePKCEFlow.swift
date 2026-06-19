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
    /// Serializes check-and-set of `activeSubject` so two concurrent `publisher`
    /// calls can't both pass the de-duplication guard and open competing flows.
    static internal let activeSubjectLock = NSLock()
    static internal var activeSubject: (subject: PassthroughSubject<Credential, Error>, consumerKey: String)?
    /// The flow that owns the in-progress authentication, so it can be torn down
    /// by `cancelActiveAuthentication()`. Weak: if the owner is released the
    /// browser session is gone with it, and clearing the guard alone suffices.
    private static weak var activeFlow: AuthorizationCodePKCEFlow?

    private let session: URLSession
    private let verifierGenerator: () throws -> String
    private var authenticationSession: ASWebAuthenticationSession?
    private var presentationContextProvider: ASWebAuthenticationPresentationContextProviding?
    private var subscriptions = Set<AnyCancellable>()

    public init(session: URLSession = .shared, verifierGenerator: @escaping () throws -> String = AuthorizationCodePKCEFlow.generateCodeVerifier) {
        self.session = session
        self.verifierGenerator = verifierGenerator
    }

    /// Stops any in-progress authorization, dismisses its browser session and
    /// clears the shared in-progress guard so the next `authenticate()` begins a
    /// brand-new PKCE transaction (fresh verifier and code_challenge).
    ///
    /// Call this before switching hosts — e.g. when the user changes their My
    /// Domain mid-login. PKCE binds the `code_challenge` to the authorize request
    /// of a single host; reusing the in-flight transaction against a new host
    /// makes Salesforce reject the exchange with `invalid_grant` ("invalid code
    /// verifier"). After cancelling, recreate the flow/`OAuthManager` with the new
    /// hostname and authenticate again.
    ///
    /// The in-flight authentication publisher completes with
    /// `AuthorizationCodePKCEFlowError.authenticationCancelled`. Safe to call when
    /// nothing is in progress.
    public static func cancelActiveAuthentication() {
        activeSubjectLock.lock()
        let subject = activeSubject?.subject
        let flow = activeFlow
        activeSubject = nil
        activeFlow = nil
        activeSubjectLock.unlock()

        DispatchQueue.main.async {
            flow?.authenticationSession?.cancel()
            flow?.authenticationSession = nil
            flow?.presentationContextProvider = nil
        }

        subject?.send(completion: .failure(AuthorizationCodePKCEFlowError.authenticationCancelled))
    }

    private static func clearActiveSubject() {
        activeSubjectLock.lock()
        activeSubject = nil
        activeFlow = nil
        activeSubjectLock.unlock()
    }
}

extension AuthorizationCodePKCEFlow: Authenticator {
    public func publisher(connectedApp: ConnectedApp, hostname: String) -> AnyPublisher<Credential, Error> {
        AuthorizationCodePKCEFlow.activeSubjectLock.lock()
        if let existing = AuthorizationCodePKCEFlow.activeSubject {
            AuthorizationCodePKCEFlow.activeSubjectLock.unlock()
            if existing.consumerKey == connectedApp.consumerKey {
                return existing.subject.eraseToAnyPublisher()
            } else {
                return Fail(error: AuthorizationCodePKCEFlowError.authenticationInProgress).eraseToAnyPublisher()
            }
        }

        let subject = PassthroughSubject<Credential, Error>()
        AuthorizationCodePKCEFlow.activeSubject = (subject, connectedApp.consumerKey)
        AuthorizationCodePKCEFlow.activeFlow = self
        AuthorizationCodePKCEFlow.activeSubjectLock.unlock()

        let authURL: URL
        let verifier: String
        do {
            (authURL, verifier) = try authorizationURL(connectedApp: connectedApp, hostname: hostname)
        } catch {
            AuthorizationCodePKCEFlow.clearActiveSubject()
            return Fail(error: error).eraseToAnyPublisher()
        }

        // `verifier` is captured by this completion closure, binding it to the
        // session opened with its matching challenge. Even if another flow starts
        // concurrently, the verifier sent at exchange is always the one whose
        // code_challenge opened *this* browser — no shared mutable state to clobber.
        let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: connectedApp.callbackURL.scheme) { [weak self] url, error in
            guard let self = self else { return }
            defer {
                self.authenticationSession = nil
                self.presentationContextProvider = nil
                AuthorizationCodePKCEFlow.clearActiveSubject()
            }

            if let error = error {
                subject.send(completion: .failure(error))
                return
            }

            do {
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
                self.authenticationSession = nil
                self.presentationContextProvider = nil
                AuthorizationCodePKCEFlow.clearActiveSubject()
            }
        }

        self.authenticationSession = session
        return subject.eraseToAnyPublisher()
    }

    /// Stops the in-progress authorization. Forwards to
    /// `cancelActiveAuthentication()`; the guard is process-wide, so this tears
    /// down whichever flow is active regardless of which instance receives it.
    public func cancel() {
        AuthorizationCodePKCEFlow.cancelActiveAuthentication()
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
    func authorizationURL(connectedApp: ConnectedApp, hostname: String) throws -> (url: URL, verifier: String) {
        let verifier = try verifierGenerator()

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
            throw AuthorizationCodePKCEFlowError.invalidEndpointURL
        }
        return (url, verifier)
    }

    func authorizationCode(from callbackURL: URL) throws -> String {
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
    case authenticationCancelled
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
