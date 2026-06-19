/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine
import AuthenticationServices
import CryptoKit
import Security
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Error type

/// Errors specific to the PKCE authorization code flow.
public enum PKCEFlowError: Swift.Error, Equatable {
    /// Random number generation failed — flow must NOT proceed with a weak verifier.
    case rngFailure
    /// The callback URL returned by ASWebAuthenticationSession lacked a `code` query param.
    case missingCode
    /// The token endpoint returned an unexpected response that could not be mapped to a Credential.
    case badServerResponse
    /// ASWebAuthenticationSession could not be started.
    case sessionFailure
}

// MARK: - Flow

/// PKCE Authorization Code flow (RFC 7636) adapted to the 9.0.3 Combine / value-type stack.
///
/// Lifetime contract:
/// - This is a `final class` — it holds `authenticationSession` and `presentationContextProvider`
///   as instance properties so they survive the asynchronous ASWebAuthenticationSession callback.
/// - Callers must pin the flow instance for the duration of the session. The recommended pattern
///   inside `CredentialManager.grantCredential` is to capture `flow` in the publisher closure and
///   append `.handleEvents(receiveCompletion: { _ in withExtendedLifetime(flow) {} })`.
public final class AuthorizationCodePKCEFlow: NSObject {

    // MARK: - Stored properties

    private let session: URLSession

    /// The active ASWebAuthenticationSession. Stored so it survives the async callback.
    private var authenticationSession: ASWebAuthenticationSession?

    /// Presentation anchor provider. Stored alongside `authenticationSession`.
    private var presentationContextProvider: (NSObject & ASWebAuthenticationPresentationContextProviding)?

    /// Subscriptions that keep in-flight Combine chains alive.
    private var subscriptions = Set<AnyCancellable>()

    /// The PKCE `code_verifier` generated in `authorizationURL`, read back in the
    /// ASWebAuthenticationSession callback for the token exchange.
    private var currentVerifier: String?

    // MARK: - Init

    public init(session: URLSession = URLSession(configuration: .ephemeral)) {
        self.session = session
    }
}

// MARK: - Public / internal interface

extension AuthorizationCodePKCEFlow {

    // MARK: 2.3.2 — Verifier generation

    /// Generate a cryptographically random PKCE `code_verifier`.
    ///
    /// - Returns: A base64url-encoded string of 64 random bytes (86 chars after encoding), satisfying
    ///   RFC 7636's [43, 128] length requirement and `[A-Za-z0-9\-._~]` charset.
    /// - Throws: `PKCEFlowError.rngFailure` when the system RNG fails.
    func generateVerifier() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 64)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw PKCEFlowError.rngFailure
        }
        // base64url without padding satisfies RFC 7636 charset requirements.
        return Data(bytes)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: 2.3.3 — Challenge derivation

    /// Compute the S256 `code_challenge` for a given verifier.
    ///
    /// Formula: `BASE64URL(SHA256(ASCII(verifier)))` — no padding.
    func challenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: 2.3.4 — Authorization URL

    /// Build the Salesforce authorization URL for an OAuth PKCE authorization code request.
    ///
    /// Stores the generated verifier internally so `publisher` can pass it to `exchangeCode`.
    func authorizationURL(host: String, consumerKey: String, callbackURL: URL) throws -> URL {
        let verifier = try generateVerifier()
        let codeChallenge = challenge(for: verifier)

        let parameters: [String: String] = [
            "response_type": "code",
            "client_id": consumerKey,
            "redirect_uri": callbackURL.absoluteString,
            "code_challenge": codeChallenge,
            "code_challenge_method": "S256",
            "prompt": "login consent",
            "display": "touch"
        ]

        guard let url = URLComponents(host: host, path: "/services/oauth2/authorize", queryParameters: parameters).url else {
            throw URLError(.badURL)
        }

        // Keep verifier so the ASWebAuthenticationSession callback can use it.
        self.currentVerifier = verifier
        return url
    }

    // MARK: 2.3.5 — Code exchange

    /// POST the authorization `code` + `code_verifier` to `/services/oauth2/token`.
    ///
    /// The request body contains `code_verifier` (the original random bytes) NOT `code_challenge`.
    /// The response is decoded as URL-encoded form data (9.0.3 native format) into `Credential`.
    func exchangeCode(
        _ code: String,
        verifier: String,
        consumerKey: String,
        callbackURL: URL,
        host: String
    ) -> AnyPublisher<Credential, Error> {
        guard let url = URL(string: "https://\(host)/services/oauth2/token") else {
            return Fail(error: URLError(.badURL)).eraseToAnyPublisher()
        }

        let params: [String: String] = [
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": consumerKey,
            "redirect_uri": callbackURL.absoluteString,
            "format": "urlencoded"
        ]

        guard let body = String(byURLEncoding: params)?.data(using: .utf8) else {
            return Fail(error: URLError(.badURL)).eraseToAnyPublisher()
        }

        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringCacheData)
        request.httpMethod = HTTP.Method.post
        request.httpBody = body
        request.setHTTPHeader(HTTP.Header.contentType(HTTP.MIMEType.formUrlEncoded))

        return session.dataTaskPublisher(for: request)
            .mapError { $0 as Error }
            .tryMap { output -> String in
                guard let httpResponse = output.response as? HTTPURLResponse else {
                    throw URLError(.badServerResponse)
                }
                guard (200..<300).contains(httpResponse.statusCode) else {
                    // Surface typed error from urlencoded error body when possible
                    if let bodyString = String(data: output.data, encoding: .utf8),
                       let comps = URLComponents(percentEncodedQuery: bodyString).queryItems,
                       let errorCode = comps["error"] {
                        let desc = comps["error_description"] ?? "OAuth error: \(errorCode)"
                        throw SalesforceError(code: errorCode, message: desc)
                    }
                    throw PKCEFlowError.badServerResponse
                }
                guard let bodyString = String(data: output.data, encoding: .utf8) else {
                    throw URLError(.cannotDecodeRawData)
                }
                return bodyString
            }
            .map { Credential(fromURLEncodedString: $0) }
            .unwrap(orThrow: PKCEFlowError.badServerResponse)
            .eraseToAnyPublisher()
    }

    // MARK: 2.3.6 — Main publisher

    /// Orchestrates the full PKCE flow: verifier → ASWebAuthenticationSession → code exchange → Credential.
    ///
    /// The flow instance (`self`) must be kept alive across the async callback. The recommended
    /// lifetime pattern: in `CredentialManager`, capture `let flow = AuthorizationCodePKCEFlow(...)`,
    /// return `flow.publisher(...).handleEvents(receiveCompletion: { _ in withExtendedLifetime(flow) {} })`.
    func publisher(host: String, consumerKey: String, callbackURL: URL) -> AnyPublisher<Credential, Error> {
        let subject = PassthroughSubject<Credential, Error>()

        guard let scheme = callbackURL.scheme else {
            return Fail(error: URLError(.badURL)).eraseToAnyPublisher()
        }

        let authURL: URL
        do {
            authURL = try authorizationURL(host: host, consumerKey: consumerKey, callbackURL: callbackURL)
        } catch {
            return Fail(error: error).eraseToAnyPublisher()
        }

        let verifier = self.currentVerifier ?? ""

        let asSession = ASWebAuthenticationSession(url: authURL, callbackURLScheme: scheme) { [weak self] url, error in
            guard let self = self else {
                subject.send(completion: .failure(PKCEFlowError.sessionFailure))
                return
            }
            defer {
                self.authenticationSession = nil
                self.presentationContextProvider = nil
                self.currentVerifier = nil
            }

            if let error = error {
                subject.send(completion: .failure(error))
                return
            }

            guard let callbackResult = url else {
                subject.send(completion: .failure(PKCEFlowError.missingCode))
                return
            }

            do {
                let code = try self.extractCode(from: callbackResult)
                self.exchangeCode(code, verifier: verifier, consumerKey: consumerKey, callbackURL: callbackURL, host: host)
                    .sink(
                        receiveCompletion: { completion in
                            if case let .failure(err) = completion {
                                subject.send(completion: .failure(err))
                            }
                        },
                        receiveValue: { credential in
                            subject.send(credential)
                            subject.send(completion: .finished)
                        }
                    )
                    .store(in: &self.subscriptions)
            } catch {
                subject.send(completion: .failure(error))
            }
        }

        DispatchQueue.main.async { [weak self] in
            guard let self = self else {
                subject.send(completion: .failure(PKCEFlowError.sessionFailure))
                return
            }
            self.presentationContextProvider = PKCEPresentationAnchor()
            asSession.presentationContextProvider = self.presentationContextProvider
            guard asSession.canStart, asSession.start() else {
                subject.send(completion: .failure(PKCEFlowError.sessionFailure))
                self.authenticationSession = nil
                self.presentationContextProvider = nil
                self.currentVerifier = nil
                return
            }
        }

        // Store session so it survives until the callback fires.
        self.authenticationSession = asSession

        return subject.eraseToAnyPublisher()
    }

    // MARK: 2.2.3 helper — code extraction (testable without a live session)

    /// Extract the `code` query parameter from an ASWebAuthenticationSession callback URL.
    ///
    /// - Throws: `PKCEFlowError.missingCode` when the parameter is absent or empty.
    func extractCode(from url: URL) throws -> String {
        guard let code = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { $0.name == "code" })?
            .value,
              !code.isEmpty
        else {
            throw PKCEFlowError.missingCode
        }
        return code
    }
}

// MARK: - Presentation anchor (connectedScenes — iOS 13+ / not deprecated)

/// Provides the key window via `connectedScenes`, replacing the deprecated
/// `UIApplication.shared.windows` lookup used in the reference implementation.
private final class PKCEPresentationAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if canImport(UIKit)
        if let windowScene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first {
            if #available(iOS 15, *) {
                return windowScene.keyWindow ?? ASPresentationAnchor()
            } else {
                return windowScene.windows.first(where: { $0.isKeyWindow }) ?? ASPresentationAnchor()
            }
        }
        #endif
        return ASPresentationAnchor()
    }
}
