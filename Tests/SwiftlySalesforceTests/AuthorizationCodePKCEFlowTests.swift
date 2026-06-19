/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine
import XCTest
import CryptoKit
import AuthenticationServices
@testable import SwiftlySalesforce

class AuthorizationCodePKCEFlowTests: XCTestCase {

    var cancellables = Set<AnyCancellable>()

    override func setUpWithError() throws {
        cancellables = []
    }

    override func tearDownWithError() throws {
        MockURLProtocol.requestHandler = nil
    }

    // MARK: - Task 2.1.1 — Verifier has valid length and charset (REQ-PKCE-02, PKCE-S02)

    func testGeneratesValidVerifier() throws {
        let flow = AuthorizationCodePKCEFlow(session: .shared)
        let verifier = try flow.generateVerifier()

        // RFC 7636: verifier must be 43–128 chars
        XCTAssertGreaterThanOrEqual(verifier.count, 43)
        XCTAssertLessThanOrEqual(verifier.count, 128)

        // Must use only unreserved / base64url chars
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        XCTAssertTrue(verifier.unicodeScalars.allSatisfy { allowed.contains($0) },
                      "Verifier contains disallowed character(s): \(verifier)")
    }

    // MARK: - Task 2.1.2 — S256 challenge derivation (REQ-PKCE-03, PKCE-S02)

    func testS256ChallengeDerivation() throws {
        let flow = AuthorizationCodePKCEFlow(session: .shared)

        // Known input / expected output pair so we can verify the formula exactly.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

        // Expected: BASE64URL(SHA256(ASCII(verifier))), no padding
        let data = Data(verifier.utf8)
        let digest = SHA256.hash(data: data)
        let expected = Data(digest)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let challenge = flow.challenge(for: verifier)
        XCTAssertEqual(challenge, expected, "S256 challenge must be BASE64URL(SHA256(verifier)) with no padding")
        XCTAssertFalse(challenge.contains("="), "Challenge must have no padding")
    }

    // MARK: - Task 2.1.3 — Authorization URL contains required params (REQ-PKCE-04, PKCE-S02)

    func testAuthorizationURLContainsRequiredParams() throws {
        let flow = AuthorizationCodePKCEFlow(session: .shared)
        let callbackURL = URL(string: "myapp://oauth/callback")!
        let url = try flow.authorizationURL(host: "login.salesforce.com",
                                            consumerKey: "my-consumer-key",
                                            callbackURL: callbackURL)

        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let items = comps?.queryItems ?? []
        func param(_ name: String) -> String? {
            items.first(where: { $0.name == name })?.value
        }

        XCTAssertEqual(param("response_type"), "code")
        XCTAssertEqual(param("client_id"), "my-consumer-key")
        XCTAssertEqual(param("redirect_uri"), callbackURL.absoluteString)
        XCTAssertNotNil(param("code_challenge"), "code_challenge must be present")
        XCTAssertEqual(param("code_challenge_method"), "S256")
    }

    // MARK: - Task 2.2.1 — exchangeCode parses Credential (REQ-PKCE-05, REQ-PKCE-06, PKCE-S01)

    func testExchangeCodeParsesCredential() throws {
        // Given: mock token endpoint returning urlencoded body
        let responseBody = [
            "access_token=test-access",
            "instance_url=https%3A%2F%2Forg.salesforce.com",
            "id=https%3A%2F%2Flogin.salesforce.com%2Fid%2Forg%2Fuser",
            "refresh_token=test-refresh",
            "id_token=test-id-token"
        ].joined(separator: "&")

        MockURLProtocol.requestHandler = { _ in
            let response = HTTPURLResponse(
                url: URL(string: "https://login.salesforce.com/services/oauth2/token")!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/x-www-form-urlencoded"]
            )!
            return (response, responseBody.data(using: .utf8)!)
        }

        let session = mockURLSession()
        let flow = AuthorizationCodePKCEFlow(session: session)

        let credential = try waitFor(
            flow.exchangeCode(
                "auth-code-123",
                verifier: "verifier-abc",
                consumerKey: "consumer-key",
                callbackURL: URL(string: "myapp://oauth/callback")!,
                host: "login.salesforce.com"
            )
        )

        XCTAssertEqual(credential.accessToken, "test-access")
        XCTAssertEqual(credential.refreshToken, "test-refresh")
        XCTAssertEqual(credential.idToken, "test-id-token")
        XCTAssertEqual(credential.instanceURL, URL(string: "https://org.salesforce.com")!)
    }

    // MARK: - Task 2.2.2 — Token exchange sends code_verifier, NOT code_challenge (REQ-PKCE-05, PKCE-S03)

    func testCodeVerifierSentNotChallenge() throws {
        var capturedRequest: URLRequest?

        let responseBody = [
            "access_token=a",
            "instance_url=https%3A%2F%2Forg.salesforce.com",
            "id=https%3A%2F%2Flogin.salesforce.com%2Fid%2Forg%2Fuser"
        ].joined(separator: "&")

        MockURLProtocol.requestHandler = { req in
            capturedRequest = req
            let response = HTTPURLResponse(
                url: req.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/x-www-form-urlencoded"]
            )!
            return (response, responseBody.data(using: .utf8)!)
        }

        let session = mockURLSession()
        let flow = AuthorizationCodePKCEFlow(session: session)
        let verifier = "my-secret-verifier"

        _ = try waitFor(
            flow.exchangeCode(
                "code-xyz",
                verifier: verifier,
                consumerKey: "ck",
                callbackURL: URL(string: "myapp://cb")!,
                host: "login.salesforce.com"
            )
        )

        // Parse the request body — URLSession moves httpBody → httpBodyStream in the intercepted request
        let bodyData: Data? = capturedRequest.flatMap { req -> Data? in
            if let data = req.httpBody { return data }
            guard let stream = req.httpBodyStream else { return nil }
            stream.open()
            defer { stream.close() }
            var data = Data()
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
            defer { buffer.deallocate() }
            while stream.hasBytesAvailable {
                let count = stream.read(buffer, maxLength: 4096)
                guard count > 0 else { break }
                data.append(buffer, count: count)
            }
            return data
        }
        let body = bodyData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let comps = URLComponents(percentEncodedQuery: body)
        let items = comps.queryItems ?? []
        func param(_ name: String) -> String? {
            items.first(where: { $0.name == name })?.value
        }

        XCTAssertEqual(param("code_verifier"), verifier, "Request body must contain the original code_verifier")
        XCTAssertNil(param("code_challenge"), "Request body must NOT contain code_challenge")
    }

    // MARK: - Task 2.2.3 — Callback URL without 'code' causes error (PKCE-S05)

    func testMissingCodeInCallbackErrors() throws {
        let flow = AuthorizationCodePKCEFlow(session: .shared)

        // Callback URL missing the 'code' query param
        let callbackURL = URL(string: "myapp://oauth/callback?state=xyz")!

        var thrownError: Error?
        XCTAssertThrowsError(try flow.extractCode(from: callbackURL)) {
            thrownError = $0
        }

        XCTAssertTrue(thrownError is PKCEFlowError,
                      "Expected PKCEFlowError but got \(String(describing: thrownError))")
        XCTAssertEqual(thrownError as? PKCEFlowError, .missingCode)
    }

    // MARK: - Task 2.2.4 — HTTP 400 from token endpoint causes failure (PKCE-S06)

    func testTokenExchangeHTTP400Errors() throws {
        MockURLProtocol.requestHandler = { _ in
            let response = HTTPURLResponse(
                url: URL(string: "https://login.salesforce.com/services/oauth2/token")!,
                statusCode: 400,
                httpVersion: nil,
                headerFields: [:]
            )!
            return (response, "error=invalid_client&error_description=bad+client".data(using: .utf8)!)
        }

        let session = mockURLSession()
        let flow = AuthorizationCodePKCEFlow(session: session)

        var thrownError: Error?
        XCTAssertThrowsError(
            try waitFor(
                flow.exchangeCode(
                    "code",
                    verifier: "verifier",
                    consumerKey: "ck",
                    callbackURL: URL(string: "myapp://cb")!,
                    host: "login.salesforce.com"
                )
            )
        ) {
            thrownError = $0
        }
        XCTAssertNotNil(thrownError, "Publisher must fail on HTTP 400")
    }

    // MARK: - Task 2.2.5 — PKCE is the default AuthMethod (REQ-PKCE-01, REQ-PKCE-08)

    func testPKCEIsDefaultAuthMethod() throws {
        let mgr = CredentialManager(
            consumerKey: "ck",
            callbackURL: URL(string: "myapp://cb")!,
            defaultHost: "login.salesforce.com"
        )
        XCTAssertEqual(mgr.authenticator, .pkce, "CredentialManager.authenticator must default to .pkce")
    }

    // MARK: - Task 2.4.1 (smoke) — connectedScenes anchor doesn't crash (design.md deprecation fix)

    func testWebAuthenticatorAnchorUsesConnectedScenes() throws {
        // Smoke test: instantiating and calling presentationAnchor must not crash
        // (live ASWebAuthenticationSession can't run headless; we just verify the
        //  non-deprecated code path compiles and executes without a crash).
        let authenticator = WebAuthenticator(
            authURL: URL(string: "https://login.salesforce.com/services/oauth2/authorize")!,
            callbackURLScheme: "myapp"
        )
        let dummySession = ASWebAuthenticationSession(
            url: URL(string: "https://example.com")!,
            callbackURLScheme: "myapp"
        ) { _, _ in }

        // Must not throw / crash — connectedScenes path used on iOS 15+
        let anchor = authenticator.presentationAnchor(for: dummySession)
        XCTAssertNotNil(anchor, "presentationAnchor must return a non-nil anchor")
    }
}
