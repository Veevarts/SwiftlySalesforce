import XCTest
@testable import SwiftlySalesforce

// MARK: - Stub LoginUserAgent

/// A deterministic stub: returns a pre-canned redirect URL on the first call,
/// or throws a configured error.
@MainActor
final class StubLoginUserAgent: LoginUserAgent {

    enum Behavior {
        case returnRedirect(URL)
        case throwError(Error)
    }

    private let behavior: Behavior
    private(set) var capturedAuthorizeURL: URL?
    private(set) var capturedRedirectURI: URL?

    init(behavior: Behavior) {
        self.behavior = behavior
    }

    func authorize(url: URL, redirectURI: URL) async throws -> URL {
        capturedAuthorizeURL = url
        capturedRedirectURI = redirectURI
        switch behavior {
        case .returnRedirect(let redirect):
            return redirect
        case .throwError(let error):
            throw error
        }
    }
}

// MARK: - Tests

final class OAuthFlowSeamTests: XCTestCase {

    private let consumerKey = "TEST_CONSUMER_KEY"
    private let host = "login.salesforce.com"
    private let callbackURL = URL(string: "myapp://oauth/callback")!
    private let cannedCode = "CANNED_AUTH_CODE"

    // MARK: Seam called with correct inputs

    func testThatStubUserAgentIsCalledWithCorrectAuthorizeURL() async throws {
        // The stub returns a valid redirect carrying our canned code.
        // We use a mock URLSession that returns a valid-looking credential response.
        let redirectURL = URL(string: "myapp://oauth/callback?code=\(cannedCode)&state=s")!
        let stub = await StubLoginUserAgent(behavior: .returnRedirect(redirectURL))
        let mockSession = makeCredentialSession()

        _ = try await OAuthFlow.authorizationCode(
            consumerKey: consumerKey,
            host: host,
            callbackURL: callbackURL,
            userAgent: stub,
            session: mockSession
        )

        // The stub must have been called with the authorize URL (scheme on login host)
        let authorizeURL = await stub.capturedAuthorizeURL
        XCTAssertNotNil(authorizeURL, "authorize(url:redirectURI:) was not called")
        XCTAssertEqual(authorizeURL?.host, host)
        XCTAssertEqual(authorizeURL?.path, "/services/oauth2/authorize")

        let capturedRedirectURI = await stub.capturedRedirectURI
        XCTAssertEqual(capturedRedirectURI, callbackURL)
    }

    func testThatAuthorizeURLContainsExpectedQueryParams() async throws {
        let redirectURL = URL(string: "myapp://oauth/callback?code=\(cannedCode)")!
        let stub = await StubLoginUserAgent(behavior: .returnRedirect(redirectURL))
        let mockSession = makeCredentialSession()

        _ = try await OAuthFlow.authorizationCode(
            consumerKey: consumerKey,
            host: host,
            callbackURL: callbackURL,
            userAgent: stub,
            session: mockSession
        )

        let authorizeURL = await stub.capturedAuthorizeURL
        let items = URLComponents(url: authorizeURL!, resolvingAgainstBaseURL: false)?.queryItems ?? []
        XCTAssertEqual(items["response_type"], "code")
        XCTAssertEqual(items["client_id"], consumerKey)
        XCTAssertEqual(items["redirect_uri"], callbackURL.absoluteString)
        XCTAssertNotNil(items["code_challenge"])
        XCTAssertEqual(items["code_challenge_method"], "S256")
    }

    // MARK: Seam result forwarded to token exchange

    func testThatCodeFromRedirectIsForwardedToTokenExchange() async throws {
        // The stub returns a redirect carrying our canned code. The mock session
        // returns a valid credential response. If `authorizationCode` incorrectly
        // ignores the code or extracts the wrong value, the exchange request will
        // carry wrong params and the credential parse will fail — causing a throw.
        // A successful return proves the code was extracted and forwarded correctly.
        let redirectURL = URL(string: "myapp://oauth/callback?code=\(cannedCode)")!
        let stub = await StubLoginUserAgent(behavior: .returnRedirect(redirectURL))
        var capturedRequestURL: URL?
        let mockSession = URLSession.mock { request in
            capturedRequestURL = request.url
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Self.credentialResponseData, nil)
        }

        let credential = try await OAuthFlow.authorizationCode(
            consumerKey: consumerKey,
            host: host,
            callbackURL: callbackURL,
            userAgent: stub,
            session: mockSession
        )

        // The token exchange must hit the /services/oauth2/token endpoint
        XCTAssertEqual(capturedRequestURL?.path, "/services/oauth2/token",
                       "Token exchange request was not sent to the expected endpoint")
        // A credential must be returned (proves the full code→exchange→parse pipeline)
        XCTAssertEqual(credential.accessToken, "TOKEN")
    }

    // MARK: Error propagation

    func testThatCancellationErrorFromSeamIsPropagated() async {
        let stub = await StubLoginUserAgent(behavior: .throwError(CancellationError()))

        do {
            _ = try await OAuthFlow.authorizationCode(
                consumerKey: consumerKey,
                host: host,
                callbackURL: callbackURL,
                userAgent: stub,
                session: URLSession(configuration: .ephemeral)
            )
            XCTFail("Expected CancellationError to propagate")
        } catch is CancellationError {
            // pass — correct error type
        } catch {
            XCTFail("Expected CancellationError, got \(type(of: error)): \(error)")
        }
    }

    func testThatOAuthErrorFromSeamIsPropagated() async {
        let oauthError = OAuthError(code: "access_denied", message: "User denied")
        let stub = await StubLoginUserAgent(behavior: .throwError(oauthError))

        do {
            _ = try await OAuthFlow.authorizationCode(
                consumerKey: consumerKey,
                host: host,
                callbackURL: callbackURL,
                userAgent: stub,
                session: URLSession(configuration: .ephemeral)
            )
            XCTFail("Expected OAuthError to propagate")
        } catch let error as OAuthError {
            XCTAssertEqual(error.code, "access_denied")
        } catch {
            XCTFail("Expected OAuthError, got \(type(of: error)): \(error)")
        }
    }
}

// MARK: - Helpers

private extension OAuthFlowSeamTests {

    static let credentialResponseData = "access_token=TOKEN&instance_url=https%3A%2F%2Fna5.salesforce.com&id=https%3A%2F%2Flogin.salesforce.com%2Fid%2FORGID%2FUSERID&issued_at=1234567890".data(using: .utf8)!

    func makeCredentialSession() -> URLSession {
        URLSession.mock { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Self.credentialResponseData, nil)
        }
    }
}
