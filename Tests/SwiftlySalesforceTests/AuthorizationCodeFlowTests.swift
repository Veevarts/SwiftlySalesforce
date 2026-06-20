import XCTest
@testable import SwiftlySalesforce

final class AuthorizationCodeFlowTests: XCTestCase {

    private let clientID = "CONSUMER_KEY"
    private let callbackURL = URL(string: "myapp://callback")!
    private let host = "login.salesforce.com"

    func testThatAuthorizeURLCarriesPKCEChallengeAndCodeResponseType() throws {
        // When
        let url = try URL.authorizationCodeFlow(host: host, clientID: clientID, callbackURL: callbackURL, codeChallenge: "CHALLENGE")
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems ?? []

        // Then
        XCTAssertEqual(url.path, "/services/oauth2/authorize")
        XCTAssertEqual(items["response_type"], "code")
        XCTAssertNotEqual(items["response_type"], "token")
        XCTAssertEqual(items["code_challenge"], "CHALLENGE")
        XCTAssertEqual(items["code_challenge_method"], "S256")
        XCTAssertEqual(items["client_id"], clientID)
        XCTAssertEqual(items["redirect_uri"], callbackURL.absoluteString)
    }

    func testThatExchangeRequestIsAuthorizationCodeGrant() throws {
        // When
        let request = try URLRequest.authorizationCodeExchange(host: host, clientID: clientID, callbackURL: callbackURL, code: "AUTH_CODE", codeVerifier: "VERIFIER")
        let body = String(data: request.httpBody!)!
        let params = URLComponents(percentEncodedQuery: body).queryItems ?? []

        // Then
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.path, "/services/oauth2/token")
        XCTAssertEqual(params["grant_type"], "authorization_code")
        XCTAssertEqual(params["code"], "AUTH_CODE")
        XCTAssertEqual(params["code_verifier"], "VERIFIER")
        XCTAssertEqual(params["client_id"], clientID)
        XCTAssertEqual(params["redirect_uri"], callbackURL.absoluteString)
    }

    func testThatItExtractsAuthorizationCodeFromRedirectQuery() throws {
        let redirect = URL(string: "myapp://callback?code=THE_CODE&state=xyz")!
        XCTAssertEqual(try OAuthFlow.authorizationCode(from: redirect), "THE_CODE")
    }

    func testThatMissingCodeThrows() {
        let redirect = URL(string: "myapp://callback?error=access_denied")!
        XCTAssertThrowsError(try OAuthFlow.authorizationCode(from: redirect))
    }
}
