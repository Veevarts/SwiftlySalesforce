import XCTest
import Foundation
@testable import SwiftlySalesforce

class AuthorizationCodeFlowTests: XCTestCase {

    let connectedApp = ConnectedApp(consumerKey: "CONSUMER_KEY", callbackURL: URL(string: "testapp://oauthdone")!)

    func testThatAuthorizationURLCarriesPKCE() throws {
        let url = try XCTUnwrap(AuthorizationCodeFlow.authorizationURL(connectedApp: connectedApp, hostname: "login.salesforce.com", challenge: "CHALLENGE"))
        let comps = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let items = Dictionary(uniqueKeysWithValues: (comps.queryItems ?? []).map { ($0.name, $0.value) })
        XCTAssertEqual(comps.path, "/services/oauth2/authorize")
        XCTAssertEqual(items["response_type"], "code")
        XCTAssertEqual(items["code_challenge"], "CHALLENGE")
        XCTAssertEqual(items["code_challenge_method"], "S256")
        XCTAssertEqual(items["client_id"], "CONSUMER_KEY")
        XCTAssertEqual(items["redirect_uri"], "testapp://oauthdone")
    }

    func testThatTokenParametersCarryVerifier() {
        let params = AuthorizationCodeFlow.tokenParameters(code: "AUTHCODE", verifier: "VERIFIER", connectedApp: connectedApp)
        XCTAssertEqual(params["grant_type"], "authorization_code")
        XCTAssertEqual(params["code"], "AUTHCODE")
        XCTAssertEqual(params["code_verifier"], "VERIFIER")
        XCTAssertEqual(params["redirect_uri"], "testapp://oauthdone")
        XCTAssertEqual(params["client_id"], "CONSUMER_KEY")
        XCTAssertNil(params["client_secret"])
    }

    func testThatTokenParametersIncludeClientSecretWhenPresent() {
        let app = ConnectedApp(consumerKey: "CONSUMER_KEY", callbackURL: URL(string: "testapp://oauthdone")!, clientSecret: "SECRET")
        let params = AuthorizationCodeFlow.tokenParameters(code: "AUTHCODE", verifier: "VERIFIER", connectedApp: app)
        XCTAssertEqual(params["client_secret"], "SECRET")
    }

    func testThatItReadsCodeFromCallbackQuery() {
        let url = URL(string: "testapp://oauthdone?code=ABC123&state=xyz")!
        XCTAssertEqual(AuthorizationCodeFlow.code(from: url), "ABC123")
    }

    func testThatItReturnsNilWhenNoCodeInCallback() {
        let url = URL(string: "testapp://oauthdone?error=access_denied")!
        XCTAssertNil(AuthorizationCodeFlow.code(from: url))
    }

    func testThatItDecodesTokenResponseIncludingRefreshToken() throws {
        let json = """
        {
          "access_token": "ACCESS",
          "refresh_token": "REFRESH",
          "instance_url": "https://example.my.salesforce.com",
          "id": "https://login.salesforce.com/id/00Dxx0000001gPL/005xx000001Sv6D",
          "issued_at": "1600000000",
          "token_type": "Bearer"
        }
        """.data(using: .utf8)!
        let cred = try AuthorizationCodeFlow.credential(from: json)
        XCTAssertEqual(cred.accessToken, "ACCESS")
        XCTAssertEqual(cred.refreshToken, "REFRESH")
        XCTAssertEqual(cred.instanceURL, URL(string: "https://example.my.salesforce.com"))
        XCTAssertEqual(cred.issuedAt, 1600000000)
    }
}
