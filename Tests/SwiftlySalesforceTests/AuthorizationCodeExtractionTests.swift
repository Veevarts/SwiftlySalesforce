import XCTest
@testable import SwiftlySalesforce

final class AuthorizationCodeExtractionTests: XCTestCase {

    // MARK: - Code present

    func testThatCodePresentInRedirectURLIsExtracted() throws {
        let redirect = URL(string: "myapp://oauth/callback?code=AUTHCODE&state=S")!
        XCTAssertEqual(try OAuthFlow.authorizationCode(from: redirect), "AUTHCODE")
    }

    func testThatCodeWithAdditionalParamsIsExtracted() throws {
        let redirect = URL(string: "myapp://oauth/callback?state=xyz&code=MY_CODE&other=value")!
        XCTAssertEqual(try OAuthFlow.authorizationCode(from: redirect), "MY_CODE")
    }

    // MARK: - OAuth error surfaces as typed error

    func testThatOAuthErrorParamThrowsOAuthError() {
        let redirect = URL(string: "myapp://oauth/callback?error=access_denied&error_description=User+denied+access")!
        XCTAssertThrowsError(try OAuthFlow.authorizationCode(from: redirect)) { error in
            guard let oauthError = error as? OAuthError else {
                return XCTFail("Expected OAuthError, got \(type(of: error))")
            }
            XCTAssertEqual(oauthError.code, "access_denied")
            // Verify finding: '+' in error_description must decode to ' ' (space).
            // OAuth redirect parameters use application/x-www-form-urlencoded encoding
            // where '+' represents a space character.
            XCTAssertEqual(oauthError.message, "User denied access",
                           "'+' in error_description must be decoded as space, not kept as '+'")
        }
    }

    func testThatOAuthErrorWithoutDescriptionThrowsOAuthError() {
        let redirect = URL(string: "myapp://oauth/callback?error=invalid_request")!
        XCTAssertThrowsError(try OAuthFlow.authorizationCode(from: redirect)) { error in
            guard let oauthError = error as? OAuthError else {
                return XCTFail("Expected OAuthError, got \(type(of: error))")
            }
            XCTAssertEqual(oauthError.code, "invalid_request")
            XCTAssertNil(oauthError.message)
        }
    }

    // MARK: - Malformed redirect (neither code nor error)

    func testThatNoParamsThrowsURLError() {
        let redirect = URL(string: "myapp://oauth/callback")!
        XCTAssertThrowsError(try OAuthFlow.authorizationCode(from: redirect)) { error in
            guard let urlError = error as? URLError else {
                return XCTFail("Expected URLError, got \(type(of: error))")
            }
            XCTAssertEqual(urlError.code, .badServerResponse)
        }
    }

    func testThatEmptyCodeThrowsURLError() {
        // An empty `code` param is not a valid code — should fall through to URLError
        let redirect = URL(string: "myapp://oauth/callback?code=")!
        XCTAssertThrowsError(try OAuthFlow.authorizationCode(from: redirect)) { error in
            // Either URLError or something else, but it MUST throw — not silently return ""
            XCTAssertNotNil(error)
        }
    }

    func testThatUnrelatedParamsThrowsURLError() {
        let redirect = URL(string: "myapp://oauth/callback?state=xyz")!
        XCTAssertThrowsError(try OAuthFlow.authorizationCode(from: redirect)) { error in
            guard let urlError = error as? URLError else {
                return XCTFail("Expected URLError, got \(type(of: error))")
            }
            XCTAssertEqual(urlError.code, .badServerResponse)
        }
    }
}
