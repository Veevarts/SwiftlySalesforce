import XCTest
@testable import SwiftlySalesforce

final class RedirectMatcherTests: XCTestCase {

    private let callback = URL(string: "myapp://oauth/callback")!

    // MARK: - Matching redirect URLs

    func testThatMatchingRedirectWithCodeReturnsTrue() {
        let candidate = URL(string: "myapp://oauth/callback?code=abc&state=xyz")!
        XCTAssertTrue(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    func testThatExactCallbackURLReturnsTrue() {
        XCTAssertTrue(RedirectMatcher.isRedirect(callback, callback: callback))
    }

    func testThatMatchingRedirectWithOAuthErrorReturnsTrue() {
        // Even an error redirect should be recognized as a redirect (caller will parse the error)
        let candidate = URL(string: "myapp://oauth/callback?error=access_denied&error_description=User+denied+access")!
        XCTAssertTrue(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    // MARK: - Non-matching intermediate Salesforce pages

    func testThatIntermediateSalesforcePageReturnsFalse() {
        let candidate = URL(string: "https://login.salesforce.com/setup/secur/RemoteAccessAuthorizationPage.apexp")!
        XCTAssertFalse(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    func testThatDifferentSchemeReturnsFalse() {
        let candidate = URL(string: "otherapp://oauth/callback?code=abc")!
        XCTAssertFalse(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    func testThatDifferentHostReturnsFalse() {
        let candidate = URL(string: "myapp://other/callback?code=abc")!
        XCTAssertFalse(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    func testThatDifferentPathReturnsFalse() {
        let candidate = URL(string: "myapp://oauth/other?code=abc")!
        XCTAssertFalse(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    // MARK: - Edge cases

    func testThatCallbackWithTrailingSlashMatchesWithoutTrailingSlash() {
        // callback ends with slash, candidate does not — should still match (prefix semantics)
        let callbackWithSlash = URL(string: "myapp://oauth/callback/")!
        let candidate = URL(string: "myapp://oauth/callback/?code=abc")!
        XCTAssertTrue(RedirectMatcher.isRedirect(candidate, callback: callbackWithSlash))
    }

    func testThatCandidateWithTrailingSlashMatchesCallbackWithoutTrailingSlash() {
        // Both sides include the slash variant — prefix match covers it
        let candidate = URL(string: "myapp://oauth/callback/?code=abc")!
        XCTAssertTrue(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    func testThatMatchingIsCaseInsensitive() {
        let candidate = URL(string: "MYAPP://oauth/callback?code=abc")!
        XCTAssertTrue(RedirectMatcher.isRedirect(candidate, callback: callback))
    }

    // MARK: - Path-boundary fix (verify finding)

    /// A URL that has the callback as a raw string prefix but NOT on a path/query boundary
    /// must NOT be treated as a redirect.  Example: `myapp://oauth/callbackEXTRA` shares
    /// the prefix `myapp://oauth/callback` but the path diverges at `EXTRA`.
    func testThatURLWithCallbackAsRawStringPrefixButDifferentPathReturnsFalse() {
        // "callbackEXTRA" is NOT the callback path "callback" — must NOT match
        let spuriousCandidate = URL(string: "myapp://oauth/callbackEXTRA?code=abc")!
        XCTAssertFalse(RedirectMatcher.isRedirect(spuriousCandidate, callback: callback))
    }

    func testThatURLWithCallbackPathExtendedBySegmentReturnsFalse() {
        // "/callback/extra" shares the path prefix but is a deeper path — must NOT match
        let candidate = URL(string: "myapp://oauth/callback/extra?code=abc")!
        XCTAssertFalse(RedirectMatcher.isRedirect(candidate, callback: callback))
    }
}
