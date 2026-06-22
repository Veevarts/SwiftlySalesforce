import XCTest
@testable import SwiftlySalesforce

class PKCETests: XCTestCase {

    func testThatItBase64URLEncodes() {
        // '+' becomes '-', '/' becomes '_', padding stripped
        XCTAssertEqual(Data([0xFB]).base64URLEncodedString(), "-w")          // std base64 "+w=="
        XCTAssertEqual(Data([0xFF, 0xFF]).base64URLEncodedString(), "__8")    // std base64 "//8="
        XCTAssertEqual(Data([0xFF, 0xFF, 0xFF]).base64URLEncodedString(), "____") // std base64 "////"
    }

    func testThatItDerivesChallengeFromVerifier() {
        // RFC 7636 Appendix B known-answer vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        XCTAssertEqual(PKCE.challenge(for: verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    func testThatItGeneratesValidVerifier() {
        let pkce = PKCE()
        XCTAssertEqual(pkce.verifier.count, 43) // 32 random bytes -> 43 base64url chars
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        XCTAssertTrue(pkce.verifier.unicodeScalars.allSatisfy { allowed.contains($0) })
    }

    func testThatGeneratedChallengeMatchesVerifier() {
        let pkce = PKCE()
        XCTAssertEqual(pkce.challenge, PKCE.challenge(for: pkce.verifier))
    }

    func testThatVerifiersAreUnique() {
        XCTAssertNotEqual(PKCE().verifier, PKCE().verifier)
    }
}
