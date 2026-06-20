import XCTest
@testable import SwiftlySalesforce

final class PKCETests: XCTestCase {

    // RFC 7636 unreserved characters allowed in a code verifier.
    private let unreserved = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    func testThatVerifierHasValidLengthAndAlphabet() {
        for _ in 0..<100 {
            let verifier = PKCE.makeVerifier()
            XCTAssertTrue((43...128).contains(verifier.count), "Verifier length \(verifier.count) out of RFC 7636 range")
            XCTAssertTrue(verifier.allSatisfy { unreserved.contains($0) }, "Verifier contains a non-unreserved character")
        }
    }

    func testThatVerifiersAreUnique() {
        let sample = (0..<50).map { _ in PKCE.makeVerifier() }
        XCTAssertEqual(Set(sample).count, sample.count, "Verifiers must not repeat")
    }

    func testThatChallengeMatchesRFC7636Vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        XCTAssertEqual(PKCE.challenge(for: verifier), expectedChallenge)
    }

    func testThatInstanceBindsVerifierToItsChallenge() {
        let pkce = PKCE()
        XCTAssertEqual(pkce.challenge, PKCE.challenge(for: pkce.verifier))
    }
}
