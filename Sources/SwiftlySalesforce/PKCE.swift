//
//  PKCE.swift
//  SwiftlySalesforce
//
//  For license & details see: https://www.github.com/mike4aday/SwiftlySalesforce
//

import Foundation
import CryptoKit

/// Proof Key for Code Exchange (PKCE) parameters for the OAuth authorization-code flow.
/// See [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636).
struct PKCE {

    /// The high-entropy `code_verifier` sent to the token endpoint.
    let verifier: String

    /// The `code_challenge` (S256) sent to the authorization endpoint.
    let challenge: String

    init() {
        let verifier = PKCE.generateVerifier()
        self.verifier = verifier
        self.challenge = PKCE.challenge(for: verifier)
    }

    /// Generates a base64url-encoded code verifier from 32 cryptographically secure
    /// random bytes (43 characters — within the RFC 7636 43–128 range).
    static func generateVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncodedString()
    }

    /// Derives the S256 code challenge: base64url( SHA-256( UTF-8(verifier) ) ).
    static func challenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64URLEncodedString()
    }
}
