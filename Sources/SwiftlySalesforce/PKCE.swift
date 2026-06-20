import Foundation
import CryptoKit

/// Proof Key for Code Exchange (RFC 7636), using the S256 challenge method.
///
/// A `PKCE` instance binds a freshly generated `verifier` to its derived `challenge` so the value sent
/// to the authorize endpoint (`challenge`) and the value sent to the token endpoint (`verifier`) always
/// correspond to the same transaction.
struct PKCE {

    let verifier: String
    let challenge: String

    init(verifier: String = PKCE.makeVerifier()) {
        self.verifier = verifier
        self.challenge = PKCE.challenge(for: verifier)
    }

    /// A high-entropy code verifier: base64url (no padding) of cryptographically random bytes. Every
    /// character is therefore in the RFC 7636 unreserved set and there is no modulo bias.
    static func makeVerifier(byteCount: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        precondition(status == errSecSuccess, "Unable to generate secure random bytes for the PKCE verifier")
        return Data(bytes).base64URLEncodedString()
    }

    /// The S256 code challenge: base64url( SHA256( ascii(verifier) ) ), no padding.
    static func challenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64URLEncodedString()
    }
}

private extension Data {

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
