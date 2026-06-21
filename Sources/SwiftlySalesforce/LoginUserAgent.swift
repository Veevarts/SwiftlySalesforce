import Foundation

/// Seam that owns the "present an authorize URL and capture the redirect URL" step.
/// Implementations include `WebAuthUserAgent` (ASWebAuthenticationSession) and,
/// in PR2, `EmbeddedWebViewUserAgent` (WKWebView).
/// The PKCE URL-build and token-exchange steps remain in `OAuthFlow` and are NOT
/// part of this protocol's responsibility.
@MainActor public protocol LoginUserAgent {
    /// Present `url` to the user and return the redirect URL (carrying `code`)
    /// once the authorization server redirects to a URL prefixed by `redirectURI`.
    /// Throws on cancellation, OAuth error, or any other failure.
    func authorize(url: URL, redirectURI: URL) async throws -> URL
}

// MARK: - RedirectMatcher

/// Pure, UIKit-free helper that decides whether a navigation candidate URL
/// is the authorization redirect the app is waiting for.
///
/// Matching rule: the candidate's absolute string must have the callback URL's
/// absolute string as a case-insensitive prefix, AND the character immediately
/// after that prefix in the candidate must be a query separator (`?`), fragment
/// separator (`#`), path separator (`/`), or end-of-string.  This prevents
/// false positives such as `myapp://oauth/callbackEXTRA` matching against
/// `myapp://oauth/callback` (path-boundary fix, RFC 8252 §8.12).
///
/// This covers:
///   - exact match (no query params)
///   - redirect carrying query params (?code=…&state=…)
///   - redirect carrying an OAuth error (?error=access_denied)
///
/// It does NOT match:
///   - intermediate Salesforce pages (different scheme/host/path)
///   - other apps' custom scheme URIs (different scheme)
///   - URLs that share the callback as a raw string prefix but differ at a
///     path-segment boundary (e.g. `myapp://oauth/callbackEXTRA`)
enum RedirectMatcher {

    /// Returns `true` when `candidate` starts with the `callback` URL prefix
    /// on a path/query boundary (scheme + authority + path), case-insensitively.
    static func isRedirect(_ candidate: URL, callback: URL) -> Bool {
        let candidateString = candidate.absoluteString.lowercased()
        let callbackString  = callback.absoluteString.lowercased()
        guard candidateString.hasPrefix(callbackString) else { return false }
        // Verify the character immediately after the prefix is a valid boundary.
        // Valid boundaries:
        //   - end-of-string: exact match
        //   - '?': query begins (e.g. ?code=abc)
        //   - '#': fragment begins
        //   - '/' followed immediately by '?', '#', or end-of-string:
        //         trailing slash on candidate path (e.g. myapp://oauth/callback/?code=abc)
        // NOT valid: '/' followed by more path components (deeper sub-paths such as /extra)
        let afterPrefix = candidateString.dropFirst(callbackString.count)
        if afterPrefix.isEmpty { return true }
        let next = afterPrefix.first!
        if next == "?" || next == "#" { return true }
        if next == "/" {
            // Only allow the trailing-slash case: the slash must be followed by nothing,
            // or immediately by a query/fragment separator.
            let afterSlash = afterPrefix.dropFirst()
            if afterSlash.isEmpty { return true }
            let nextNext = afterSlash.first!
            return nextNext == "?" || nextNext == "#"
        }
        return false
    }
}
