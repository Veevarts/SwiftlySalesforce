import Foundation

/// `LoginUserAgent` implementation backed by `ASWebAuthenticationSession`
/// (via the existing `WebAuthenticationSession` wrapper).
///
/// This is the default user agent, which preserves the behavior that existed
/// before the `LoginUserAgent` seam was introduced: the system presents the
/// authorize URL in a secure, isolated browser session managed by the OS.
///
/// UIKit-free — uses only `AuthenticationServices` / Foundation types.
@MainActor
public final class WebAuthUserAgent: LoginUserAgent {

    public static let shared = WebAuthUserAgent()

    private init() {}

    /// Presents the authorize URL using `ASWebAuthenticationSession` and
    /// returns the redirect URL once the authorization server redirects to
    /// a URL whose scheme matches the scheme component of `redirectURI`.
    public func authorize(url: URL, redirectURI: URL) async throws -> URL {
        guard let scheme = redirectURI.scheme else {
            throw URLError(.badURL, userInfo: [NSURLErrorFailingURLStringErrorKey: redirectURI])
        }
        return try await WebAuthenticationSession.shared.start(url: url, callbackURLScheme: scheme)
    }
}
