import Foundation

struct OAuthFlow {
    
    /// Interactive login via the OAuth 2.0 authorization-code flow with PKCE (S256).
    ///
    /// The `userAgent` parameter handles only the "present authorize URL and
    /// capture the redirect URL" step. All PKCE URL-build and token-exchange
    /// logic remain here, unchanged.
    ///
    /// The default value of `userAgent` (`WebAuthUserAgent.shared`) preserves
    /// the pre-seam behavior: `ASWebAuthenticationSession` is used. Callers that
    /// do not pass `userAgent` explicitly — including `DefaultAuthorizer` — are
    /// unaffected. PR2 will wire `EmbeddedWebViewUserAgent` via `LoginMode`.
    static func authorizationCode(
        consumerKey: String,
        host: String,
        callbackURL: URL,
        userAgent: LoginUserAgent = WebAuthUserAgent.shared,
        session: URLSession = URLSession(configuration: .ephemeral)
    ) async throws -> Credential {

        let pkce = PKCE()
        let authURL = try URL.authorizationCodeFlow(host: host, clientID: consumerKey, callbackURL: callbackURL, codeChallenge: pkce.challenge)
        let redirectURL = try await userAgent.authorize(url: authURL, redirectURI: callbackURL)
        let code = try authorizationCode(from: redirectURL)
        let request = try URLRequest.authorizationCodeExchange(host: host, clientID: consumerKey, callbackURL: callbackURL, code: code, codeVerifier: pkce.verifier)
        let (response, _) = try await session.data(for: request)
        return try parse(encodedString: String(data: response)) {
            Credential(fromPercentEncoded: $0)
        }
    }

    /// Extracts the authorization `code` from the redirect URL's query, or throws the OAuth error it carries.
    ///
    /// `error_description` values in OAuth redirect URLs use `application/x-www-form-urlencoded`
    /// encoding where `+` represents a space character.  `URLComponents.queryItems` does NOT
    /// decode `+` as space (it only percent-decodes), so we do it explicitly here.
    static func authorizationCode(from url: URL) throws -> String {
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if let code = comps?.queryItems?["code"], !code.isEmpty {
            return code
        }
        if let error = comps?.queryItems?["error"] {
            // Decode '+' → ' ' in error_description per form-encoding convention.
            let rawDescription = comps?.queryItems?["error_description"]
            let description = rawDescription?.replacingOccurrences(of: "+", with: " ")
            throw OAuthError(code: error, message: description)
        }
        throw URLError(.badServerResponse)
    }

    static func refreshToken(
        consumerKey: String,
        host: String,
        refreshToken: String,
        session: URLSession = URLSession(configuration: .ephemeral)
    ) async throws -> Credential {

        let req = try URLRequest.refreshTokenFlow(host: host, clientID: consumerKey, refreshToken: refreshToken)
        let (response, _) = try await session.data(for: req)
        return try parse(encodedString: String(data: response)) {
            Credential(fromPercentEncoded: $0, andRefreshToken: refreshToken)
        }
    }
    
    static func revokeToken(
        host: String,
        token: String,
        session: URLSession = URLSession(configuration: .ephemeral)
    ) async throws -> Void {
        
        let req = try URLRequest.revokeTokenFlow(host: host, token: token)
        let (response, _) = try await session.data(for: req)
        return try parse(encodedString: String(data: response)) {
             $0 == "" ? Void() : nil
        }
    }
}

private extension OAuthFlow {
    
    static func parse<T>(encodedString: String?, with parser: (String) -> T?) throws -> T {
        if let t = encodedString.flatMap({ parser($0) }) {
            return t
        }
        if let err = encodedString.flatMap({ OAuthError(fromPercentEncodedString: $0) }) {
            throw err
        }
        throw URLError(.badServerResponse)
    }
}
