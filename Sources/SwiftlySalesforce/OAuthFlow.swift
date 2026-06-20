import Foundation

struct OAuthFlow {
    
    /// Interactive login via the OAuth 2.0 authorization-code flow with PKCE (S256).
    static func authorizationCode(
        consumerKey: String,
        host: String,
        callbackURL: URL,
        session: URLSession = URLSession(configuration: .ephemeral)
    ) async throws -> Credential {

        let pkce = PKCE()
        let authURL = try URL.authorizationCodeFlow(host: host, clientID: consumerKey, callbackURL: callbackURL, codeChallenge: pkce.challenge)
        guard let scheme = callbackURL.scheme else {
            throw URLError(.badURL, userInfo: [NSURLErrorFailingURLStringErrorKey: callbackURL])
        }
        let redirectURL = try await WebAuthenticationSession.shared.start(url: authURL, callbackURLScheme: scheme)
        let code = try authorizationCode(from: redirectURL)
        let request = try URLRequest.authorizationCodeExchange(host: host, clientID: consumerKey, callbackURL: callbackURL, code: code, codeVerifier: pkce.verifier)
        let (response, _) = try await session.data(for: request)
        return try parse(encodedString: String(data: response)) {
            Credential(fromPercentEncoded: $0)
        }
    }

    /// Extracts the authorization `code` from the redirect URL's query, or throws the OAuth error it carries.
    static func authorizationCode(from url: URL) throws -> String {
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if let code = comps?.queryItems?["code"], !code.isEmpty {
            return code
        }
        if let error = comps?.queryItems?["error"] {
            throw OAuthError(code: error, message: comps?.queryItems?["error_description"])
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
