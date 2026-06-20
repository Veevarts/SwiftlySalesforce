import Foundation

actor DefaultAuthorizer {

    let consumerKey: String
    let callbackURL: URL
    let defaultHost: String
    private let session: URLSession

    private var authenticatingTask: Task<Credential, Error>?
    private var revokingTask: Task<Void, Error>?

    /// The most recently granted credential, kept in memory as the single source of truth for the
    /// reuse-if-rotated check. Updated inside the serialized refresh task *before* the in-flight marker
    /// is cleared, so a staggered caller observes the rotated credential instead of refreshing a
    /// single-use refresh token that has already been rotated out.
    private var currentCredential: Credential?

    init(consumerKey: String, callbackURL: URL, session: URLSession? = nil, defaultHost: String? = nil) {
        self.consumerKey = consumerKey
        self.callbackURL = callbackURL
        self.defaultHost = defaultHost ?? "login.salesforce.com"
        self.session = session ?? URLSession(configuration: .ephemeral)
    }
}

//MARK: - Authenticator conformance -
extension DefaultAuthorizer: Authorizer {

    func grantCredential(refreshing: Credential? = nil) async throws -> Credential {
        // (1) Coalesce: an authentication/refresh is already in flight for this user — join it.
        if let task = authenticatingTask {
            return try await task.value
        }
        // (2) Reuse-if-rotated: the in-memory credential is already newer than the one the caller used
        // (another request rotated the single-use refresh token). Reuse it instead of refreshing a
        // superseded token, which Salesforce would reject with `invalid_grant`.
        if let used = refreshing, let current = currentCredential, current.timestamp > used.timestamp {
            return current
        }
        // (3) Perform exactly one authentication/refresh, serialized via `authenticatingTask`.
        // Steps (1)–(3) run without an `await` in between, so the check-and-set is atomic.
        let task: Task<Credential, Error> = Task {
            defer { self.authenticatingTask = nil }            // released LAST, after (4)
            let new = try await self.produceCredential(refreshing: refreshing)
            self.currentCredential = new                       // (4) update SoT before releasing the gate
            return new
        }
        self.authenticatingTask = task
        return try await task.value
    }

    private func produceCredential(refreshing: Credential?) async throws -> Credential {
        let host = refreshing?.siteURL?.host ?? refreshing?.instanceURL.host ?? defaultHost
        guard let credential = refreshing, let refreshToken = credential.refreshToken else {
            return try await OAuthFlow.authorizationCode(consumerKey: consumerKey, host: host, callbackURL: callbackURL, session: session)
        }
        do {
            return try await OAuthFlow.refreshToken(consumerKey: consumerKey, host: host, refreshToken: refreshToken, session: session)
        }
        catch let error as OAuthError where error.code == "invalid_grant" {
            // The refresh token is genuinely dead — only now fall back to interactive login.
            return try await OAuthFlow.authorizationCode(consumerKey: consumerKey, host: host, callbackURL: callbackURL, session: session)
        }
    }
    
    func revoke(credential: Credential) async throws {
        if let task = revokingTask {
            return try await task.value
        }
        let task: Task<Void, Error> = Task {
            defer { self.revokingTask = nil }
            let host = credential.siteURL?.host ?? credential.instanceURL.host ?? defaultHost
            let token = credential.refreshToken ?? credential.accessToken
            return try await OAuthFlow.revokeToken(host: host, token: token)
        }
        self.revokingTask = task
        return try await task.value
    }
}
