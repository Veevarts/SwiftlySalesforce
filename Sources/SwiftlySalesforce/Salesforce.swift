import Foundation

public struct Salesforce {

    /// Connects to Salesforce using a `Salesforce.json` configuration file.
    ///
    /// The JSON file may include an optional `"loginMode"` key with value `"embeddedWebView"`
    /// or `"systemBrowser"`.  When absent, the default is `.embeddedWebView` (see `LoginMode.default`).
    ///
    /// **JSON-vs-anchor asymmetry**: The config-file `"embeddedWebView"` value always uses the
    /// `defaultAnchor` heuristic (foreground-active `UIWindowScene` key window).  A JSON key
    /// cannot supply a custom anchor closure.  Multi-scene apps that need a specific anchor should
    /// configure the mode programmatically via `connect(consumerKey:callbackURL:authorizingHost:loginMode:session:)`.
    public static func connect(configurationURL: URL? = nil, session: URLSession = .shared) throws -> Connection {

        guard let url =
                configurationURL
                ?? Bundle.main.url(forResource: "Salesforce", withExtension: "json")
                ?? Bundle.main.url(forResource: "salesforce", withExtension: "json") else {
                throw URLError(.badURL, userInfo: [NSURLErrorFailingURLStringErrorKey : "Salesforce.json"])
        }
        let config = try JSONDecoder().decode(Configuration.self, from: try Data(contentsOf: url))
        let loginMode = config.loginMode ?? .default
        return try connect(consumerKey: config.consumerKey, callbackURL: config.callbackURL, authorizingHost: config.authorizingHost, loginMode: loginMode, session: session)
    }

    /// Connects to Salesforce with explicit parameters.
    ///
    /// - Parameters:
    ///   - consumerKey: The Connected App's consumer key.
    ///   - callbackURL: The Connected App's callback URL.
    ///   - authorizingHost: Optional Salesforce host (e.g. `"login.salesforce.com"`).
    ///   - loginMode: Controls how the interactive login UI is presented.
    ///     Defaults to `.embeddedWebView` (in-app WKWebView).
    ///
    /// ## Security Note (RFC 8252 §8.12)
    ///
    /// The default mode, `.embeddedWebView`, presents the Salesforce login page inside an
    /// in-app `WKWebView`.  The host application runs in the same process and can, in principle,
    /// observe web content, cookies, and credentials entered on the Salesforce login form.
    ///
    /// If your app requires stronger credential isolation, pass `loginMode: .systemBrowser` to
    /// use `ASWebAuthenticationSession`, which runs in a separate OS-managed process.
    ///
    /// ```swift
    /// // Default: embedded WKWebView
    /// let connection = try Salesforce.connect(consumerKey: key, callbackURL: url)
    ///
    /// // System browser (stronger isolation, RFC 8252 §8.12 compliant)
    /// let connection = try Salesforce.connect(
    ///     consumerKey: key,
    ///     callbackURL: url,
    ///     loginMode: .systemBrowser
    /// )
    /// ```
    public static func connect(consumerKey: String, callbackURL: URL, authorizingHost: String? = nil, loginMode: LoginMode = .default, session: URLSession = .shared) throws -> Connection {

        let authorizer = DefaultAuthorizer(consumerKey: consumerKey, callbackURL: callbackURL, defaultHost: authorizingHost, loginMode: loginMode)
        let credentialStore = DefaultCredentialStore(consumerKey: consumerKey)
        guard let defaults = UserDefaults(suiteName: consumerKey) else {
            throw StateError("Failed to initialize user defaults")
        }
        return try connect(authorizer: authorizer, credentialStore: credentialStore, defaults: defaults, session: session)
    }

    public static func connect(authorizer: Authorizer, credentialStore: CredentialStore, defaults: UserDefaults, session: URLSession) throws -> Connection {
        return Connection(authorizer: authorizer, credentialStore: credentialStore, defaults: defaults, session: session)
    }
}

internal extension Salesforce {

    /// Internal configuration decoded from `Salesforce.json`.
    ///
    /// The optional `loginMode` key accepts `"embeddedWebView"` or `"systemBrowser"`.
    /// When absent, the caller defaults to `LoginMode.default` (embedded WKWebView).
    ///
    /// **JSON-vs-anchor asymmetry**: `"embeddedWebView"` in the JSON always uses the
    /// `defaultAnchor` heuristic (foreground-active scene key window).  Apps that need a
    /// specific anchor must pass `loginMode` programmatically via
    /// `connect(consumerKey:callbackURL:authorizingHost:loginMode:session:)`.
    struct Configuration: Decodable {

        let consumerKey: String
        let callbackURL: URL
        let authorizingHost: String?

        /// Optional login-mode key from JSON.  `nil` → caller defaults to `.default`.
        ///
        /// NOTE: config-file embedded mode uses the default-anchor heuristic; apps needing
        /// a custom anchor must pass loginMode programmatically via connect(consumerKey:...).
        let loginMode: LoginMode?

        enum CodingKeys: String, CodingKey {
            case consumerKey
            case callbackURL
            case authorizingHost
            case loginMode
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            consumerKey = try container.decode(String.self, forKey: .consumerKey)
            callbackURL = try container.decode(URL.self, forKey: .callbackURL)
            authorizingHost = try container.decodeIfPresent(String.self, forKey: .authorizingHost)

            if let rawMode = try container.decodeIfPresent(String.self, forKey: .loginMode) {
                switch rawMode {
                case "systemBrowser":
                    loginMode = .systemBrowser
                case "embeddedWebView":
                    loginMode = .embeddedWebView()
                default:
                    throw DecodingError.dataCorruptedError(
                        forKey: .loginMode,
                        in: container,
                        debugDescription: "Unrecognized loginMode '\(rawMode)'. Valid values: \"embeddedWebView\", \"systemBrowser\"."
                    )
                }
            } else {
                loginMode = nil
            }
        }
    }
}
