import UIKit

// MARK: - LoginMode

/// Selects how the library presents the Salesforce authorize URL to the user
/// during an interactive login.
///
/// ## Security Tradeoff (RFC 8252 §8.12)
///
/// **IMPORTANT**: The default mode, `.embeddedWebView`, presents the Salesforce
/// login page inside an in-app `WKWebView`.  This means the host application
/// shares the same process as the login page and can, in principle, observe
/// web content, cookies, and credentials entered by the user on the Salesforce
/// login form.  This is a known limitation described in RFC 8252 §8.12 and
/// Apple's own security guidance for OAuth on iOS.
///
/// If your app requires stronger credential isolation — for example, if it
/// handles sensitive enterprise data or must comply with strict security
/// policies — use `.systemBrowser` instead.  The system browser
/// (`ASWebAuthenticationSession`) runs in a separate process managed by the OS
/// and does NOT give the host app access to web content or credentials.
///
/// ## Choosing a Mode
///
/// ```swift
/// // Default: embedded WKWebView (SDK-parity behavior)
/// let connection = try Salesforce.connect(consumerKey: key, callbackURL: url)
///
/// // Explicit system browser (stronger isolation)
/// let connection = try Salesforce.connect(
///     consumerKey: key,
///     callbackURL: url,
///     loginMode: .systemBrowser
/// )
///
/// // Embedded with a custom anchor (multi-scene apps)
/// let connection = try Salesforce.connect(
///     consumerKey: key,
///     callbackURL: url,
///     loginMode: .embeddedWebView(anchor: { myScene.keyWindow })
/// )
/// ```
///
/// ## JSON Configuration Asymmetry
///
/// When `loginMode` is read from a `Salesforce.json` configuration file, the
/// embedded mode is always used with the **default-anchor heuristic** (foreground-
/// active `UIWindowScene` key window).  A config-file entry cannot supply a
/// custom anchor closure.  Apps that need a specific window anchor — for example,
/// multi-scene apps — should configure the mode programmatically via
/// `Salesforce.connect(consumerKey:callbackURL:authorizingHost:loginMode:session:)`
/// rather than through the JSON file.
///
/// - Note: Introducing `UIKit` into the public API is intentional and expected.
///   `UIWindow` is the only type that works across both UIKit and SwiftUI hosts.
public enum LoginMode {

    /// Presents the Salesforce authorize URL inside an in-app `WKWebView`.
    ///
    /// The `anchor` closure resolves the `UIWindow` from which the internal
    /// modal view controller is presented.  The default implementation resolves
    /// the foreground-active `UIWindowScene`'s key window, which is correct for
    /// most single-scene apps.
    ///
    /// **Security note (RFC 8252 §8.12)**: The host application shares the same
    /// process as the embedded login page.  Use `.systemBrowser` for stronger
    /// credential isolation.
    case embeddedWebView(anchor: @MainActor () -> UIWindow? = LoginMode.defaultAnchor)

    /// Presents the Salesforce authorize URL in the system's secure browser
    /// session (`ASWebAuthenticationSession`), which runs in a separate OS-managed
    /// process.  Credentials entered by the user are NOT accessible to the host app.
    ///
    /// This option matches the behavior of Swiftly Salesforce prior to v11 and
    /// conforms to the RFC 8252 §8.12 recommendation for maximum credential isolation.
    case systemBrowser

    /// The default mode: embedded WKWebView with the system-resolved anchor.
    ///
    /// Equivalent to `.embeddedWebView()` with no explicit anchor.
    public static var `default`: LoginMode { .embeddedWebView() }
}

// MARK: - Default Anchor

extension LoginMode {

    /// Resolves the foreground-active `UIWindowScene`'s key window.
    ///
    /// This heuristic is correct for most single-scene apps.  Multi-scene apps
    /// should supply an explicit anchor via `.embeddedWebView(anchor: { ... })`.
    @MainActor
    public static func defaultAnchor() -> UIWindow? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first(where: { $0.activationState == .foregroundActive })
            .flatMap { $0.keyWindow }
    }
}

// MARK: - Factory

extension LoginMode {

    /// Resolves the concrete `LoginUserAgent` for this mode.
    ///
    /// This factory is UIKit-free-deterministic: it creates `EmbeddedWebViewUserAgent`
    /// or `WebAuthUserAgent` without performing any presentation.  Safe to call in
    /// unit tests without a running UI.
    @MainActor
    public func makeUserAgent() -> any LoginUserAgent {
        switch self {
        case .embeddedWebView(let anchor):
            return EmbeddedWebViewUserAgent(anchor: anchor)
        case .systemBrowser:
            return WebAuthUserAgent.shared
        }
    }
}
