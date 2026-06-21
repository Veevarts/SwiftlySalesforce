import UIKit
import WebKit

// MARK: - EmbeddedWebViewUserAgent

/// `LoginUserAgent` implementation backed by an in-app `WKWebView` presented inside
/// a modal `UIViewController`.
///
/// The present → redirect-capture → dismiss path requires a live UI context and is
/// validated manually (see `// MARK: - Manual validation required` below).
/// All pure helper logic (`RedirectMatcher`, `LoginMode.makeUserAgent`) is unit-tested.
///
/// ## Lifecycle
/// 1. `authorize(url:redirectURI:)` is called on the `@MainActor`.
/// 2. A `WebViewHostViewController` is created, embedded with a `WKWebView`, and
///    presented modally from `anchor()?.rootViewController`.
/// 3. The `WKNavigationDelegate` (`NavigationHandler` inner class) watches every
///    navigation decision.  When `RedirectMatcher.isRedirect` returns `true`, it
///    cancels the navigation and calls back to `EmbeddedWebViewUserAgent` on the
///    main thread.
/// 4. If the user dismisses the modal (swipe-to-dismiss / Cancel button), the host
///    VC calls back → continuation resumes with `CancellationError`.
/// 5. A `resumed` flag prevents double-resuming under any race.
///
/// ## RFC 8252 §8.12 Note
/// The host application runs in the same process as this web view.  See `LoginMode`
/// documentation for the full security tradeoff and instructions on how to opt in to
/// the system browser for stronger credential isolation.
@MainActor
public final class EmbeddedWebViewUserAgent: LoginUserAgent {

    // MARK: - Stored Properties

    /// Closure that resolves the presentation window.
    private let anchor: @MainActor () -> UIWindow?

    // Continuation + teardown guard.  All access is on the MainActor.
    private var continuation: CheckedContinuation<URL, Error>?
    private var resumed = false

    // Retained during the async call; released on teardown.
    private var webView: WKWebView?
    private var navHandler: NavigationHandler?
    private weak var hostVC: WebViewHostViewController?

    // The redirect URI for this invocation; set in authorize(), read by navHandler callbacks.
    private var pendingRedirectURI: URL?

    // MARK: - Init

    /// Creates a user agent with the supplied anchor closure.
    ///
    /// - Parameter anchor: A `@MainActor` closure that returns the `UIWindow` from
    ///   which the modal host VC will be presented.  Typically supplied by `LoginMode`.
    public init(anchor: @MainActor @escaping () -> UIWindow?) {
        self.anchor = anchor
    }

    // MARK: - LoginUserAgent

    // MARK: - Manual validation required
    // The present → redirect-capture → dismiss path below cannot be unit-tested
    // without a running UI context (WKWebView, UIViewController presentation,
    // and a real Salesforce authorize URL).  Validate manually on a simulator:
    //   1. Call Salesforce.connect() and trigger an interactive login.
    //   2. Confirm the Salesforce login page appears in an in-app modal.
    //   3. Complete the login; confirm a Credential is produced.
    //   4. Repeat and swipe-dismiss the modal; confirm CancellationError is thrown
    //      and the call does not hang.

    /// Presents the authorize URL in an embedded `WKWebView`, waits for the
    /// authorization server to redirect to `redirectURI`, and returns that
    /// redirect URL (carrying `?code=…`).
    ///
    /// Throws `CancellationError` if the user dismisses the web view without
    /// completing authorization.
    public func authorize(url: URL, redirectURI: URL) async throws -> URL {
        // Reset state for this call.
        resumed = false
        pendingRedirectURI = redirectURI

        let handler = NavigationHandler(owner: self)
        navHandler = handler

        let wv = WKWebView()
        wv.navigationDelegate = handler
        webView = wv

        let vc = WebViewHostViewController(webView: wv)
        vc.onUserDismiss = { [weak self] in
            self?.resumeWithCancellation()
        }
        hostVC = vc

        guard let window = anchor(), let rootVC = window.rootViewController else {
            teardown()
            throw StateError("EmbeddedWebViewUserAgent: anchor returned no window or rootViewController")
        }

        // Find the topmost presented VC to avoid "already presenting" issues.
        var presenter = rootVC
        while let next = presenter.presentedViewController { presenter = next }

        presenter.present(vc, animated: true)
        wv.load(URLRequest(url: url))

        return try await withCheckedThrowingContinuation { [weak self] cont in
            self?.continuation = cont
        }
    }

    // MARK: - Navigation Decision (called by NavigationHandler)

    fileprivate func handleNavigationDecision(for url: URL) -> WKNavigationActionPolicy {
        guard let redirectURI = pendingRedirectURI else { return .allow }
        if RedirectMatcher.isRedirect(url, callback: redirectURI) {
            resumeWith(url)
            return .cancel
        }
        return .allow
    }

    // MARK: - Teardown

    /// Resumes the continuation with a redirect URL and dismisses the host VC.
    /// Safe to call only once (guarded by `resumed`).
    private func resumeWith(_ url: URL) {
        guard !resumed else { return }
        resumed = true
        let cont = continuation
        continuation = nil
        teardown()
        cont?.resume(returning: url)
    }

    /// Resumes the continuation with `CancellationError`.
    fileprivate func resumeWithCancellation() {
        guard !resumed else { return }
        resumed = true
        let cont = continuation
        continuation = nil
        teardown()
        cont?.resume(throwing: CancellationError())
    }

    /// Clears delegate references, stops loading, dismisses the host VC, nils all retained objects.
    private func teardown() {
        pendingRedirectURI = nil
        webView?.navigationDelegate = nil
        webView?.stopLoading()
        webView = nil
        navHandler = nil
        hostVC?.dismiss(animated: true)
        hostVC = nil
    }
}

// MARK: - NavigationHandler

/// Concrete `WKNavigationDelegate` that bridges `nonisolated` WebKit callbacks
/// back to the `@MainActor`-isolated `EmbeddedWebViewUserAgent`.
///
/// `WKNavigationDelegate` methods are NOT `@MainActor`-isolated but in practice
/// WebKit calls them on the main thread.  We use `MainActor.assumeIsolated` for
/// safe, synchronous access to the owner rather than spawning a detached Task
/// (which would require calling `decisionHandler` asynchronously — not allowed).
private final class NavigationHandler: NSObject, WKNavigationDelegate {

    private weak var owner: EmbeddedWebViewUserAgent?

    init(owner: EmbeddedWebViewUserAgent) {
        self.owner = owner
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }
        // WebKit calls this on the main thread. Use assumeIsolated so we can
        // call the @MainActor owner synchronously without spawning a Task.
        let policy = MainActor.assumeIsolated {
            owner?.handleNavigationDecision(for: url) ?? .allow
        }
        decisionHandler(policy)
    }
}

// MARK: - Host View Controller

/// Internal modal container for the embedded `WKWebView`.
///
/// Holds a strong reference to the web view; notifies the parent when the user
/// dismisses the modal via swipe-to-dismiss or the Cancel button.
final class WebViewHostViewController: UIViewController {

    var onUserDismiss: (() -> Void)?

    private let webView: WKWebView

    init(webView: WKWebView) {
        self.webView = webView
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .pageSheet
        presentationController?.delegate = self
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        // Navigation bar with a Cancel button for explicit user dismissal.
        let navBar = UINavigationBar()
        navBar.translatesAutoresizingMaskIntoConstraints = false
        let navItem = UINavigationItem(title: "Sign In")
        navItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel,
            target: self,
            action: #selector(cancelTapped)
        )
        navBar.items = [navItem]

        webView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(navBar)
        view.addSubview(webView)

        NSLayoutConstraint.activate([
            navBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            navBar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            navBar.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            webView.topAnchor.constraint(equalTo: navBar.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    @objc private func cancelTapped() {
        onUserDismiss?()
    }
}

// MARK: - UIAdaptivePresentationControllerDelegate

extension WebViewHostViewController: UIAdaptivePresentationControllerDelegate {

    /// Called when the user swipes down to dismiss the `.pageSheet`.
    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        onUserDismiss?()
    }
}
