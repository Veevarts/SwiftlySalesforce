import XCTest
@testable import SwiftlySalesforce

/// Deterministic tests for `LoginMode` — no UIKit presentation, no WKWebView instantiation.
/// These tests validate the factory/default-selection logic only.
@MainActor
final class LoginModeTests: XCTestCase {

    // MARK: - Default is embeddedWebView

    func testThatDefaultLoginModeIsEmbeddedWebView() {
        // LoginMode.default must resolve to .embeddedWebView (not .systemBrowser)
        let mode = LoginMode.default
        if case .embeddedWebView = mode {
            // pass
        } else {
            XCTFail("Expected LoginMode.default to be .embeddedWebView, got \(mode)")
        }
    }

    // MARK: - Stored variables (enum is storable)

    func testThatLoginModeCanBeStoredInVariable() {
        let explicitEmbedded: LoginMode = .embeddedWebView()
        let systemBrowser: LoginMode = .systemBrowser
        // Just verifying these compile and are distinct
        if case .systemBrowser = explicitEmbedded {
            XCTFail("embeddedWebView must not equal systemBrowser")
        }
        if case .embeddedWebView = systemBrowser {
            XCTFail("systemBrowser must not equal embeddedWebView")
        }
    }

    // MARK: - Factory: .systemBrowser resolves to WebAuthUserAgent

    func testThatSystemBrowserResolvesToWebAuthUserAgent() {
        let agent = LoginMode.systemBrowser.makeUserAgent()
        XCTAssertTrue(agent is WebAuthUserAgent,
                      "Expected WebAuthUserAgent, got \(type(of: agent))")
    }

    // MARK: - Factory: .embeddedWebView resolves to EmbeddedWebViewUserAgent

    func testThatEmbeddedWebViewResolvesToEmbeddedWebViewUserAgent() {
        let agent = LoginMode.embeddedWebView().makeUserAgent()
        XCTAssertTrue(agent is EmbeddedWebViewUserAgent,
                      "Expected EmbeddedWebViewUserAgent, got \(type(of: agent))")
    }

    // MARK: - Factory: default resolves to EmbeddedWebViewUserAgent

    func testThatDefaultModeResolvesToEmbeddedWebViewUserAgent() {
        let agent = LoginMode.default.makeUserAgent()
        XCTAssertTrue(agent is EmbeddedWebViewUserAgent,
                      "Expected EmbeddedWebViewUserAgent for .default, got \(type(of: agent))")
    }
}
