import XCTest
import Combine
@testable import SwiftlySalesforce

final class AuthorizationCodePKCEFlowTests: XCTestCase {
    private var subscriptions = Set<AnyCancellable>()

    override func tearDown() {
        subscriptions.removeAll()
        TestURLProtocol.requestHandler = nil
        super.tearDown()
    }

    func testVerifierAndChallengeUseS256PKCE() throws {
        let verifier = try AuthorizationCodePKCEFlow.generateCodeVerifier()

        XCTAssertGreaterThanOrEqual(verifier.count, 43)
        XCTAssertLessThanOrEqual(verifier.count, 128)
        XCTAssertTrue(verifier.allSatisfy { char in
            char.isLetter || char.isNumber || ["-", ".", "_", "~"].contains(String(char))
        })
        XCTAssertEqual(
            AuthorizationCodePKCEFlow.codeChallenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        )
    }

    func testVerifierGenerationFailsClosedWhenSecureRandomFails() {
        XCTAssertThrowsError(try AuthorizationCodePKCEFlow.generateCodeVerifier(randomBytes: { _ in
            throw AuthorizationCodePKCEFlowError.randomGenerationFailed
        })) { error in
            guard case AuthorizationCodePKCEFlowError.randomGenerationFailed = error else {
                return XCTFail("Expected randomGenerationFailed, got \(error)")
            }
        }
    }

    func testAuthorizeURLIncludesAuthorizationCodePKCEParameters() throws {
        let flow = AuthorizationCodePKCEFlow(verifierGenerator: { "verifier-value" })

        let url = try flow.authorizationURL(connectedApp: Util.connectedApp, hostname: "login.salesforce.com")
        let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []

        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "login.salesforce.com")
        XCTAssertEqual(url.path, "/services/oauth2/authorize")
        XCTAssertEqual(query.first(named: "response_type")?.value, "code")
        XCTAssertEqual(query.first(named: "client_id")?.value, Util.connectedApp.consumerKey)
        XCTAssertEqual(query.first(named: "redirect_uri")?.value, Util.connectedApp.callbackURL.absoluteString)
        XCTAssertEqual(query.first(named: "code_challenge_method")?.value, "S256")
        XCTAssertEqual(query.first(named: "code_challenge")?.value, AuthorizationCodePKCEFlow.codeChallenge(for: "verifier-value"))
    }

    func testCallbackWithoutCodeFailsAndClearsVerifier() throws {
        let flow = AuthorizationCodePKCEFlow(verifierGenerator: { "verifier-value" })
        _ = try flow.authorizationURL(connectedApp: Util.connectedApp, hostname: "login.salesforce.com")

        XCTAssertThrowsError(try flow.authorizationCode(from: Util.connectedApp.callbackURL)) { error in
            guard case AuthorizationCodePKCEFlowError.missingAuthorizationCode = error else {
                return XCTFail("Expected missingAuthorizationCode, got \(error)")
            }
        }
        XCTAssertNil(flow.currentVerifierForTesting)
    }

    func testTokenExchangeIncludesCodeVerifierInRequestBody() {
        let session = URLSession.testSession()
        let flow = AuthorizationCodePKCEFlow(session: session, verifierGenerator: { "verifier-value" })
        let exp = expectation(description: "Exchange code")

        TestURLProtocol.requestHandler = { request in
            let body = String(data: request.testBodyData ?? Data(), encoding: .utf8) ?? ""
            XCTAssertEqual(request.url?.absoluteString, "https://login.salesforce.com/services/oauth2/token")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertTrue(body.contains("grant_type=authorization_code"), body)
            XCTAssertTrue(body.contains("code=auth-code"), body)
            XCTAssertTrue(body.contains("client_id=\(Util.connectedApp.consumerKey)"), body)
            XCTAssertTrue(body.contains("redirect_uri="), body)
            XCTAssertTrue(body.contains("code_verifier=verifier-value"), body)
            return TestURLProtocol.Stub(
                statusCode: 200,
                headers: ["Content-Type": "application/json"],
                body: Data("""
                {
                  "access_token": "access-token",
                  "instance_url": "https://example.my.salesforce.com",
                  "id": "https://login.salesforce.com/id/ORG/USER",
                  "refresh_token": "refresh-token",
                  "issued_at": "1700000000"
                }
                """.utf8)
            )
        }

        flow.exchangeCode(
            "auth-code",
            codeVerifier: "verifier-value",
            connectedApp: Util.connectedApp,
            hostname: "login.salesforce.com"
        )
        .sink(receiveCompletion: { completion in
            if case let .failure(error) = completion { XCTFail("\(error)") }
            exp.fulfill()
        }, receiveValue: { credential in
            XCTAssertEqual(credential.accessToken, "access-token")
            XCTAssertEqual(credential.refreshToken, "refresh-token")
        })
        .store(in: &subscriptions)

        waitForExpectations(timeout: 5)
    }
}

private extension Array where Element == URLQueryItem {
    func first(named name: String) -> URLQueryItem? {
        first { $0.name == name }
    }
}
