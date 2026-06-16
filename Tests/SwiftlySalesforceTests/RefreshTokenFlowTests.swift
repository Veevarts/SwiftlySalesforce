import XCTest
import Combine
@testable import SwiftlySalesforce

class RefreshTokenFlowTests: XCTestCase {

    var subscriptions = Set<AnyCancellable>()

    override func tearDown() {
        subscriptions.removeAll()
        TestURLProtocol.requestHandler = nil
        super.tearDown()
    }

    func testRefreshPersistsRotatedRefreshTokenInReturnedCredential() {
        let session = URLSession.testSession()
        let original = Self.credential(refreshToken: "old-refresh-token")
        let exp = expectation(description: "Refresh token rotates")

        TestURLProtocol.requestHandler = { request in
            let body = String(data: request.testBodyData ?? Data(), encoding: .utf8) ?? ""
            XCTAssertTrue(body.contains("grant_type=refresh_token"), body)
            XCTAssertTrue(body.contains("refresh_token=old-refresh-token"), body)
            return TestURLProtocol.Stub(statusCode: 200, headers: [:], body: Data("""
            {
              "access_token": "new-access-token",
              "instance_url": "https://example.my.salesforce.com",
              "id": "https://login.salesforce.com/id/ORG/USER",
              "refresh_token": "rotated-refresh-token",
              "issued_at": "1700000000"
            }
            """.utf8))
        }

        RefreshTokenFlow(session: session)
            .publisher(credential: original, connectedApp: Util.connectedApp, hostname: "login.salesforce.com")
            .sink(receiveCompletion: { completion in
                if case let .failure(error) = completion { XCTFail("\(error)") }
                exp.fulfill()
            }, receiveValue: { credential in
                XCTAssertEqual(credential.accessToken, "new-access-token")
                XCTAssertEqual(credential.refreshToken, "rotated-refresh-token")
            })
            .store(in: &subscriptions)

        waitForExpectations(timeout: 5)
    }

    func testRefreshPreservesExistingRefreshTokenWhenResponseDoesNotRotate() {
        let session = URLSession.testSession()
        let original = Self.credential(refreshToken: "existing-refresh-token")
        let exp = expectation(description: "Refresh token preserved")

        TestURLProtocol.requestHandler = { _ in
            TestURLProtocol.Stub(statusCode: 200, headers: [:], body: Data("""
            {
              "access_token": "new-access-token",
              "instance_url": "https://example.my.salesforce.com",
              "id": "https://login.salesforce.com/id/ORG/USER",
              "issued_at": "1700000000"
            }
            """.utf8))
        }

        RefreshTokenFlow(session: session)
            .publisher(credential: original, connectedApp: Util.connectedApp, hostname: "login.salesforce.com")
            .sink(receiveCompletion: { completion in
                if case let .failure(error) = completion { XCTFail("\(error)") }
                exp.fulfill()
            }, receiveValue: { credential in
                XCTAssertEqual(credential.accessToken, "new-access-token")
                XCTAssertEqual(credential.refreshToken, "existing-refresh-token")
            })
            .store(in: &subscriptions)

        waitForExpectations(timeout: 5)
    }

    func testInvalidGrantEndpointFailureIsClassifiedAsUnrecoverable() {
        let session = URLSession.testSession()
        let original = Self.credential(refreshToken: "expired-refresh-token")
        let exp = expectation(description: "invalid_grant classified")

        TestURLProtocol.requestHandler = { _ in
            TestURLProtocol.Stub(statusCode: 400, headers: [:], body: Data("""
            { "error": "invalid_grant", "error_description": "expired authorization code" }
            """.utf8))
        }

        RefreshTokenFlow(session: session)
            .publisher(credential: original, connectedApp: Util.connectedApp, hostname: "login.salesforce.com")
            .sink(receiveCompletion: { completion in
                guard case let .failure(error as RefreshTokenFlowError) = completion else {
                    return XCTFail("Expected RefreshTokenFlowError failure")
                }
                XCTAssertTrue(error.isInvalidGrant)
                exp.fulfill()
            }, receiveValue: { _ in
                XCTFail("Expected refresh failure")
            })
            .store(in: &subscriptions)

        waitForExpectations(timeout: 5)
    }

    private static func credential(refreshToken: String) -> Credential {
        Credential(
            accessToken: "old-access-token",
            instanceURL: URL(string: "https://example.my.salesforce.com")!,
            identityURL: URL(string: "https://login.salesforce.com/id/ORG/USER")!,
            refreshToken: refreshToken,
            issuedAt: 1600000000,
            idToken: nil,
            communityURL: nil,
            communityID: nil
        )
    }
}
