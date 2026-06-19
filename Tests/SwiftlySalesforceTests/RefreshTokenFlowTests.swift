/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine
import XCTest
@testable import SwiftlySalesforce

class RefreshTokenFlowTests: XCTestCase {

    var cancellables = Set<AnyCancellable>()

    override func setUpWithError() throws {
        cancellables = []
    }

    override func tearDownWithError() throws {
        MockURLProtocol.requestHandler = nil
    }

    // MARK: - Task 1.2.1 — Rotation: server returns a new refresh token (REQ-ROT-01, ROT-S01)

    func testRefreshCapturesRotatedToken() throws {
        // Given: server returns a rotated refresh_token
        let responseBody = "access_token=new-access&instance_url=https%3A%2F%2Forg.salesforce.com&id=https%3A%2F%2Flogin.salesforce.com%2Fid%2Forg%2Fuser&refresh_token=new-token"
        MockURLProtocol.requestHandler = { _ in
            let response = HTTPURLResponse(
                url: URL(string: "https://login.salesforce.com/services/oauth2/token")!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/x-www-form-urlencoded"]
            )!
            return (response, responseBody.data(using: .utf8)!)
        }

        let session = mockURLSession()
        let flow = RefreshTokenFlow(
            refreshToken: "old-token",
            consumerKey: "consumer-key",
            host: "login.salesforce.com",
            session: session
        )

        // When
        let credential = try waitFor(flow.publisher)

        // Then: rotated token is captured
        XCTAssertEqual(credential.refreshToken, "new-token")
        XCTAssertEqual(credential.accessToken, "new-access")
    }

    // MARK: - Task 1.2.2 — No rotation: server omits refresh token (REQ-ROT-01, REQ-ROT-04, ROT-S02)

    func testRefreshFallsBackWhenNoRotation() throws {
        // Given: server response omits refresh_token
        let responseBody = "access_token=new-access&instance_url=https%3A%2F%2Forg.salesforce.com&id=https%3A%2F%2Flogin.salesforce.com%2Fid%2Forg%2Fuser"
        MockURLProtocol.requestHandler = { _ in
            let response = HTTPURLResponse(
                url: URL(string: "https://login.salesforce.com/services/oauth2/token")!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/x-www-form-urlencoded"]
            )!
            return (response, responseBody.data(using: .utf8)!)
        }

        let session = mockURLSession()
        let flow = RefreshTokenFlow(
            refreshToken: "old-token",
            consumerKey: "consumer-key",
            host: "login.salesforce.com",
            session: session
        )

        // When
        let credential = try waitFor(flow.publisher)

        // Then: falls back to original token
        XCTAssertEqual(credential.refreshToken, "old-token")
    }

    // MARK: - Task 1.2.3 — invalid_grant is surfaced without string-parsing (REQ-ROT-03, ROT-S03)

    func testInvalidGrantSurfaced() throws {
        // Given: server returns HTTP 400 with error=invalid_grant
        let responseBody = "error=invalid_grant&error_description=expired%20access%2Frefresh%20token"
        MockURLProtocol.requestHandler = { _ in
            let response = HTTPURLResponse(
                url: URL(string: "https://login.salesforce.com/services/oauth2/token")!,
                statusCode: 400,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/x-www-form-urlencoded"]
            )!
            return (response, responseBody.data(using: .utf8)!)
        }

        let session = mockURLSession()
        let flow = RefreshTokenFlow(
            refreshToken: "expired-token",
            consumerKey: "consumer-key",
            host: "login.salesforce.com",
            session: session
        )

        // When / Then: publisher fails AND error is identifiable as invalid_grant
        var thrownError: Error?
        XCTAssertThrowsError(try waitFor(flow.publisher)) {
            thrownError = $0
        }

        // Error must be identifiable as invalid_grant without string-parsing.
        // Approach: SalesforceError.isInvalidGrant (code == "invalid_grant") — lightest option.
        guard let sfError = thrownError as? SalesforceError else {
            XCTFail("Expected SalesforceError, got \(String(describing: thrownError))")
            return
        }
        XCTAssertTrue(sfError.isInvalidGrant, "SalesforceError.isInvalidGrant must be true for invalid_grant responses")
    }

    // MARK: - Task 1.2.4 — Network error propagates (ROT-S04)

    func testNetworkErrorPropagates() throws {
        // Given: URLSession throws a network error
        MockURLProtocol.requestHandler = { _ in
            throw URLError(.notConnectedToInternet)
        }

        let session = mockURLSession()
        let flow = RefreshTokenFlow(
            refreshToken: "some-token",
            consumerKey: "consumer-key",
            host: "login.salesforce.com",
            session: session
        )

        // When / Then
        var thrownError: Error?
        XCTAssertThrowsError(try waitFor(flow.publisher)) {
            thrownError = $0
        }
        XCTAssertTrue(thrownError is URLError)
        XCTAssertEqual((thrownError as? URLError)?.code, .notConnectedToInternet)
    }
}
