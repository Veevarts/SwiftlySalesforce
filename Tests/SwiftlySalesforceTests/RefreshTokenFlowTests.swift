import XCTest
import Combine
@testable import SwiftlySalesforce

class RefreshTokenFlowTests: XCTestCase {

    var subscriptions = Set<AnyCancellable>()

    override func setUp() {
    }

    override func tearDown() {
    }

    private func makeCredential(refreshToken: String?) -> Credential {
        return Credential(
            accessToken: "OLD_ACCESS",
            instanceURL: URL(string: "https://example.my.salesforce.com")!,
            identityURL: URL(string: "https://login.salesforce.com/id/00Dxx0000001gPL/005xx000001Sv6D")!,
            refreshToken: refreshToken,
            issuedAt: nil, idToken: nil, communityURL: nil, communityID: nil)
    }

    private let tokenURL = URL(string: "https://login.salesforce.com/services/oauth2/token")!

    // MARK: - Group 5: Refresh Token Rotation

    func testThatItUsesRotatedRefreshToken() throws {
        let original = makeCredential(refreshToken: "OLD_REFRESH")
        let json = """
        {"access_token":"NEW_ACCESS","refresh_token":"NEW_REFRESH","instance_url":"https://example.my.salesforce.com","id":"https://login.salesforce.com/id/00Dxx0000001gPL/005xx000001Sv6D","issued_at":"1600000000"}
        """.data(using: .utf8)!
        let refreshed = try RefreshTokenFlow.refreshedCredential(from: json, credential: original)
        XCTAssertEqual(refreshed.accessToken, "NEW_ACCESS")
        XCTAssertEqual(refreshed.refreshToken, "NEW_REFRESH")
    }

    func testThatItKeepsOldRefreshTokenWhenNoneReturned() throws {
        let original = makeCredential(refreshToken: "OLD_REFRESH")
        let json = """
        {"access_token":"NEW_ACCESS","instance_url":"https://example.my.salesforce.com","id":"https://login.salesforce.com/id/00Dxx0000001gPL/005xx000001Sv6D","issued_at":"1600000000"}
        """.data(using: .utf8)!
        let refreshed = try RefreshTokenFlow.refreshedCredential(from: json, credential: original)
        XCTAssertEqual(refreshed.accessToken, "NEW_ACCESS")
        XCTAssertEqual(refreshed.refreshToken, "OLD_REFRESH")
    }

    // MARK: - Group 6: Typed RTR error

    func testThatInvalidGrantMapsToRotatedOrExpired() throws {
        let response = HTTPURLResponse(url: tokenURL, statusCode: 400, httpVersion: nil, headerFields: nil)!
        let data = #"{"error":"invalid_grant","error_description":"expired access/refresh token"}"#.data(using: .utf8)!
        let error = try XCTUnwrap(RefreshTokenFlow.endpointError(data: data, response: response))
        guard case RefreshTokenFlowError.refreshTokenRotatedOrExpired = error else {
            return XCTFail("Expected refreshTokenRotatedOrExpired, got \(error)")
        }
    }

    func testThatOtherErrorsMapToEndpointFailure() throws {
        let response = HTTPURLResponse(url: tokenURL, statusCode: 500, httpVersion: nil, headerFields: nil)!
        let data = #"{"error":"server_error"}"#.data(using: .utf8)!
        let error = try XCTUnwrap(RefreshTokenFlow.endpointError(data: data, response: response))
        guard case RefreshTokenFlowError.endpointFailure = error else {
            return XCTFail("Expected endpointFailure, got \(error)")
        }
    }

    func testThatSuccessfulResponseHasNoEndpointError() {
        let response = HTTPURLResponse(url: tokenURL, statusCode: 200, httpVersion: nil, headerFields: nil)!
        XCTAssertNil(RefreshTokenFlow.endpointError(data: Data(), response: response))
    }

    // Assumption: server grants refresh token
    func testThatItRefreshes() {
        
        // Given
        let connectedApp = Util.connectedApp
        let exp = expectation(description: "Refresh token")
        
        // When
        let pub = UserAgentFlow().publisher(connectedApp: connectedApp, hostname: "login.salesforce.com")
        .flatMap { (cred) -> AnyPublisher<Credential, Error> in
            RefreshTokenFlow().publisher(credential: cred, connectedApp: connectedApp, hostname: "login.salesforce.com")
        }
        .eraseToAnyPublisher()
        
        // Then
        pub.sink(receiveCompletion: { (completion) in
            exp.fulfill()
            switch completion {
            case let .failure(error):
                XCTFail("\(error)")
            case .finished:
                break
            }
        }) { (credential) in
            XCTAssertNotNil(credential.accessToken)
            XCTAssertNotNil(credential.identityURL)
        }.store(in: &subscriptions)
        waitForExpectations(timeout: 60 , handler: nil)
    }
    
    // Assumption: server grants refresh token
    func testThatItFailsToRefresh() {
        
        // Given
        let connectedApp = Util.connectedApp
        let exp = expectation(description: "Fails to refresh token")
        
        // When
        let pub = UserAgentFlow().publisher(connectedApp: connectedApp, hostname: "login.salesforce.com")
        .flatMap { (cred) -> AnyPublisher<Credential, Error> in
            let badCred = Credential(accessToken: cred.accessToken,
                                     instanceURL: cred.instanceURL,
                                     identityURL: cred.identityURL,
                                     refreshToken: "NO REFRESH TOKEN",
                                     issuedAt: nil, idToken: nil,
                                     communityURL: nil,
                                     communityID: nil)
            return RefreshTokenFlow().publisher(credential: badCred, connectedApp: connectedApp, hostname: "login.salesforce.com")
        }
        .eraseToAnyPublisher()
        
        // Then
        pub.sink(receiveCompletion: { (completion) in
            exp.fulfill()
            switch completion {
            case let .failure(error):
                // Expected to fail with RefreshTokenFlowError
                guard case RefreshTokenFlowError.endpointFailure = error else {
                    return XCTFail("Should have failed to refresh token")
                }
                break
            case .finished:
                break
            }
        }) { (credential) in
            return XCTFail("Should have failed to refresh token")
        }.store(in: &subscriptions)
        waitForExpectations(timeout: 120, handler: nil)
    }
}
