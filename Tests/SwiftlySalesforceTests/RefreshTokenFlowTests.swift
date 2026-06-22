import XCTest
import Combine
@testable import SwiftlySalesforce

class RefreshTokenFlowTests: XCTestCase {

    var subscriptions = Set<AnyCancellable>()

    override func setUp() {
        super.setUp()
        RefreshTokenFlow.resetInFlightRefreshes()
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

    // MARK: - Group 9: Single-flight refresh coalescing

    /// Thread-safe call counter for the injected refresh factory.
    private final class Counter {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    private func delayedRefresh(_ counter: Counter, token: String = "ROTATED", milliseconds: Int = 300) -> () -> AnyPublisher<Credential, Error> {
        return {
            counter.increment()
            return Just(self.makeCredential(refreshToken: token))
                .setFailureType(to: Error.self)
                .delay(for: .milliseconds(milliseconds), scheduler: DispatchQueue.global())
                .eraseToAnyPublisher()
        }
    }

    func testThatConcurrentRefreshesWithSameKeyRunOnce() {
        let counter = Counter()
        let make = delayedRefresh(counter)
        let received = NSMutableArray()
        let lock = NSLock()
        let exp = expectation(description: "both complete")
        exp.expectedFulfillmentCount = 2

        for _ in 0..<2 {
            RefreshTokenFlow.coordinatedRefresh(consumerKey: "APP", refreshToken: "SAME_TOKEN", make)
                .sink(receiveCompletion: { _ in exp.fulfill() },
                      receiveValue: { cred in lock.lock(); received.add(cred.refreshToken ?? ""); lock.unlock() })
                .store(in: &subscriptions)
        }

        waitForExpectations(timeout: 5)
        XCTAssertEqual(counter.value, 1, "Concurrent same-token refreshes must coalesce into one")
        XCTAssertEqual(received.count, 2, "Both callers must receive the rotated credential")
        XCTAssertEqual(received.firstObject as? String, "ROTATED")
    }

    func testThatDifferentTokensDoNotCoalesce() {
        let counter = Counter()
        let make = delayedRefresh(counter)
        let exp = expectation(description: "both complete")
        exp.expectedFulfillmentCount = 2

        for token in ["TOKEN_A", "TOKEN_B"] {
            RefreshTokenFlow.coordinatedRefresh(consumerKey: "APP", refreshToken: token, make)
                .sink(receiveCompletion: { _ in exp.fulfill() }, receiveValue: { _ in })
                .store(in: &subscriptions)
        }

        waitForExpectations(timeout: 5)
        XCTAssertEqual(counter.value, 2, "Different tokens must each issue their own refresh")
    }

    // MARK: - Group 11: Straggler replay

    func testThatStragglerWithAlreadyRotatedTokenReplaysResult() {
        let counter = Counter()
        let make = delayedRefresh(counter, token: "ROTATED", milliseconds: 10)

        // First refresh of T1 completes and rotates the token.
        let first = expectation(description: "first completes")
        var firstResult: String?
        RefreshTokenFlow.coordinatedRefresh(consumerKey: "APP", refreshToken: "T1", make)
            .sink(receiveCompletion: { _ in first.fulfill() }, receiveValue: { firstResult = $0.refreshToken })
            .store(in: &subscriptions)
        wait(for: [first], timeout: 5)

        // A straggler still holding T1 arrives after completion: it must replay, not refresh again.
        let second = expectation(description: "straggler completes")
        var stragglerResult: String?
        RefreshTokenFlow.coordinatedRefresh(consumerKey: "APP", refreshToken: "T1", make)
            .sink(receiveCompletion: { _ in second.fulfill() }, receiveValue: { stragglerResult = $0.refreshToken })
            .store(in: &subscriptions)
        wait(for: [second], timeout: 5)

        XCTAssertEqual(counter.value, 1, "A straggler with an already-rotated token must replay, not re-refresh")
        XCTAssertEqual(firstResult, "ROTATED")
        XCTAssertEqual(stragglerResult, "ROTATED", "The straggler must receive the rotation result")
    }

    func testThatRefreshWithRotatedTokenRunsAgain() {
        let counter = Counter()
        let make = delayedRefresh(counter, milliseconds: 10)

        let first = expectation(description: "first completes")
        RefreshTokenFlow.coordinatedRefresh(consumerKey: "APP", refreshToken: "T1", make)
            .sink(receiveCompletion: { _ in first.fulfill() }, receiveValue: { _ in })
            .store(in: &subscriptions)
        wait(for: [first], timeout: 5)

        // A later refresh presenting the genuinely rotated token must issue a fresh request.
        let second = expectation(description: "second completes")
        RefreshTokenFlow.coordinatedRefresh(consumerKey: "APP", refreshToken: "T2", make)
            .sink(receiveCompletion: { _ in second.fulfill() }, receiveValue: { _ in })
            .store(in: &subscriptions)
        wait(for: [second], timeout: 5)

        XCTAssertEqual(counter.value, 2, "A refresh with a genuinely new token must run again")
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
