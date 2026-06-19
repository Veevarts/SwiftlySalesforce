import XCTest
import Combine
@testable import SwiftlySalesforce

final class SalesforceRefreshCoordinatorTests: XCTestCase {
    private var subscriptions = Set<AnyCancellable>()

    override func tearDown() {
        subscriptions.removeAll()
        super.tearDown()
    }

    func testConcurrentRequestsForSameCredentialShareOneRefresh() {
        let coordinator = SalesforceRefreshCoordinator()
        let credential = Self.credential(accessToken: "expired-token", refreshToken: "refresh-token")
        let refreshed = Self.credential(accessToken: "new-access-token", refreshToken: "rotated-refresh-token")
        let refreshSubject = PassthroughSubject<Credential, Error>()
        let allSubscribersReceiveRefresh = expectation(description: "All subscribers receive shared credential")
        allSubscribersReceiveRefresh.expectedFulfillmentCount = 3
        var refreshCount = 0
        var receivedCredentials: [Credential] = []

        for _ in 0..<3 {
            coordinator.refresh(credential: credential) {
                refreshCount += 1
                return refreshSubject.eraseToAnyPublisher()
            }
            .sink(receiveCompletion: { completion in
                if case let .failure(error) = completion { XCTFail("\(error)") }
            }, receiveValue: { value in
                receivedCredentials.append(value)
                allSubscribersReceiveRefresh.fulfill()
            })
            .store(in: &subscriptions)
        }

        XCTAssertEqual(refreshCount, 1)
        refreshSubject.send(refreshed)
        refreshSubject.send(completion: .finished)

        waitForExpectations(timeout: 5)
        XCTAssertEqual(receivedCredentials, [refreshed, refreshed, refreshed])
    }

    func testStaggeredRequestReusesRotatedCredentialInsteadOfRefreshingStaleToken() {
        // Reproduces the refresh-token-rotation (RTR) race: a first caller rotates
        // RT0 -> RT1 and persists it; a second, *staggered* caller (its in-flight
        // entry already freed) still carries the now single-use-spent RT0. It must
        // reuse the rotated credential from storage rather than launch a second
        // refresh of RT0, which Salesforce rejects with `invalid_grant`.
        let coordinator = SalesforceRefreshCoordinator()
        let stale = Self.credential(accessToken: "expired-token", refreshToken: "RT0")
        let rotated = Self.credential(accessToken: "new-access-token", refreshToken: "RT1")

        // `stored` models the credential store; the first refresh persists RT1.
        var stored = stale
        var operationCount = 0

        let firstRefresh = expectation(description: "first caller rotates the token")
        coordinator.refresh(credential: stale, latestCredential: { stored }) {
            operationCount += 1
            stored = rotated
            return Just(rotated).setFailureType(to: Error.self).eraseToAnyPublisher()
        }
        .sink(receiveCompletion: { _ in firstRefresh.fulfill() }, receiveValue: { _ in })
        .store(in: &subscriptions)
        wait(for: [firstRefresh], timeout: 5)

        let staggeredReuse = expectation(description: "staggered caller reuses rotated credential")
        var received: Credential?
        coordinator.refresh(credential: stale, latestCredential: { stored }) {
            XCTFail("Staggered caller must not refresh a rotated-out token")
            return Fail(error: SalesforceError.authenticationRequired).eraseToAnyPublisher()
        }
        .sink(receiveCompletion: { _ in staggeredReuse.fulfill() }, receiveValue: { received = $0 })
        .store(in: &subscriptions)
        wait(for: [staggeredReuse], timeout: 5)

        XCTAssertEqual(operationCount, 1, "Only the first caller should hit the refresh endpoint")
        XCTAssertEqual(received, rotated, "Staggered caller should receive the already-rotated credential")
    }

    private static func credential(accessToken: String, refreshToken: String) -> Credential {
        Credential(
            accessToken: accessToken,
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
