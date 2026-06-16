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
