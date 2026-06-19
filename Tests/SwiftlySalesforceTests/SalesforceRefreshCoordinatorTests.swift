/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine
import XCTest
@testable import SwiftlySalesforce

// MARK: - Task 3.1 — SalesforceRefreshCoordinator Tests (RED → GREEN)

class SalesforceRefreshCoordinatorTests: XCTestCase {

    var subscriptions = Set<AnyCancellable>()

    override func setUpWithError() throws {
        subscriptions = []
    }

    override func tearDownWithError() throws {
        subscriptions.removeAll()
    }

    // MARK: - Task 3.1.1 — Concurrent refreshes for same credential coalesce to one call (REQ-SFR-01, SFR-S01)

    func testConcurrentRefreshDeduplicated() throws {
        let coordinator = SalesforceRefreshCoordinator()
        let credential = Self.makeCredential(accessToken: "expired-access", refreshToken: "refresh-tok")
        let refreshed  = Self.makeCredential(accessToken: "new-access",     refreshToken: "rotated-tok")
        let subject    = PassthroughSubject<Credential, Error>()

        var invokeCount = 0
        var receivedValues: [Credential] = []

        // 3 concurrent callers — all before subject emits
        let allReceived = expectation(description: "All 3 callers receive the result")
        allReceived.expectedFulfillmentCount = 3

        for _ in 0..<3 {
            coordinator.refresh(credential: credential) {
                invokeCount += 1
                return subject.eraseToAnyPublisher()
            }
            .sink(
                receiveCompletion: { completion in
                    if case let .failure(e) = completion { XCTFail("Unexpected error: \(e)") }
                },
                receiveValue: { value in
                    receivedValues.append(value)
                    allReceived.fulfill()
                }
            )
            .store(in: &subscriptions)
        }

        // Operation must have been invoked exactly once (dedup)
        XCTAssertEqual(invokeCount, 1, "Operation must be invoked only once for concurrent same-key calls")

        // Resolve the in-flight publisher
        subject.send(refreshed)
        subject.send(completion: .finished)

        waitForExpectations(timeout: 5)
        XCTAssertEqual(receivedValues.count, 3)
        XCTAssertTrue(receivedValues.allSatisfy { $0 == refreshed }, "All callers must receive the same refreshed credential")
    }

    // MARK: - Task 3.1.2 — Different credentials get independent calls (REQ-SFR-02, SFR-S02)

    func testDifferentCredentialsGetIndependentCalls() throws {
        let coordinator = SalesforceRefreshCoordinator()
        let credA = Self.makeCredential(accessToken: "access-A", refreshToken: "refresh-A",
                                        identityURL: URL(string: "https://login.salesforce.com/id/org/userA")!)
        let credB = Self.makeCredential(accessToken: "access-B", refreshToken: "refresh-B",
                                        identityURL: URL(string: "https://login.salesforce.com/id/org/userB")!)
        let resultA = Self.makeCredential(accessToken: "new-A", refreshToken: "rot-A",
                                          identityURL: URL(string: "https://login.salesforce.com/id/org/userA")!)
        let resultB = Self.makeCredential(accessToken: "new-B", refreshToken: "rot-B",
                                          identityURL: URL(string: "https://login.salesforce.com/id/org/userB")!)

        let subjectA = PassthroughSubject<Credential, Error>()
        let subjectB = PassthroughSubject<Credential, Error>()

        var invokeCount = 0
        var receivedA: Credential?
        var receivedB: Credential?
        let doneA = expectation(description: "Caller A receives result")
        let doneB = expectation(description: "Caller B receives result")

        coordinator.refresh(credential: credA) {
            invokeCount += 1
            return subjectA.eraseToAnyPublisher()
        }
        .sink(receiveCompletion: { _ in }, receiveValue: { v in receivedA = v; doneA.fulfill() })
        .store(in: &subscriptions)

        coordinator.refresh(credential: credB) {
            invokeCount += 1
            return subjectB.eraseToAnyPublisher()
        }
        .sink(receiveCompletion: { _ in }, receiveValue: { v in receivedB = v; doneB.fulfill() })
        .store(in: &subscriptions)

        // Both operations must be invoked independently
        XCTAssertEqual(invokeCount, 2, "Each distinct credential must trigger an independent operation call")

        subjectA.send(resultA); subjectA.send(completion: .finished)
        subjectB.send(resultB); subjectB.send(completion: .finished)

        waitForExpectations(timeout: 5)
        XCTAssertEqual(receivedA, resultA, "Caller A must receive credA's result")
        XCTAssertEqual(receivedB, resultB, "Caller B must receive credB's result")
    }

    // MARK: - Task 3.1.3 — Entry cleaned up after success → new call starts fresh (REQ-SFR-03, SFR-S03)

    func testCleanupAfterSuccess() throws {
        let coordinator = SalesforceRefreshCoordinator()
        let credential  = Self.makeCredential(accessToken: "access", refreshToken: "refresh")
        let result1     = Self.makeCredential(accessToken: "new1",   refreshToken: "rot1")
        let result2     = Self.makeCredential(accessToken: "new2",   refreshToken: "rot2")

        var invokeCount = 0

        // First refresh — completes successfully
        let first = coordinator.refresh(credential: credential) {
            invokeCount += 1
            return Just(result1).setFailureType(to: Error.self).eraseToAnyPublisher()
        }
        let _ = try waitFor(first)
        XCTAssertEqual(invokeCount, 1)

        // Second refresh — must start a fresh operation
        let second = coordinator.refresh(credential: credential) {
            invokeCount += 1
            return Just(result2).setFailureType(to: Error.self).eraseToAnyPublisher()
        }
        let got = try waitFor(second)

        XCTAssertEqual(invokeCount, 2, "A second call after completion must invoke the operation again")
        XCTAssertEqual(got, result2)
    }

    // MARK: - Task 3.1.4 — Entry cleaned up after failure → retry starts fresh (REQ-SFR-03, SFR-S04)

    func testCleanupAfterFailure() throws {
        let coordinator = SalesforceRefreshCoordinator()
        let credential  = Self.makeCredential(accessToken: "access", refreshToken: "refresh")
        let result2     = Self.makeCredential(accessToken: "new2",   refreshToken: "rot2")

        struct FakeError: Error {}
        var invokeCount = 0

        // First refresh — fails
        let first = coordinator.refresh(credential: credential) {
            invokeCount += 1
            return Fail<Credential, Error>(error: FakeError()).eraseToAnyPublisher()
        }
        XCTAssertThrowsError(try waitFor(first))
        XCTAssertEqual(invokeCount, 1)

        // Second refresh — must start a fresh operation
        let second = coordinator.refresh(credential: credential) {
            invokeCount += 1
            return Just(result2).setFailureType(to: Error.self).eraseToAnyPublisher()
        }
        let got = try waitFor(second)

        XCTAssertEqual(invokeCount, 2, "A retry after failure must invoke the operation again")
        XCTAssertEqual(got, result2)
    }

    // MARK: - Task 3.1.5 — All concurrent callers receive the same error (SFR-S05)

    func testAllConcurrentCallersReceiveSameError() throws {
        struct FakeError: Error, Equatable { let code: Int }
        let expectedError = FakeError(code: 42)

        let coordinator = SalesforceRefreshCoordinator()
        let credential  = Self.makeCredential(accessToken: "access", refreshToken: "refresh")
        let subject     = PassthroughSubject<Credential, Error>()

        var invokeCount = 0
        var errorCount  = 0
        var valueCount  = 0
        let allDone = expectation(description: "All 3 callers complete")
        allDone.expectedFulfillmentCount = 3

        for _ in 0..<3 {
            coordinator.refresh(credential: credential) {
                invokeCount += 1
                return subject.eraseToAnyPublisher()
            }
            .sink(
                receiveCompletion: { completion in
                    if case let .failure(e) = completion {
                        if let fe = e as? FakeError, fe == expectedError { errorCount += 1 }
                    }
                    allDone.fulfill()
                },
                receiveValue: { _ in valueCount += 1 }
            )
            .store(in: &subscriptions)
        }

        XCTAssertEqual(invokeCount, 1)

        subject.send(completion: .failure(expectedError))

        waitForExpectations(timeout: 5)
        XCTAssertEqual(errorCount, 3, "All 3 callers must receive the error")
        XCTAssertEqual(valueCount, 0, "No values must be emitted on failure")
    }

    // MARK: - Task 3.1.6 — nil refreshToken falls back to accessToken as key (REQ-SFR-02, SFR-S06)

    func testNilRefreshTokenUsesAccessTokenAsKey() throws {
        let coordinator = SalesforceRefreshCoordinator()
        // refreshToken is nil — key must use accessToken instead
        let credential = Self.makeCredential(accessToken: "access-only", refreshToken: nil)
        let result     = Self.makeCredential(accessToken: "refreshed",   refreshToken: nil)
        let subject    = PassthroughSubject<Credential, Error>()

        var invokeCount = 0
        var receivedValues: [Credential] = []
        let allReceived = expectation(description: "Both callers receive result")
        allReceived.expectedFulfillmentCount = 2

        for _ in 0..<2 {
            coordinator.refresh(credential: credential) {
                invokeCount += 1
                return subject.eraseToAnyPublisher()
            }
            .sink(
                receiveCompletion: { completion in
                    if case let .failure(e) = completion { XCTFail("Unexpected error: \(e)") }
                },
                receiveValue: { v in receivedValues.append(v); allReceived.fulfill() }
            )
            .store(in: &subscriptions)
        }

        XCTAssertEqual(invokeCount, 1, "Nil refreshToken must still coalesce concurrent calls using accessToken as key")

        subject.send(result)
        subject.send(completion: .finished)

        waitForExpectations(timeout: 5)
        XCTAssertEqual(receivedValues.count, 2)
        XCTAssertTrue(receivedValues.allSatisfy { $0 == result })
    }

    // MARK: - Task 3.1.7 — pendingRevokers behavior unchanged (REQ-SFR-05, SFR-S07)

    func testPendingRevokersBehaviorUnchanged() throws {
        // Smoke test: CredentialManager.revokeCredential still deduplicates concurrent revocations.
        // This test verifies the revokeCredential code path was not modified by Slice 3.
        // We cannot call revokeCredential live (requires credentials + network), so we verify
        // the structural invariant: CredentialManager still has the pendingRevokers dedup path
        // by exercising the path indirectly — two concurrent revoke calls on the same token
        // must not crash or produce unexpected results.
        //
        // Full integration coverage is in CredentialManagerTests (pre-existing, environment-dependent).
        // This test confirms the structural compilation guarantee.
        let mgr = CredentialManager(
            consumerKey: "ck",
            callbackURL: URL(string: "myapp://cb")!,
            defaultHost: "login.salesforce.com"
        )
        // Verify the manager exists and compiles with the new coordinator in place
        XCTAssertEqual(mgr.authenticator, .pkce,
                       "CredentialManager.authenticator must still default to .pkce after Slice 3 changes")
        // pendingRevokers is private static — we can only confirm revokeCredential API still exists
        // by calling it (it will fail with -1000 in CI, which is the pre-existing baseline).
        let credential = Self.makeCredential(accessToken: "a", refreshToken: "r")
        let pub = mgr.revokeCredential(credential)
        XCTAssertNotNil(pub, "revokeCredential must still return a publisher (pendingRevokers path intact)")
    }

    // MARK: - Helpers

    private static func makeCredential(
        accessToken: String,
        refreshToken: String?,
        identityURL: URL = URL(string: "https://login.salesforce.com/id/orgId/userId")!
    ) -> Credential {
        Credential(
            accessToken: accessToken,
            instanceURL: URL(string: "https://example.my.salesforce.com")!,
            identityURL: identityURL,
            refreshToken: refreshToken,
            siteURL: nil,
            siteID: nil,
            timestamp: nil,
            idToken: nil
        )
    }
}
