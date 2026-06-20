import XCTest
@testable import SwiftlySalesforce

/// Deterministic, headless tests for the RTR-safe refresh behavior of `DefaultAuthorizer`.
/// These do NOT perform live login; the refresh network call is mocked and counted.
final class DefaultAuthorizerConcurrencyTests: XCTestCase {

    private let callbackURL = URL(string: "myapp://callback")!

    /// A credential the caller "used" before rotation: old refresh token (`RT0`) and an early timestamp.
    private var staleCredential: Credential {
        Credential(
            accessToken: "AT0",
            instanceURL: URL(string: "https://yourInstance.salesforce.com")!,
            identityURL: URL(string: "https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P")!,
            timestamp: Date(timeIntervalSince1970: 1_000_000_000),
            refreshToken: "RT0"
        )
    }

    /// A refresh-token-flow response that rotates the token (`refresh_token=RT1`) and carries a newer
    /// `issued_at` (1278448101416 ms ⇒ ~2010) than `staleCredential` (~2001).
    private static let rotatedRefreshBody =
        "access_token=AT1"
        + "&instance_url=https%3A%2F%2FyourInstance.salesforce.com"
        + "&id=https://login.salesforce.com%2Fid%2F00Dx0000000BV7z%2F005x00000012Q9P"
        + "&issued_at=1278448101416"
        + "&refresh_token=RT1"

    private func countingRefreshSession(_ counter: CallCounter) -> URLSession {
        URLSession.mock { request in
            counter.increment()
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(Self.rotatedRefreshBody.utf8), nil)
        }
    }

    func testThatConcurrentRequestsTriggerExactlyOneRefresh() async throws {
        // Given
        let counter = CallCounter()
        let authorizer = DefaultAuthorizer(consumerKey: "CK", callbackURL: callbackURL, session: countingRefreshSession(counter))
        let used = staleCredential

        // When: 20 requests concurrently ask to refresh the same (expired) credential
        let results = try await withThrowingTaskGroup(of: Credential.self) { group -> [Credential] in
            for _ in 0..<20 {
                group.addTask { try await authorizer.grantCredential(refreshing: used) }
            }
            var creds = [Credential]()
            for try await cred in group { creds.append(cred) }
            return creds
        }

        // Then: exactly one refresh network call; everyone gets the rotated credential
        XCTAssertEqual(counter.count, 1, "Expected exactly one refresh network call for N concurrent requests")
        XCTAssertEqual(results.count, 20)
        XCTAssertTrue(results.allSatisfy { $0.refreshToken == "RT1" }, "All callers must receive the rotated credential")
    }

    func testThatStaggeredRequestReusesRotatedCredentialWithoutRefreshing() async throws {
        // Given
        let counter = CallCounter()
        let authorizer = DefaultAuthorizer(consumerKey: "CK", callbackURL: callbackURL, session: countingRefreshSession(counter))
        let used = staleCredential

        // When: one refresh completes (RT0 -> RT1) ...
        let first = try await authorizer.grantCredential(refreshing: used)
        XCTAssertEqual(first.refreshToken, "RT1")
        XCTAssertEqual(counter.count, 1)

        // ... then a staggered straggler arrives still holding the old RT0 credential
        let second = try await authorizer.grantCredential(refreshing: used)

        // Then: no second refresh; the straggler reuses the already-rotated credential
        XCTAssertEqual(counter.count, 1, "A staggered straggler must not refresh an already-rotated token")
        XCTAssertEqual(second.refreshToken, "RT1")
    }
}

/// Thread-safe call counter shared with a synchronous `MockURLProtocol` loading handler.
final class CallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}
