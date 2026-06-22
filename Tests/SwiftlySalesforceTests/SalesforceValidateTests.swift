import XCTest
@testable import SwiftlySalesforce

class SalesforceValidateTests: XCTestCase {

    private func response(_ urlString: String, _ statusCode: Int) -> HTTPURLResponse {
        return HTTPURLResponse(url: URL(string: urlString)!, statusCode: statusCode, httpVersion: nil, headerFields: nil)!
    }

    // 10.1 — 403 + /services/oauth2 path + "Bad_OAuth_Token" body → refresh
    func testThatBadOAuthToken403OnOAuthPathTriggersRefresh() {
        let resp = response("https://login.salesforce.com/services/oauth2/userinfo", 403)
        let data = "Bad_OAuth_Token".data(using: .utf8)!
        XCTAssertThrowsError(try Salesforce.validate(data: data, response: resp)) { error in
            guard case SalesforceError.authenticationRequired = error else {
                return XCTFail("Expected authenticationRequired, got \(error)")
            }
        }
    }

    // 10.2 — same body but NOT an oauth path → unauthorized
    func testThatBadOAuthTokenBodyOnNonOAuthPathIsUnauthorized() {
        let resp = response("https://na1.salesforce.com/services/data/v49.0/sobjects/Account", 403)
        let data = "Bad_OAuth_Token".data(using: .utf8)!
        XCTAssertThrowsError(try Salesforce.validate(data: data, response: resp)) { error in
            guard case SalesforceError.unauthorized = error else {
                return XCTFail("Expected unauthorized, got \(error)")
            }
        }
    }

    // 10.3 — oauth path but a different body → unauthorized
    func testThat403OnOAuthPathWithOtherBodyIsUnauthorized() {
        let resp = response("https://login.salesforce.com/services/oauth2/userinfo", 403)
        let data = "Forbidden".data(using: .utf8)!
        XCTAssertThrowsError(try Salesforce.validate(data: data, response: resp)) { error in
            guard case SalesforceError.unauthorized = error else {
                return XCTFail("Expected unauthorized, got \(error)")
            }
        }
    }

    // 10.4 — 401 still refreshes; 200 still passes through
    func testThat401TriggersRefresh() {
        let resp = response("https://na1.salesforce.com/services/data/v49.0/sobjects/Account", 401)
        XCTAssertThrowsError(try Salesforce.validate(data: Data(), response: resp)) { error in
            guard case SalesforceError.authenticationRequired = error else {
                return XCTFail("Expected authenticationRequired, got \(error)")
            }
        }
    }

    func testThatSuccessfulResponsePassesThrough() throws {
        let resp = response("https://na1.salesforce.com/services/data/v49.0/sobjects/Account", 200)
        let payload = "{}".data(using: .utf8)!
        let (data, _) = try Salesforce.validate(data: payload, response: resp)
        XCTAssertEqual(data, payload)
    }
}
