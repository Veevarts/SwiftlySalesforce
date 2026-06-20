import XCTest
@testable import SwiftlySalesforce

final class ResponseValidatorTests: XCTestCase {

    // A concrete `ResponseValidator` with `Body == Data` (via `DataService`).
    private let validator = Resource.Limits()

    private func response(statusCode: Int, body: String) -> (body: Data, metadata: HTTPURLResponse) {
        let url = URL(string: "https://na1.salesforce.com/services/data/v50.0/limits")!
        let metadata = HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: nil, headerFields: nil)!
        return (Data(body.utf8), metadata)
    }

    func testThatItTreats403BadOAuthTokenAsAuthenticationRequired() throws {
        do {
            try validator.validate(response: response(statusCode: 403, body: "Bad_OAuth_Token"))
            XCTFail("Expected userAuthenticationRequired for 403 Bad_OAuth_Token")
        }
        catch let error where (error as? URLError)?.code == .userAuthenticationRequired {
            // Expected
        }
    }

    func testThatItDoesNotTreatOther403AsAuthenticationRequired() throws {
        do {
            try validator.validate(response: response(statusCode: 403, body: "REQUEST_LIMIT_EXCEEDED"))
            XCTFail("Expected an error for a 403")
        }
        catch let error as URLError where error.code == .userAuthenticationRequired {
            XCTFail("A non-Bad_OAuth_Token 403 must not be auth-required")
        }
        catch is ResponseError {
            // Expected: ordinary response error
        }
    }

    func testThatItStillTreats401AsAuthenticationRequired() throws {
        do {
            try validator.validate(response: response(statusCode: 401, body: ""))
            XCTFail("Expected userAuthenticationRequired for 401")
        }
        catch let error where (error as? URLError)?.code == .userAuthenticationRequired {
            // Expected
        }
    }

    func testThatItAcceptsSuccessfulResponse() throws {
        XCTAssertNoThrow(try validator.validate(response: response(statusCode: 200, body: "{}")))
    }
}
