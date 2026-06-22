import XCTest
import Foundation
@testable import SwiftlySalesforce

class ConnectedAppTests: XCTestCase {

    func testThatItInitsWithoutClientSecret() {
        let app = ConnectedApp(consumerKey: "key", callbackURL: URL(string: "testapp://oauthdone")!)
        XCTAssertNil(app.clientSecret)
    }

    func testThatItInitsWithClientSecret() {
        let app = ConnectedApp(consumerKey: "key", callbackURL: URL(string: "testapp://oauthdone")!, clientSecret: "secret")
        XCTAssertEqual(app.clientSecret, "secret")
    }
}
