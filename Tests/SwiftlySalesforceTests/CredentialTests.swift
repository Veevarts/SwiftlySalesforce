/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine
import XCTest
@testable import SwiftlySalesforce

class CredentialTests: XCTestCase {

    override func setUpWithError() throws {

    }

    override func tearDownWithError() throws {

    }

    // MARK: - Existing tests (regression)

    func testThatItInitializesWithCallbackURL() throws {

        // Given
        let callback = "myapp://callback#access_token=00Dx0000000BV7z%21AR8AQBM8J_xr9kLqmZIRyQxZgLcM4HVi41aGtW0qW3JCzf5xdTGGGSoVim8FfJkZEqxbjaFbberKGk8v8AnYrvChG4qJbQo8&refresh_token=5Aep8614iLM.Dq661ePDmPEgaAW9Oh_L3JKkDpB4xReb54_pZfVti1dPEk8aimw4Hr9ne7VXXVSIQ%3D%3D&instance_url=https://yourInstance.salesforce.com&id=https://login.salesforce.com%2Fid%2F00Dx0000000BV7z%2F005x00000012Q9P&issued_at=1278448101416&signature=miQQ1J4sdMPiduBsvyRYPCDozqhe43KRc1i9LmZHR70%3D&scope=id+api+refresh_token&token_type=Bearer&state=mystate"
        let callbackURL = URL(string: callback)!

        // When
        let cred = Credential(fromURLEncodedString: callbackURL.fragment!)!

        // Then
        XCTAssertEqual(cred.accessToken, "00Dx0000000BV7z%21AR8AQBM8J_xr9kLqmZIRyQxZgLcM4HVi41aGtW0qW3JCzf5xdTGGGSoVim8FfJkZEqxbjaFbberKGk8v8AnYrvChG4qJbQo8".removingPercentEncoding)
        XCTAssertEqual(cred.refreshToken, "5Aep8614iLM.Dq661ePDmPEgaAW9Oh_L3JKkDpB4xReb54_pZfVti1dPEk8aimw4Hr9ne7VXXVSIQ%3D%3D".removingPercentEncoding)
        XCTAssertEqual(cred.instanceURL, URL(string: "https://yourInstance.salesforce.com")!)
        XCTAssertEqual(cred.identityURL, URL(string: "https://login.salesforce.com%2Fid%2F00Dx0000000BV7z%2F005x00000012Q9P".removingPercentEncoding)!)
        XCTAssertNil(cred.siteID)
        XCTAssertNil(cred.siteURL)
        XCTAssertEqual(cred.timestamp, Date(timeIntervalSince1970: 1278448101.416))
    }

    // MARK: - Task 1.1.1 — Legacy Credential round-trip (REQ-PKCE-07, PKCE-S07, ROT-S07)

    func testLegacyCredentialRoundTrip() throws {
        // Given: a pre-PKCE JSON payload with no idToken key
        let json = """
        {
            "accessToken": "token123",
            "instanceURL": "https://org.salesforce.com",
            "identityURL": "https://login.salesforce.com/id/org/user",
            "refreshToken": "refresh456",
            "siteURL": null,
            "siteID": null,
            "timestamp": 704671216.0
        }
        """.data(using: .utf8)!

        // When: decoded as Credential — must not throw
        let decoded = try JSONDecoder().decode(Credential.self, from: json)

        // Then: new optional fields are nil; original fields intact
        XCTAssertNil(decoded.idToken, "idToken must be nil for legacy payloads")
        XCTAssertEqual(decoded.accessToken, "token123")
        XCTAssertEqual(decoded.instanceURL, URL(string: "https://org.salesforce.com")!)
        XCTAssertEqual(decoded.identityURL, URL(string: "https://login.salesforce.com/id/org/user")!)
        XCTAssertEqual(decoded.refreshToken, "refresh456")
        XCTAssertNil(decoded.siteURL)
        XCTAssertNil(decoded.siteID)
        XCTAssertNotNil(decoded.timestamp)
    }

    // MARK: - Task 1.1.2 — PKCE Credential round-trip (REQ-PKCE-07, PKCE-S08)

    func testPKCECredentialRoundTrip() throws {
        // Given: a Credential with non-nil idToken and community values in siteURL/siteID
        let original = Credential(
            accessToken: "pkce-access",
            instanceURL: URL(string: "https://org.salesforce.com")!,
            identityURL: URL(string: "https://login.salesforce.com/id/org/user")!,
            refreshToken: "pkce-refresh",
            siteURL: URL(string: "https://community.example.com")!,
            siteID: "cid99",
            timestamp: Date(timeIntervalSince1970: 1000),
            idToken: "id-tok-xyz"
        )

        // When: encode then decode
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(Credential.self, from: encoded)

        // Then: all fields round-trip correctly
        XCTAssertEqual(decoded.accessToken, original.accessToken)
        XCTAssertEqual(decoded.instanceURL, original.instanceURL)
        XCTAssertEqual(decoded.identityURL, original.identityURL)
        XCTAssertEqual(decoded.refreshToken, original.refreshToken)
        XCTAssertEqual(decoded.siteURL, original.siteURL)
        XCTAssertEqual(decoded.siteID, original.siteID)
        XCTAssertEqual(decoded.timestamp, original.timestamp)
        XCTAssertEqual(decoded.idToken, "id-tok-xyz")
        XCTAssertEqual(decoded, original)
    }

    // MARK: - Task 1.1.3 — URLEncoded init captures idToken (REQ-PKCE-06, REQ-PKCE-07)

    func testURLEncodedInitCapturesIdToken() throws {
        // Given: urlencoded string containing id_token
        let urlEncoded = "access_token=access123&instance_url=https%3A%2F%2Forg.salesforce.com&id=https%3A%2F%2Flogin.salesforce.com%2Fid%2Forg%2Fuser&id_token=tok123"

        // When
        let cred = Credential(fromURLEncodedString: urlEncoded)

        // Then
        XCTAssertNotNil(cred, "Credential init must succeed")
        XCTAssertEqual(cred?.idToken, "tok123")
    }

    // MARK: - Task 1.1.4 — URLEncoded init maps community fields to existing site fields (REQ-PKCE-06, REQ-PKCE-07)

    func testURLEncodedInitMapsCommunityFieldsToExistingSiteFields() throws {
        // Given: urlencoded string with sfdc_community_url and sfdc_community_id
        let urlEncoded = "access_token=access123&instance_url=https%3A%2F%2Forg.salesforce.com&id=https%3A%2F%2Flogin.salesforce.com%2Fid%2Forg%2Fuser&sfdc_community_url=https%3A%2F%2Fcommunity.example.com&sfdc_community_id=cid99"

        // When
        let cred = Credential(fromURLEncodedString: urlEncoded)

        // Then: community values map to existing siteURL/siteID
        XCTAssertNotNil(cred)
        XCTAssertEqual(cred?.siteURL, URL(string: "https://community.example.com"))
        XCTAssertEqual(cred?.siteID, "cid99")
    }
}
