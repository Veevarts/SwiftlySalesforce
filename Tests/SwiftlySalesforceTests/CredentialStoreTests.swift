import XCTest
@testable import SwiftlySalesforce

class CredentialStoreTests: XCTestCase {
    
    let callbackURL = URL(string: "https://www.mysite.com/user_callback.jsp#access_token=00Dx0000000BV7z%21AR8AQBM8J_xr9kLqmZIRyQxZgLcM4HVi41aGtW0qW3JCzf5xdTGGGSoVim8FfJkZEqxbjaFbberKGk8v8AnYrvChG4qJbQo8&refresh_token=5Aep8614iLM.Dq661ePDmPEgaAW9Oh_L3JKkDpB4xReb54_pZfVti1dPEk8aimw4Hr9ne7VXXVSIQ%3D%3D&instance_url=https%3A%2F%2FyourInstance.salesforce.com&id=https%3A%2F%2Flogin.salesforce.com%2Fid%2F00Dx0000000BV7z%2F005x00000012Q9P&issued_at=1278448101416&signature=miQQ1J4sdMPiduBsvyRYPCDozqhe43KRc1i9LmZHR70%3D&scope=id+api+refresh_token&token_type=Bearer&state=mystate")!
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testThatItStoresAndRetrieves() {
    
        // Given
        let connectedApp = ConnectedApp(consumerKey: "KEY", callbackURL: URL(string: "myscheme://authorized")!)
        let store = CredentialStore(for: connectedApp)
        let cred = try! Credential(with: callbackURL)
        let user = User(userID: cred.userID, orgID: cred.orgID)
        
        // When
        try! store.store(cred)
        let retrievedCred = store.retrieve(for: user)
        
        // Then
        XCTAssertNotNil(retrievedCred)
        XCTAssertEqual(cred.accessToken, retrievedCred?.accessToken)
        XCTAssertEqual(cred.refreshToken, retrievedCred?.refreshToken)
        XCTAssertEqual(cred.identityURL, retrievedCred?.identityURL)
    }
    
    // Note: Keychain round-trips (testThatItStoresAndRetrieves / testThatItClears) require a test
    // host app with a keychain entitlement; in a bare SPM test bundle they fail with
    // errSecMissingEntitlement (-34018). This test verifies the serialization path that
    // CredentialStore uses around the Keychain (encode -> decode), without the Keychain I/O,
    // so it confirms a rotated refresh token survives persistence.
    func testThatRotatedCredentialSerializesRotatedToken() throws {

        // Given a credential rotated by a refresh response that returned a new refresh token
        let original = try Credential(with: callbackURL)
        let json = """
        {"access_token":"NEW_ACCESS","refresh_token":"ROTATED_REFRESH","instance_url":"https://yourInstance.salesforce.com","id":"https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P","issued_at":"1278448101416"}
        """.data(using: .utf8)!
        let rotated = try RefreshTokenFlow.refreshedCredential(from: json, credential: original)

        // When it goes through the same JSON encode/decode CredentialStore performs around the Keychain
        let data = try JSONEncoder().encode(rotated)
        let decoded = try JSONDecoder().decode(Credential.self, from: data)

        // Then the rotated refresh token (and new access token) survive
        XCTAssertEqual(decoded.refreshToken, "ROTATED_REFRESH")
        XCTAssertEqual(decoded.accessToken, "NEW_ACCESS")
    }

    func testThatItClears() {

        // Given
        let connectedApp = ConnectedApp(consumerKey: "KEY", callbackURL: URL(string: "myscheme://authorized")!)
        let store = CredentialStore(for: connectedApp)
        let cred = try! Credential(with: callbackURL)
        let user = User(userID: cred.userID, orgID: cred.orgID)
        
        // When
        try! store.store(cred)
        try! store.clear(for: user)
        let retrievedCred = store.retrieve(for: user)
        
        // Then
        XCTAssertNil(retrievedCred)
    }
}
