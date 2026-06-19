/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation

/// Holds the result of a successful OAuth2 authentication, including the Salesforce access token and the refresh token, if available.
/// # Reference
/// [OAuth 2.0 User-Agent Flow](https://help.salesforce.com/articleView?id=remoteaccess_oauth_user_agent_flow.htm)
public struct Credential: Equatable {
    public let accessToken: String
    public let instanceURL: URL
    public let identityURL: URL
    public let refreshToken: String?
    public let siteURL: URL?
    public let siteID: String?
    /// The date/time when the credential was issued. Derived from `issued_at` (milliseconds since epoch).
    public let timestamp: Date?
    /// The OpenID Connect ID token returned by the PKCE token exchange. Nil for credentials obtained
    /// via UserAgentFlow (which does not return an id_token).
    public let idToken: String?
}

// MARK: - Codable

extension Credential: Codable {

    /// CodingKeys maps Swift property names to JSON keys.
    /// `idToken` uses snake_case JSON key `id_token`.
    /// All other keys match property names (Swift synthesised keys).
    enum CodingKeys: String, CodingKey {
        case accessToken
        case instanceURL
        case identityURL
        case refreshToken
        case siteURL
        case siteID
        case timestamp
        case idToken = "idToken"  // stored as "idToken" in Keychain JSON; id_token is only the wire key
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessToken  = try container.decode(String.self, forKey: .accessToken)
        instanceURL  = try container.decode(URL.self,    forKey: .instanceURL)
        identityURL  = try container.decode(URL.self,    forKey: .identityURL)
        // All optional fields use decodeIfPresent so existing Keychain entries (pre-PKCE)
        // continue to deserialize without error even when the key is absent.
        refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
        siteURL      = try container.decodeIfPresent(URL.self,    forKey: .siteURL)
        siteID       = try container.decodeIfPresent(String.self, forKey: .siteID)
        timestamp    = try container.decodeIfPresent(Date.self,   forKey: .timestamp)
        idToken      = try container.decodeIfPresent(String.self, forKey: .idToken)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(accessToken,  forKey: .accessToken)
        try container.encode(instanceURL,  forKey: .instanceURL)
        try container.encode(identityURL,  forKey: .identityURL)
        // Encode optionals; nil values produce absent keys (not JSON null)
        try container.encodeIfPresent(refreshToken, forKey: .refreshToken)
        try container.encodeIfPresent(siteURL,      forKey: .siteURL)
        try container.encodeIfPresent(siteID,       forKey: .siteID)
        try container.encodeIfPresent(timestamp,    forKey: .timestamp)
        try container.encodeIfPresent(idToken,      forKey: .idToken)
    }
}

// MARK: - Public extensions

public extension Credential {

    /// The identifier for the user associated with this credential.
    ///
    /// Swiftly Salesforce uses the identity URL as a unique identifier for securely storing and retrieving credentials.
    /// # Reference
    /// [Identity URLs](https://help.salesforce.com/articleView?id=sf.remoteaccess_using_openid.htm&type=5)
    var user: UserIdentifier {
        return identityURL
    }

    /// The ID of the Salesforce User record associated with this credential.
    var userID: String {
        return user.lastPathComponent
    }

    /// The ID of the Salesforce Organization record associated with this credential.
    var orgID: String {
        return user.deletingLastPathComponent().lastPathComponent
    }
}

// MARK: - Internal extensions

internal extension Credential {

    /// Initialise a `Credential` from a URL-encoded string (as returned by the Salesforce
    /// token endpoint when `format=urlencoded`). Supports both the standard site fields
    /// (`sfdc_site_url` / `sfdc_site_id`) and the PKCE community-URL aliases
    /// (`sfdc_community_url` / `sfdc_community_id`), so callers do not need to distinguish
    /// between the two naming conventions used by Salesforce across different flows.
    ///
    /// Refresh-token rotation: when the server includes a `refresh_token` in the response
    /// (rotation-enabled org), that value is stored. When absent (non-rotating org), the
    /// caller-supplied `refreshToken` parameter is carried forward. Logic: `server ?? param`.
    init?(fromURLEncodedString string: String, andRefreshToken refreshToken: String? = nil) {
        guard let queryItems = URLComponents(percentEncodedQuery: string).queryItems,
              let accessToken = queryItems["access_token"],
              let instanceURL = URL(string: queryItems["instance_url"]),
              let identityURL = URL(string: queryItems["id"]) else {
            return nil
        }

        self.accessToken  = accessToken
        self.instanceURL  = instanceURL
        self.identityURL  = identityURL

        // Rotation: server-returned token wins over the caller-supplied fallback.
        self.refreshToken = queryItems["refresh_token"] ?? refreshToken

        // Site / community URL: check the PKCE community keys first, then fall back to
        // the standard site keys. Both variants map to the EXISTING siteURL / siteID fields —
        // no new properties are introduced for community values.
        self.siteURL = URL(string: queryItems["sfdc_community_url"])
                    ?? URL(string: queryItems["sfdc_site_url"])
        self.siteID  = queryItems["sfdc_community_id"]
                    ?? queryItems["sfdc_site_id"]

        // issued_at is provided as milliseconds-since-epoch; stored in the existing `timestamp`
        // field. No separate `issuedAt` field is added — timestamp already carries this value.
        self.timestamp = {
            guard let str = queryItems["issued_at"], let millisecs = Double(str) else {
                return nil
            }
            return Date(timeIntervalSince1970: millisecs / 1000)
        }()

        // id_token is a new optional field — populated only when the token endpoint returns it
        // (PKCE flows). Absent for UserAgentFlow responses.
        self.idToken = queryItems["id_token"]
    }

    /// Convenience initialiser used internally when constructing a minimal `Credential`
    /// (e.g., in tests or placeholder scenarios). All optional fields default to nil.
    init(accessToken: String, instanceURL: URL, identityURL: URL) {
        self.init(
            accessToken: accessToken,
            instanceURL: instanceURL,
            identityURL: identityURL,
            refreshToken: nil,
            siteURL: nil,
            siteID: nil,
            timestamp: nil,
            idToken: nil
        )
    }
}
