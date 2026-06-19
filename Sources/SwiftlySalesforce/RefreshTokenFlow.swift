/*
"Swiftly Salesforce: the Swift-est way to build iOS apps that connect to Salesforce"
For more information and license see: https://www.github.com/mike4aday/SwiftlySalesforce
Copyright (c) 2021. All rights reserved.
*/

import Foundation
import Combine

struct RefreshTokenFlow {
    var refreshToken: String
    var consumerKey: String
    var host: String
    var session: URLSession = URLSession(configuration: .ephemeral)
    var validator: Validator = .default
}

extension RefreshTokenFlow {

    var publisher: AnyPublisher<Credential, Error> {
        AnyPublisher<URLRequest?, Error>
            .just(URLRequest.refreshTokenFlow(refreshToken: refreshToken, consumerKey: consumerKey, host: host))
            .unwrap(orThrow: URLError(.badURL))
            .flatMap { session.dataTaskPublisher(for: $0).mapError { $0 as Error } }
            // Custom refresh validator: for non-2xx responses, attempt to parse the
            // urlencoded error body first (to surface `invalid_grant` with a typed code),
            // then fall back to the standard JSON-based validator behaviour.
            .tryMap { output -> (data: Data, response: URLResponse) in
                guard let httpResponse = output.response as? HTTPURLResponse else {
                    throw URLError(.badServerResponse)
                }
                if (200..<300).contains(httpResponse.statusCode) {
                    return output  // success path — proceed normally
                }
                // Error path: try to parse urlencoded body for OAuth error codes.
                // The Salesforce refresh endpoint returns urlencoded errors (not JSON)
                // when format=urlencoded is requested. This surfaces invalid_grant as a
                // typed SalesforceError.code so callers can use isInvalidGrant without
                // string-parsing (REQ-ROT-03).
                if let bodyString = String(data: output.data, encoding: .utf8),
                   let components = URLComponents(percentEncodedQuery: bodyString).queryItems,
                   let errorCode = components["error"] {
                    let description = components["error_description"] ?? "OAuth error: \(errorCode)"
                    throw SalesforceError(code: errorCode, message: description)
                }
                // Fall back to standard validator for JSON-encoded errors or bare HTTP errors.
                try validator.validate(output)
                return output  // unreachable if validator threw, but satisfies compiler
            }
            .map { String(data: $0.data, encoding: .utf8) }
            .unwrap(orThrow: URLError(.cannotDecodeRawData))
            .map { Credential(fromURLEncodedString: $0, andRefreshToken: refreshToken) }
            .unwrap(orThrow: URLError(.badServerResponse))
            .eraseToAnyPublisher()
    }
}
