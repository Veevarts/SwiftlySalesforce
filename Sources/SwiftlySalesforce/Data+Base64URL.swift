//
//  Data+Base64URL.swift
//  SwiftlySalesforce
//
//  For license & details see: https://www.github.com/mike4aday/SwiftlySalesforce
//

import Foundation

extension Data {

    /// Returns a base64url-encoded string (RFC 4648 §5): standard base64 with
    /// `+` mapped to `-`, `/` mapped to `_`, and `=` padding removed.
    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
