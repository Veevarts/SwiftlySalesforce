import Foundation

public protocol ResponseValidator {
    
    typealias Response<Body> = (body: Body, metadata: HTTPURLResponse)
    
    associatedtype Body = Data
    func validate(response: Response<Body>) throws
    func checkAuthenticationRequired(response: Response<Body>) throws
    func checkError(response: Response<Body>) throws
}

public extension ResponseValidator {
    
    func validate(response: Response<Body>) throws {
        try checkAuthenticationRequired(response: response)
        try checkError(response: response)
    }
    
    func checkAuthenticationRequired(response: Response<Body>) throws {
        guard 401 != response.metadata.statusCode else {
            throw URLError(.userAuthenticationRequired)
        }
    }

    func checkAuthenticationRequired(response: Response<Body>) throws where Body == Data {
        // A 401 always means the access token is no longer accepted.
        if response.metadata.statusCode == 401 {
            throw URLError(.userAuthenticationRequired)
        }
        // Salesforce's `/services/oauth2/*` and some REST resources answer with HTTP 403 and a plain
        // `Bad_OAuth_Token` body when the token is invalid. Treat that as authentication-required so the
        // request is refreshed and retried, matching the official Mobile SDK. Other 403s are real errors.
        if response.metadata.statusCode == 403,
           String(data: response.body)?.trimmingCharacters(in: .whitespacesAndNewlines) == "Bad_OAuth_Token" {
            throw URLError(.userAuthenticationRequired)
        }
    }

    func checkError(response: Response<Body>) throws {
        guard (200..<300).contains(response.metadata.statusCode) else {
            throw ResponseError(metadata: response.metadata)
        }
    }
    
    func checkError(response: Response<Body>) throws where Body == Data {
        guard (200..<300).contains(response.metadata.statusCode) else {
            if let dto = ResponseErrorDTO(from: response.body) {
                throw ResponseError(code: dto.errorCode, message: dto.message, fields: dto.fields, metadata: response.metadata)
            }
            else if let str = String(data: response.body) {
                throw ResponseError(message: str, metadata: response.metadata)
            }
            else {
                throw ResponseError(metadata: response.metadata)
            }
        }
    }
}

fileprivate struct ResponseErrorDTO: Decodable {
    
    let errorCode: String
    let message: String
    let fields: [String]?
    
    init?(from data: Data) {
        guard let dto =
                (try? JSONDecoder.salesforce.decode([ResponseErrorDTO].self, from: data).first)
                ?? (try? JSONDecoder.salesforce.decode(ResponseErrorDTO.self, from: data)) else {
            return nil
        }
        self = dto
    }
}
