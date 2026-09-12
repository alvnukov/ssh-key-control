import Foundation

/// One request from the Go side: a JSON object on a line of standard input.
public struct Request: Codable, Equatable, Sendable {
    public enum Op: String, Codable, Sendable {
        case secret
        case text
        case confirm
        case notify
        case keychainGet = "keychain.get"
        case keychainSet = "keychain.set"
        case keychainDelete = "keychain.delete"
    }

    /// The "remember in my keychain" checkbox, when the caller wants one.
    public struct Remember: Codable, Equatable, Sendable {
        public var label: String
        public init(label: String) { self.label = label }
    }

    public var op: Op
    public var title: String?
    public var message: String?
    public var remember: Remember?
    public var placeholder: String?
    public var allow: String?
    public var deny: String?
    public var account: String?
    public var secret: String?
    public var destination: String?

    public init(
        op: Op, title: String? = nil, message: String? = nil, remember: Remember? = nil,
        placeholder: String? = nil, allow: String? = nil, deny: String? = nil,
        account: String? = nil, secret: String? = nil, destination: String? = nil
    ) {
        self.op = op
        self.title = title
        self.message = message
        self.remember = remember
        self.placeholder = placeholder
        self.allow = allow
        self.deny = deny
        self.account = account
        self.secret = secret
        self.destination = destination
    }
}

/// The UI reports a lifetime; callers own caching and local-day expiry.
/// Deny durations make the caller refuse silently for that duration instead.
public enum GrantScope: String, Codable, Sendable, CaseIterable {
    case once
    case fiveMinutes = "5m"
    case fifteenMinutes = "15m"
    case day
    case denyFiveMinutes = "deny5m"
    case denyOneHour = "deny1h"

    /// True for the durations that extend a denial instead of a grant.
    public var isDenyDuration: Bool {
        self == .denyFiveMinutes || self == .denyOneHour
    }
}

public struct Confirmation: Equatable, Sendable {
    public var allowed: Bool
    public var scope: GrantScope

    public init(allowed: Bool, scope: GrantScope = .once) {
        self.allowed = allowed
        self.scope = scope
    }
}

/// The answer to a request: one JSON object on a line of standard output.
public struct Response: Codable, Equatable, Sendable {
    public var ok: Bool
    public var error: String?
    public var answer: String?
    public var remember: Bool?
    public var scope: GrantScope? = nil

    /// A scope travels with the answer only when the caller can use it:
    /// any scope on an allowed answer, deny durations on a denied one,
    /// nothing on a plain deny.
    public static func confirmation(_ choice: Confirmation) -> Response {
        var response = success(answer: choice.allowed ? "yes" : "no")
        if choice.allowed || choice.scope.isDenyDuration {
            response.scope = choice.scope
        }
        return response
    }
    public static func success(answer: String? = nil, remember: Bool? = nil) -> Response {
        Response(ok: true, error: nil, answer: answer, remember: remember)
    }

    public static func failure(_ failure: Failure) -> Response {
        Response(ok: false, error: failure.wire, answer: nil, remember: nil)
    }

    public static func failure(_ error: any Error) -> Response {
        if let failure = error as? Failure {
            return .failure(failure)
        }
        return .failure(.other(String(describing: error)))
    }
}

/// The outcomes the Go side tells apart. Anything else travels as text.
public enum Failure: Error, Equatable, Sendable {
    case cancelled
    case notFound
    case denied
    case other(String)

    /// The string the Go side matches on.
    public var wire: String {
        switch self {
        case .cancelled: return "cancelled"
        case .notFound: return "not-found"
        case .denied: return "denied"
        case .other(let text): return text.isEmpty ? "failed" : text
        }
    }
}

/// Encoding of one line each way.
public enum Wire {
    public static func decode(_ line: Data) throws -> Request {
        try JSONDecoder().decode(Request.self, from: line)
    }

    /// The response as a single line, newline included.
    public static func encode(_ response: Response) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        // Response has no field that can fail to encode.
        var data = (try? encoder.encode(response)) ?? Data("{\"ok\":false,\"error\":\"encoding failed\"}".utf8)
        data.append(0x0A)
        return data
    }
}
