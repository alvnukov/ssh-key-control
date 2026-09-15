import Foundation

/// One request from the Go side: a JSON object on a line of standard input.
public struct Request: Codable, Equatable, Sendable {
    public enum Op: String, Codable, Sendable {
        case secret
        case text
        case confirm
        case manageDecisions = "manage-decisions"
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
    public var decisions: [TemporaryDecision]?
    public var activate: Bool?
    /// The processes that led to this request, nearest caller first, and the
    /// index of the one a timed decision would attach to. A zero or missing
    /// boundary means no process could be named, so nothing is on offer.
    public var chain: [ProcessLink]?
    public var boundary: Int?

    public init(
        op: Op, title: String? = nil, message: String? = nil, remember: Remember? = nil,
        placeholder: String? = nil, allow: String? = nil, deny: String? = nil,
        account: String? = nil, secret: String? = nil, destination: String? = nil,
        decisions: [TemporaryDecision]? = nil, activate: Bool? = nil,
        chain: [ProcessLink]? = nil, boundary: Int? = nil
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
        self.decisions = decisions
        self.activate = activate
        self.chain = chain
        self.boundary = boundary
    }
}

/// One process in the chain that asked for a signature. Every field here
/// describes the caller; none of them authorizes it.
public struct ProcessLink: Codable, Equatable, Sendable {
    public var name: String
    public var pid: Int32
    /// The signing team macOS vouched for, when it could vouch for one at all.
    /// A program that rewrites its own bundle has neither, which is ordinary
    /// and is shown as such rather than treated as a failure.
    public var team: String?
    public var verified: Bool?

    public init(name: String, pid: Int32, team: String? = nil, verified: Bool? = nil) {
        self.name = name
        self.pid = pid
        self.team = team
        self.verified = verified
    }

    public var isVerified: Bool { verified == true }

    /// What a person reads: the program, and which copy of it is asking.
    public var label: String { "\(name) [\(pid)]" }
}

/// The UI reports a lifetime; callers own caching and local-day expiry.
/// Deny durations make the caller refuse silently for that duration instead.
public enum GrantScope: String, Codable, Sendable, CaseIterable {
    case once
    case fiveMinutes = "5m"
    case fifteenMinutes = "15m"
    case day
    /// As long as the process the decision is anchored to keeps running.
    case process
    case denyFiveMinutes = "deny5m"
    case denyOneHour = "deny1h" // Retained for older helpers.
    case denyFifteenMinutes = "deny15m"
    case denyDay = "denyday"
    /// As long as the program the refusal was drawn at keeps running: the
    /// answer to something that asks in a loop.
    case denyProcess = "denyprocess"
    case custom
    case denyCustom = "denycustom"

    /// True for the durations that extend a denial instead of a grant.
    public var isDenyDuration: Bool {
        [.denyFiveMinutes, .denyOneHour, .denyFifteenMinutes, .denyDay,
         .denyProcess, .denyCustom].contains(self)
    }

    /// One duration selector serves both decision buttons.
    func scope(forAllowed allowed: Bool) -> GrantScope? {
        switch self {
        case .once: return .once
        case .fiveMinutes: return allowed ? .fiveMinutes : .denyFiveMinutes
        case .fifteenMinutes: return allowed ? .fifteenMinutes : .denyFifteenMinutes
        case .day: return allowed ? .day : .denyDay
        case .process: return allowed ? .process : .denyProcess
        case .custom: return allowed ? .custom : .denyCustom
        default: return nil
        }
    }
}

public struct Confirmation: Equatable, Sendable {
    public var allowed: Bool
    public var scope: GrantScope
    public var durationMinutes: Int?
    /// The link the user settled on, as an index into the chain they were
    /// shown. Nil when no chain was offered, or when the answer was for one
    /// signature only and nothing is kept.
    public var boundary: Int?

    public init(allowed: Bool, scope: GrantScope = .once, durationMinutes: Int? = nil, boundary: Int? = nil) {
        self.allowed = allowed
        self.scope = scope
        self.durationMinutes = durationMinutes
        self.boundary = boundary
    }
}

/// The answer to a request: one JSON object on a line of standard output.
public struct Response: Codable, Equatable, Sendable {
    public var ok: Bool
    public var error: String?
    public var answer: String?
    public var remember: Bool?
    public var scope: GrantScope? = nil
    public var durationMinutes: Int? = nil
    public var boundary: Int? = nil
    public var change: DecisionChange? = nil

    /// A scope travels with the answer only when the caller can use it:
    /// any scope on an allowed answer, deny durations on a denied one,
    /// nothing on a plain deny.
    public static func confirmation(_ choice: Confirmation) -> Response {
        var response = success(answer: choice.allowed ? "yes" : "no")
        if choice.allowed || choice.scope.isDenyDuration {
            response.scope = choice.scope
            response.durationMinutes = choice.durationMinutes
        }
        // Both answers attach to the program the user drew them at, so both
        // report where the line ended up. A plain deny keeps nothing, so it
        // has nowhere to attach and says nothing.
        if choice.allowed || choice.scope.isDenyDuration {
            response.boundary = choice.boundary
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
