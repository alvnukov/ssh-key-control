import Foundation

/// Reads requests from standard input on a background thread, answers each on
/// the main actor (where AppKit lives) and writes the response to standard
/// output. End of input means the client is done: `finished` runs on the main
/// actor and is expected to end the process.
public final class LineServer: Sendable {
    public typealias Handler = @MainActor @Sendable (Request) -> Response
    public typealias Finished = @MainActor @Sendable () -> Void

    private let handler: Handler
    private let finished: Finished
    private let input: FileHandle
    private let output: FileHandle

    public init(
        input: FileHandle = .standardInput, output: FileHandle = .standardOutput,
        handler: @escaping Handler, finished: @escaping Finished
    ) {
        self.input = input
        self.output = output
        self.handler = handler
        self.finished = finished
    }

    /// Starts the reader thread and returns.
    public func start() {
        let thread = Thread { [self] in serve() }
        thread.name = "ssh-key-control-ui reader"
        thread.start()
    }

    private func serve() {
        var splitter = LineSplitter()
        while true {
            let chunk = input.availableData
            if chunk.isEmpty { break }
            for line in splitter.feed(chunk) {
                respond(to: line)
            }
        }
        if let line = splitter.flush() {
            respond(to: line)
        }
        DispatchQueue.main.sync {
            MainActor.assumeIsolated { finished() }
        }
    }

    private func respond(to line: Data) {
        let reply = DispatchQueue.main.sync {
            MainActor.assumeIsolated { Self.process(line, handler: handler) }
        }
        output.write(reply)
    }

    /// Decodes one line, runs the handler and encodes its answer.
    @MainActor
    public static func process(_ line: Data, handler: Handler) -> Data {
        let request: Request
        do {
            request = try Wire.decode(line)
        } catch {
            return Wire.encode(.failure(.other("bad request: \(error)")))
        }
        return Wire.encode(handler(request))
    }
}

/// Splits a byte stream into lines without the newline.
public struct LineSplitter: Sendable {
    private var buffer = Data()

    public init() {}

    /// Adds bytes and returns every complete line they finish.
    public mutating func feed(_ chunk: Data) -> [Data] {
        buffer.append(chunk)
        var lines: [Data] = []
        while let newline = buffer.firstIndex(of: 0x0A) {
            lines.append(buffer[buffer.startIndex..<newline])
            buffer = Data(buffer[(newline + 1)...])
        }
        return lines
    }

    /// Returns the unterminated remainder, if any, and empties the buffer.
    public mutating func flush() -> Data? {
        defer { buffer.removeAll() }
        return buffer.isEmpty ? nil : buffer
    }
}
